//! SSPI Negotiate handshake via Windows native APIs.
//!
//! Implements the flow documented in `docs/SPEC.md` § 2.
//! Uses windows-native SSPI (not pure-Rust sspi-rs) so single-sign-on
//! with the current user's Kerberos ticket cache works automatically.

use crate::Error;
use std::mem::MaybeUninit;
use std::ptr;
use tracing::{debug, trace};

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeContextBuffer,
    FreeCredentialsHandle, InitializeSecurityContextW, QueryContextAttributesW, SecBuffer,
    SecBufferDesc, SecPkgContext_StreamSizes, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY,
    ISC_REQ_CONNECTION, ISC_REQ_INTEGRITY, ISC_REQ_MUTUAL_AUTH, ISC_REQ_REPLAY_DETECT,
    ISC_REQ_SEQUENCE_DETECT, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_STREAM_SIZES,
    SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
};
use windows::Win32::Security::Credentials::SecHandle;

// SSPI status codes returned via windows-rs Result<()>.Err.code().0 (i32).
const SEC_E_OK_RAW: i32 = 0;
const SEC_I_CONTINUE_NEEDED_RAW: i32 = 0x00090312u32 as i32;
const SEC_I_COMPLETE_NEEDED_RAW: i32 = 0x00090313u32 as i32;
const SEC_I_COMPLETE_AND_CONTINUE_RAW: i32 = 0x00090314u32 as i32;

/// Builds the SPN to use for Kerberos auth.
pub fn build_spn(target_host: &str) -> String {
    format!("TERMSRV/{target_host}")
}

/// Stream sizes returned by SSPI after handshake — needed for sizing
/// EncryptMessage / DecryptMessage buffers.
#[derive(Debug, Clone, Copy)]
pub struct StreamSizes {
    pub cb_header: u32,
    pub cb_trailer: u32,
    pub cb_maximum_message: u32,
    pub c_buffers: u32,
    pub cb_block_size: u32,
}

/// One round-trip of the SSPI handshake.
#[derive(Debug)]
pub struct HandshakeStep {
    pub output: Vec<u8>,
    pub done: bool,
}

/// Owned SSPI session: credential handle + (eventually) context handle.
pub struct SspiSession {
    cred: Box<SecHandle>,
    ctxt: Box<SecHandle>,
    ctxt_initialized: bool,
    spn_wide: Vec<u16>,
}

impl std::fmt::Debug for SspiSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SspiSession")
            .field("ctxt_initialized", &self.ctxt_initialized)
            .finish()
    }
}

impl Drop for SspiSession {
    fn drop(&mut self) {
        // SAFETY: both handles owned through our lifetime; APIs tolerate
        // never-initialized handles (return error, no crash).
        unsafe {
            if self.ctxt_initialized {
                let _ = DeleteSecurityContext(self.ctxt.as_mut() as *mut _);
            }
            let _ = FreeCredentialsHandle(self.cred.as_mut() as *mut _);
        }
    }
}

fn status_code(r: windows::core::Result<()>) -> i32 {
    match r {
        Ok(()) => SEC_E_OK_RAW,
        Err(e) => e.code().0,
    }
}

#[inline]
fn hr_to_status(hr: HRESULT) -> i32 {
    hr.0
}

impl SspiSession {
    /// Create a new SSPI session for the given target. Uses default
    /// credentials (current Kerberos ticket / NTLM identity).
    pub fn new_for_target(target_host: &str) -> crate::Result<Self> {
        let package = wide_nul("Negotiate");
        let spn = wide_nul(&build_spn(target_host));
        let mut cred = Box::new(SecHandle { dwLower: 0, dwUpper: 0 });
        let mut expiry: i64 = 0;

        // SAFETY: package buffer lives until end of call; NULLs explicitly
        // accepted by the API for "current user, default key fn".
        let status = status_code(unsafe {
            AcquireCredentialsHandleW(
                PCWSTR::null(),
                PCWSTR(package.as_ptr()),
                SECPKG_CRED_OUTBOUND,
                None,
                None,
                None,
                None,
                cred.as_mut() as *mut _,
                Some(&mut expiry),
            )
        });

        if status != SEC_E_OK_RAW {
            return Err(Error::Sspi(format!(
                "AcquireCredentialsHandleW failed: 0x{status:08X}"
            )));
        }

        debug!(spn = %String::from_utf16_lossy(&spn[..spn.len() - 1]), "SSPI session created");

        Ok(Self {
            cred,
            ctxt: Box::new(SecHandle { dwLower: 0, dwUpper: 0 }),
            ctxt_initialized: false,
            spn_wide: spn,
        })
    }

    /// Pump one round of the handshake. `input` = bytes from peer (empty
    /// for first call). Returns bytes to send and `done == true` when complete.
    pub fn step(&mut self, input: &[u8]) -> crate::Result<HandshakeStep> {
        let mut in_buf = SecBuffer {
            cbBuffer: input.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: if input.is_empty() {
                ptr::null_mut()
            } else {
                input.as_ptr() as *mut _
            },
        };
        let mut in_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_buf,
        };

        let mut out_buf = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };

        let mut context_attr: u32 = 0;
        let mut expiry: i64 = 0;
        let flags = ISC_REQ_ALLOCATE_MEMORY
            | ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_INTEGRITY
            | ISC_REQ_REPLAY_DETECT
            | ISC_REQ_SEQUENCE_DETECT
            | ISC_REQ_CONNECTION
            | ISC_REQ_MUTUAL_AUTH;

        let ctxt_in: Option<*const SecHandle> = if self.ctxt_initialized {
            Some(self.ctxt.as_mut() as *const _)
        } else {
            None
        };

        // SAFETY: descriptors + spn live for the call; ISC_REQ_ALLOCATE_MEMORY
        // means SSPI fills out_buf.pvBuffer which we free below.
        let status = hr_to_status(unsafe {
            InitializeSecurityContextW(
                Some(self.cred.as_mut() as *const _),
                ctxt_in,
                Some(self.spn_wide.as_ptr()),
                flags,
                0,
                SECURITY_NATIVE_DREP,
                if input.is_empty() {
                    None
                } else {
                    Some(&in_desc)
                },
                0,
                Some(self.ctxt.as_mut() as *mut _),
                Some(&mut out_desc),
                &mut context_attr,
                Some(&mut expiry),
            )
        });
        self.ctxt_initialized = true;

        trace!(status = format!("0x{status:08X}"), output_bytes = out_buf.cbBuffer, "ISC returned");

        let mut output_bytes = Vec::new();
        if !out_buf.pvBuffer.is_null() && out_buf.cbBuffer > 0 {
            let slice = unsafe {
                std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize)
            };
            output_bytes.extend_from_slice(slice);
            unsafe {
                let _ = FreeContextBuffer(out_buf.pvBuffer);
            }
        }

        if status == SEC_I_COMPLETE_AND_CONTINUE_RAW || status == SEC_I_COMPLETE_NEEDED_RAW {
            let cas = status_code(unsafe {
                CompleteAuthToken(self.ctxt.as_mut() as *mut _, &out_desc)
            });
            if cas != SEC_E_OK_RAW {
                return Err(Error::Sspi(format!(
                    "CompleteAuthToken failed: 0x{cas:08X}"
                )));
            }
        }

        match status {
            SEC_E_OK_RAW | SEC_I_COMPLETE_NEEDED_RAW => Ok(HandshakeStep {
                output: output_bytes,
                done: true,
            }),
            SEC_I_CONTINUE_NEEDED_RAW | SEC_I_COMPLETE_AND_CONTINUE_RAW => Ok(HandshakeStep {
                output: output_bytes,
                done: false,
            }),
            err => Err(Error::Sspi(format!(
                "InitializeSecurityContextW failed: 0x{err:08X}"
            ))),
        }
    }

    /// After handshake completes, query per-message overhead sizes.
    pub fn stream_sizes(&mut self) -> crate::Result<StreamSizes> {
        let mut sizes = MaybeUninit::<SecPkgContext_StreamSizes>::zeroed();
        // SAFETY: ctxt initialized post-handshake; sizes is a 20-byte stack buf.
        let status = status_code(unsafe {
            QueryContextAttributesW(
                self.ctxt.as_mut() as *const _,
                SECPKG_ATTR_STREAM_SIZES,
                sizes.as_mut_ptr() as *mut _,
            )
        });
        if status != SEC_E_OK_RAW {
            return Err(Error::Sspi(format!(
                "QueryContextAttributesW(STREAM_SIZES) failed: 0x{status:08X}"
            )));
        }
        let s = unsafe { sizes.assume_init() };
        Ok(StreamSizes {
            cb_header: s.cbHeader,
            cb_trailer: s.cbTrailer,
            cb_maximum_message: s.cbMaximumMessage,
            c_buffers: s.cBuffers,
            cb_block_size: s.cbBlockSize,
        })
    }
}

fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spn_format_matches_original() {
        assert_eq!(build_spn("CLIENT01"), "TERMSRV/CLIENT01");
    }

    #[test]
    fn can_acquire_credentials_for_localhost() {
        let s = SspiSession::new_for_target("localhost");
        assert!(s.is_ok(), "AcquireCredentialsHandleW failed: {:?}", s.err());
    }
}
