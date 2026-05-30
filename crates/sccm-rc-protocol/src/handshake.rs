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
    SecBufferDesc, SecPkgContext_Sizes, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY,
    ISC_REQ_CONNECTION, ISC_REQ_INTEGRITY, ISC_REQ_MUTUAL_AUTH, ISC_REQ_REPLAY_DETECT,
    ISC_REQ_SEQUENCE_DETECT, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_SIZES,
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

/// Per-message sizes returned by SSPI after handshake (SECPKG_ATTR_SIZES) —
/// needed for sizing EncryptMessage / DecryptMessage buffers. For Kerberos/
/// Negotiate these are the GSS-API token/trailer sizes (RFC 4121 wrap tokens),
/// which is what the SCCM SecurityFilter uses in the data phase.
#[derive(Debug, Clone, Copy)]
pub struct MessageSizes {
    pub cb_max_token: u32,
    pub cb_max_signature: u32,
    pub cb_block_size: u32,
    pub cb_security_trailer: u32,
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
        // Mirror CmRcViewer: cBuffers=2, first TOKEN with input bytes, second EMPTY.
        let mut in_bufs = [
            SecBuffer {
                cbBuffer: input.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: if input.is_empty() {
                    ptr::null_mut()
                } else {
                    input.as_ptr() as *mut _
                },
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN, // any type — empty buffer
                pvBuffer: ptr::null_mut(),
            },
        ];
        let mut in_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 2,
            pBuffers: in_bufs.as_mut_ptr(),
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
        // Minimal flag set — dropped MUTUAL_AUTH / REPLAY_DETECT / SEQUENCE_DETECT
        // / INTEGRITY to see if the SCCM server is strict about any of those.
        // (Diagnostic mode after observing CmRcViewer succeeds with what we suspect
        //  is a looser flag set.)
        let flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_CONNECTION;
        // Suppress unused warning while diagnosing:
        let _ = (ISC_REQ_INTEGRITY, ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT, ISC_REQ_MUTUAL_AUTH);

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

    /// After handshake completes, query per-message overhead sizes
    /// (SECPKG_ATTR_SIZES). For Kerberos/Negotiate this returns the GSS
    /// token + trailer sizes used to frame EncryptMessage output.
    pub fn message_sizes(&mut self) -> crate::Result<MessageSizes> {
        let mut sizes = MaybeUninit::<SecPkgContext_Sizes>::zeroed();
        // SAFETY: ctxt initialized post-handshake; sizes is a 16-byte stack buf.
        let status = status_code(unsafe {
            QueryContextAttributesW(
                self.ctxt.as_mut() as *const _,
                SECPKG_ATTR_SIZES,
                sizes.as_mut_ptr() as *mut _,
            )
        });
        if status != SEC_E_OK_RAW {
            return Err(Error::Sspi(format!(
                "QueryContextAttributesW(SIZES) failed: 0x{status:08X}"
            )));
        }
        let s = unsafe { sizes.assume_init() };
        Ok(MessageSizes {
            cb_max_token: s.cbMaxToken,
            cb_max_signature: s.cbMaxSignature,
            cb_block_size: s.cbBlockSize,
            cb_security_trailer: s.cbSecurityTrailer,
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
