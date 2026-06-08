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
    AcquireCredentialsHandleW, CompleteAuthToken, DecryptMessage, DeleteSecurityContext,
    EncryptMessage, FreeContextBuffer, FreeCredentialsHandle, InitializeSecurityContextW,
    QueryContextAttributesW, SecBuffer, SecBufferDesc, SecPkgContext_Sizes, ISC_REQ_ALLOCATE_MEMORY,
    ISC_REQ_CONFIDENTIALITY, ISC_REQ_CONNECTION, ISC_REQ_INTEGRITY, ISC_REQ_MUTUAL_AUTH,
    ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT, SECBUFFER_DATA, SECBUFFER_TOKEN,
    SECBUFFER_VERSION, SECPKG_ATTR_SIZES, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
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
    sizes: Option<MessageSizes>,
    /// Granted SSPI context attributes (ISC_RET_*) from the last ISC call — used
    /// to report whether confidentiality (encryption) and mutual auth were
    /// negotiated.
    context_attr: u32,
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
            sizes: None,
            context_attr: 0,
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
        // Standard SSPI flag set (mirrors mstscax): confidentiality + integrity +
        // replay/sequence detection + mutual auth. This makes the sealed channel
        // reject tampered, replayed or reordered frames and proves the server's
        // identity (Kerberos). ISC_RET_* is verified after the handshake.
        let flags = ISC_REQ_ALLOCATE_MEMORY
            | ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_INTEGRITY
            | ISC_REQ_REPLAY_DETECT
            | ISC_REQ_SEQUENCE_DETECT
            | ISC_REQ_MUTUAL_AUTH
            | ISC_REQ_CONNECTION;

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
        self.context_attr = context_attr; // granted ISC_RET_* flags

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
        let ms = MessageSizes {
            cb_max_token: s.cbMaxToken,
            cb_max_signature: s.cbMaxSignature,
            cb_block_size: s.cbBlockSize,
            cb_security_trailer: s.cbSecurityTrailer,
        };
        self.sizes = Some(ms);
        Ok(ms)
    }

    fn ensure_sizes(&mut self) -> crate::Result<MessageSizes> {
        if let Some(s) = self.sizes {
            Ok(s)
        } else {
            self.message_sizes()
        }
    }

    /// Whether the negotiated context encrypts messages (confidentiality).
    pub fn confidentiality(&self) -> bool {
        const ISC_RET_CONFIDENTIALITY: u32 = 0x0000_0010;
        self.context_attr & ISC_RET_CONFIDENTIALITY != 0
    }

    /// Whether the server's identity was mutually authenticated (Kerberos proves
    /// the server holds the service key for the SPN).
    pub fn mutual_auth(&self) -> bool {
        const ISC_RET_MUTUAL_AUTH: u32 = 0x0000_0002;
        self.context_attr & ISC_RET_MUTUAL_AUTH != 0
    }

    /// The security package the Negotiate handshake settled on ("Kerberos" /
    /// "NTLM"). Best-effort — `None` if the query fails.
    pub fn package_name(&self) -> Option<String> {
        if !self.ctxt_initialized {
            return None;
        }
        use windows::Win32::Security::Authentication::Identity::{
            SecPkgContext_NegotiationInfoW, SECPKG_ATTR_NEGOTIATION_INFO,
        };
        let mut info = MaybeUninit::<SecPkgContext_NegotiationInfoW>::zeroed();
        let status = status_code(unsafe {
            QueryContextAttributesW(
                self.ctxt.as_ref() as *const _,
                SECPKG_ATTR_NEGOTIATION_INFO,
                info.as_mut_ptr() as *mut _,
            )
        });
        if status != SEC_E_OK_RAW {
            return None;
        }
        let info = unsafe { info.assume_init() };
        let pkg = info.PackageInfo;
        if pkg.is_null() {
            return None;
        }
        // `Name` is a NUL-terminated UTF-16 pointer (`*mut u16`).
        let name = unsafe {
            let np = (*pkg).Name;
            if np.is_null() {
                None
            } else {
                let mut len = 0usize;
                while *np.add(len) != 0 {
                    len += 1;
                }
                Some(String::from_utf16_lossy(std::slice::from_raw_parts(np, len)))
            }
        };
        unsafe {
            let _ = FreeContextBuffer(pkg as *mut _);
        }
        name
    }

    /// Seal a plaintext application message for the SCCM data phase.
    ///
    /// Produces the SecFilter frame body:
    ///   `[u16 LE data_len][encrypted data][u16 LE token_len][GSS wrap token]`
    /// matching the layout observed on the wire (see docs/SPEC.md § 2).
    pub fn seal(&mut self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let sizes = self.ensure_sizes()?;

        // Working buffers: data (in-place encrypt) + token (trailer).
        let mut data = plaintext.to_vec();
        let mut token = vec![0u8; sizes.cb_security_trailer as usize];

        let mut bufs = [
            SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_mut_ptr() as *mut _,
            },
            SecBuffer {
                cbBuffer: data.len() as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data.as_mut_ptr() as *mut _,
            },
        ];
        let mut desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 2,
            pBuffers: bufs.as_mut_ptr(),
        };

        // SAFETY: ctxt established; buffers live across the call. fQOP=0 => seal.
        let status = hr_to_status(unsafe {
            EncryptMessage(self.ctxt.as_mut() as *const _, 0, &mut desc, 0)
        });
        if status != SEC_E_OK_RAW {
            return Err(Error::Sspi(format!("EncryptMessage failed: 0x{status:08X}")));
        }

        // Token length may shrink from cb_security_trailer to the actual size.
        let token_len = bufs[0].cbBuffer as usize;
        let data_len = bufs[1].cbBuffer as usize;

        // The wire format prefixes each part with a u16 length. RDP PDUs handed to
        // send_rdp stay well under 64 KB (MCS/TPKT framing), but guard the cast so
        // an oversized chunk errors loudly instead of silently truncating the
        // length and corrupting the frame.
        if data_len > u16::MAX as usize || token_len > u16::MAX as usize {
            return Err(Error::Protocol(format!(
                "sealed frame exceeds u16 length prefix: data={data_len} token={token_len}"
            )));
        }

        let mut out = Vec::with_capacity(2 + data_len + 2 + token_len);
        out.extend_from_slice(&(data_len as u16).to_le_bytes());
        out.extend_from_slice(&data[..data_len]);
        out.extend_from_slice(&(token_len as u16).to_le_bytes());
        out.extend_from_slice(&token[..token_len]);
        Ok(out)
    }

    /// Unseal an SCCM data-phase frame body back to plaintext.
    /// Inverse of `seal`.
    pub fn unseal(&mut self, frame_body: &[u8]) -> crate::Result<Vec<u8>> {
        if frame_body.len() < 4 {
            return Err(Error::Protocol("sealed frame too short".into()));
        }
        let data_len = u16::from_le_bytes([frame_body[0], frame_body[1]]) as usize;
        let off_token_len = 2 + data_len;
        if off_token_len + 2 > frame_body.len() {
            return Err(Error::Protocol("sealed frame: bad data_len".into()));
        }
        let token_len =
            u16::from_le_bytes([frame_body[off_token_len], frame_body[off_token_len + 1]]) as usize;
        let token_off = off_token_len + 2;
        if token_off + token_len > frame_body.len() {
            return Err(Error::Protocol("sealed frame: bad token_len".into()));
        }

        let mut data = frame_body[2..2 + data_len].to_vec();
        let mut token = frame_body[token_off..token_off + token_len].to_vec();

        let mut bufs = [
            SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_mut_ptr() as *mut _,
            },
            SecBuffer {
                cbBuffer: data.len() as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data.as_mut_ptr() as *mut _,
            },
        ];
        let mut desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 2,
            pBuffers: bufs.as_mut_ptr(),
        };

        let mut qop: u32 = 0;
        // SAFETY: ctxt established; buffers live across the call.
        let status = hr_to_status(unsafe {
            DecryptMessage(self.ctxt.as_mut() as *const _, &mut desc, 0, Some(&mut qop))
        });
        if status != SEC_E_OK_RAW {
            return Err(Error::Sspi(format!("DecryptMessage failed: 0x{status:08X}")));
        }
        // Reject a frame that was only signed, not encrypted: we treat this channel
        // as confidential, so an on-path attacker must not be able to feed us
        // unencrypted-but-authenticated data. A properly sealed frame returns qop=0.
        const SECQOP_WRAP_NO_ENCRYPT: u32 = 0x8000_0001;
        if qop == SECQOP_WRAP_NO_ENCRYPT {
            return Err(Error::Sspi("unsealed frame was not encrypted (QOP no-encrypt)".into()));
        }

        // Plaintext is in the DATA buffer (decrypted in place).
        let out_len = bufs[1].cbBuffer as usize;
        Ok(data[..out_len].to_vec())
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
