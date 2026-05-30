//! SSPI Negotiate handshake (NTLM/Kerberos via sspi-rs).
//!
//! Flow confirmed from static RE (`securityfilter.cpp` decomp):
//!
//! 1. Call `InitSecurityInterfaceW()` once to get the function table.
//! 2. `AcquireCredentialsHandleW` with package `Negotiate`.
//! 3. Repeatedly:
//!    a. Receive bytes from peer (raw SSPI token).
//!    b. Build input `SecBuffer{cbBuffer=N, BufferType=SECBUFFER_TOKEN, pvBuffer=bytes}`,
//!       wrapped in a `SecBufferDesc{ulVersion=0, cBuffers=2, pBuffers=&buf}`.
//!       (Why 2? Microsoft passes 2 SecBuffers — first is the token, second
//!       is empty/padding. We mirror their layout.)
//!    c. Build empty output `SecBuffer{type=TOKEN, pvBuffer=NULL}` (SSPI allocates).
//!    d. Call `InitializeSecurityContextW(...)`.
//!    e. If status == `SEC_I_COMPLETE_AND_CONTINUE` (0x90314):
//!       call `CompleteAuthToken(ctxt, &out_desc)`.
//!    f. If status in {SEC_I_CONTINUE_NEEDED (0x90313),
//!       SEC_I_COMPLETE_AND_CONTINUE}: send output bytes to peer, then loop.
//!    g. If status == 0 (SEC_E_OK): handshake done.
//!
//! SPN: `TERMSRV/<target-hostname>` (Kerberos), with NTLM fallback.

use crate::Result;

/// Builds the Service Principal Name to use for Kerberos auth.
///
/// Mirrors the original viewer's `StringCbPrintf(L"%s/%s", "TERMSRV", host)`.
pub fn build_spn(target_host: &str) -> String {
    format!("TERMSRV/{target_host}")
}

/// Placeholder for the full SSPI exchange loop. To be implemented in
/// Phase 2 once `sspi-rs` is added back to the workspace (was deferred
/// in Phase 0 due to a transitive picky-krb version conflict — verify
/// a newer sspi-rs first).
pub async fn perform_handshake(_target_host: &str) -> Result<()> {
    todo!("Phase 2 — re-add sspi-rs and wire the InitializeSecurityContext loop")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spn_format_matches_original() {
        assert_eq!(build_spn("CLIENT01"), "TERMSRV/CLIENT01");
    }
}
