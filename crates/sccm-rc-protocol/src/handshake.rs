//! SSPI Negotiate handshake (NTLM/Kerberos via sspi-rs).
//!
//! STATUS: stub. Token-exchange loop TBD until first live capture
//! confirms the SecFilter token framing on the wire.
//!
//! From the static RE we know (see `tools/rc-re/REBUILD-BRIEF.md` § 4):
//!   - SPN format is `TERMSRV/<target-hostname>` (Kerberos),
//!     with NTLM fallback when SPN lookup fails.
//!   - SecFilterClient template wraps each SSPI token in a length-
//!     prefixed frame; exact header layout TBD.

use crate::Result;

/// Builds the Service Principal Name to use for Kerberos auth.
///
/// Mirrors what the original viewer does in
/// `CmRcViewer.exe!StringCbPrintf(pTarget, ..., L"%s/%s", "TERMSRV", host)`.
pub fn build_spn(target_host: &str) -> String {
    format!("TERMSRV/{target_host}")
}

/// Placeholder for the full SSPI exchange loop. To be implemented in
/// Phase 2 of the roadmap, after the first pcap confirms wire format.
pub async fn perform_handshake(_target_host: &str) -> Result<()> {
    todo!("implement after pcap capture confirms SecFilter framing")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spn_format_matches_original() {
        assert_eq!(build_spn("CLIENT01"), "TERMSRV/CLIENT01");
    }
}
