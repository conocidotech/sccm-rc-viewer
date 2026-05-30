//! Session arbitration ("ask the remote user for permission").
//!
//! STATUS: stub. The original viewer calls
//!   `IRDPCLAxHost::RequestHostArbitration(targetHost, viewerUserName)`
//! over MS-RPC. The RPC interface UUID is hidden in `RdpCoreSccm.dll`
//! and we don't have it yet — needs pcap + RPC-binding decode in Phase 1.
//!
//! Possible outcomes (from `CmRcViewer.exe.gh.strings.txt`):
//!   - OnSessionArbitrationHostAllowed  → proceed
//!   - OnSessionArbitrationHostDenied   → abort, user said no
//!   - OnSessionArbitrationHostIdle     → no one at the target
//!   - OnSessionArbitrationHostInUse    → someone else is already connected

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbitrationOutcome {
    Allowed,
    Denied,
    HostIdle,
    HostInUse,
}

pub async fn request(_target_host: &str, _viewer_user: &str) -> Result<ArbitrationOutcome> {
    todo!("implement after RPC interface UUID + opnum table extracted from pcap")
}
