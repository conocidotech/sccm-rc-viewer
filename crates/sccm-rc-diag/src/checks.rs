//! Individual prerequisite checks. Each is `async` so the diag-runner
//! can fan them out concurrently and bound the total wall-clock time.

use crate::CheckResult;
use sccm_rc_protocol::transport::SCCM_RC_PORT;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Check 1 — TCP/2701 reachability.
///
/// Most basic check: can we even open a socket? Fails if the target
/// is down, firewall blocks 2701, or CcmExec/CmRcService isn't listening.
pub async fn tcp_reachable(target: &str) -> CheckResult {
    let start = Instant::now();
    let addr = format!("{target}:{SCCM_RC_PORT}");
    let connect = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await;
    let elapsed = start.elapsed();

    match connect {
        Ok(Ok(_)) => CheckResult::ok(
            "tcp_2701",
            format!("Target reachable at {addr} ({:?})", elapsed),
            elapsed,
        ),
        Ok(Err(e)) => CheckResult::blocker(
            "tcp_2701",
            format!("Cannot connect to {addr}: {e}"),
            "Causes (in order of likelihood):\n\
             1. Windows Firewall on target is blocking TCP/2701 → check `Get-NetFirewallRule -DisplayGroup 'Configuration Manager Remote Control'`\n\
             2. CmRcService on target is not running → `Get-Service CmRcService` on the target should be Running\n\
             3. Target is offline or hostname does not resolve",
            elapsed,
        ),
        Err(_) => CheckResult::blocker(
            "tcp_2701",
            format!("Connect to {addr} timed out after 3s"),
            "Likely a firewall silently dropping the SYN. Test from the same network as a known-working viewer.",
            elapsed,
        ),
    }
}

/// Check 2 — CmRcService running state (via Service Control Manager on target).
/// STATUS: stub. Requires SC_HANDLE remote OpenSCManager via windows-rs.
pub async fn cmrcservice_state(_target: &str) -> CheckResult {
    CheckResult::warning(
        "cmrcservice",
        "Not yet implemented",
        "Manually verify: `Get-Service -ComputerName <target> CmRcService` returns Running",
        Duration::ZERO,
    )
}

/// Check 3 — "Access this computer from the network" user right on target.
/// STATUS: stub. Requires LsaOpenPolicy + LsaEnumerateAccountRights remotely.
pub async fn network_logon_right(_target: &str, _viewer_user: &str) -> CheckResult {
    CheckResult::warning(
        "se_network_logon_right",
        "Not yet implemented",
        "This is the most common 'silent fail' cause. Check on target:\n\
         `secedit /export /cfg C:\\sec.cfg ; Select-String 'SeNetworkLogonRight' C:\\sec.cfg`\n\
         The viewer user (or a group they're in) must appear in that list. \n\
         CIS/STIG/MS Security Baselines often remove non-admin groups → \n\
         add a dedicated 'SCCM RC Operators' group there.",
        Duration::ZERO,
    )
}

/// Check 4 — Permitted Viewers membership on target.
/// STATUS: stub. Requires NetLocalGroupGetMembers remotely.
pub async fn permitted_viewers(_target: &str, _viewer_user: &str) -> CheckResult {
    CheckResult::warning(
        "permitted_viewers",
        "Not yet implemented",
        "Manually verify viewer user is in 'ConfigMgr Remote Control Users' local group on target.",
        Duration::ZERO,
    )
}

/// Run all checks concurrently and return them in fixed order
/// (so output is stable across runs).
pub async fn run_all(target: &str, viewer_user: &str) -> Vec<CheckResult> {
    let (a, b, c, d) = tokio::join!(
        tcp_reachable(target),
        cmrcservice_state(target),
        network_logon_right(target, viewer_user),
        permitted_viewers(target, viewer_user),
    );
    vec![a, b, c, d]
}
