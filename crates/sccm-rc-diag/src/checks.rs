//! Individual prerequisite checks. Each is `async` so the diag-runner
//! can fan them out concurrently and bound the total wall-clock time.

use crate::{winutil, CheckResult};
use sccm_rc_protocol::transport::SCCM_RC_PORT;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupEnum, NetLocalGroupGetMembers, LOCALGROUP_INFO_0,
    LOCALGROUP_MEMBERS_INFO_1,
};
use windows::Win32::Security::Authentication::Identity::{
    LsaClose, LsaEnumerateAccountsWithUserRight, LsaFreeMemory, LsaNtStatusToWinError,
    LsaOpenPolicy, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, POLICY_LOOKUP_NAMES,
    POLICY_VIEW_LOCAL_INFORMATION,
};
use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
};

const SCCM_SERVICE_NAME: &str = "CmRcService";

/// The "Permitted Viewers" group name is localized per OS language
/// (e.g. NL: "Gebruikers van Beheer op afstand van ConfigMgr"). We
/// discover it at runtime by enumerating local groups and matching
/// any whose name contains "ConfigMgr" — case-insensitive, accent-tolerant.
fn group_matches_sccm_rc(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("configmgr") && (n.contains("remote") || n.contains("beheer") || n.contains("afstand") || n.contains("control"))
        // Fallback: any group with both "configmgr" and any of the verbs above.
        // Also accept the bare "configmgr" + "users" / "gebruikers" pattern.
        || (n.contains("configmgr") && (n.contains("users") || n.contains("gebruikers")))
}

// ---------------------------------------------------------------- check 1
/// Check 1 — TCP/2701 reachability.
pub async fn tcp_reachable(target: &str) -> CheckResult {
    let start = Instant::now();
    let addr = format!("{target}:{SCCM_RC_PORT}");
    let connect = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await;
    let elapsed = start.elapsed();

    match connect {
        Ok(Ok(_)) => CheckResult::ok(
            "tcp_2701",
            format!("Target reachable at {addr} ({elapsed:?})"),
            elapsed,
        ),
        Ok(Err(e)) => CheckResult::blocker(
            "tcp_2701",
            format!("Cannot connect to {addr}: {e}"),
            "Causes (in order of likelihood):\n\
             1. Windows Firewall on target blocks TCP/2701 → check `Get-NetFirewallRule -DisplayGroup 'Configuration Manager Remote Control'`\n\
             2. CmRcService on target is not running → see the cmrcservice check below\n\
             3. Target is offline or hostname does not resolve",
            elapsed,
        ),
        Err(_) => CheckResult::blocker(
            "tcp_2701",
            format!("Connect to {addr} timed out after 3s"),
            "Likely a firewall silently dropping the SYN.",
            elapsed,
        ),
    }
}

// ---------------------------------------------------------------- check 2
/// Check 2 — `CmRcService` running state on the target via remote SCM.
pub async fn cmrcservice_state(target: &str) -> CheckResult {
    let target_str = target.to_string();
    let start = Instant::now();
    let result = tokio::task::spawn_blocking(move || query_service_state(&target_str)).await;
    let elapsed = start.elapsed();

    match result {
        Ok(Ok(state)) => match state {
            ServiceQueryOutcome::Running => CheckResult::ok(
                "cmrcservice",
                format!("CmRcService on {target} is RUNNING"),
                elapsed,
            ),
            ServiceQueryOutcome::Stopped => CheckResult::blocker(
                "cmrcservice",
                format!("CmRcService on {target} is STOPPED"),
                "Start it: on the target, run `Start-Service CmRcService`.\n\
                 If it won't start, check Event Viewer for SMS Agent Host errors;\n\
                 a common cause is WMI namespace corruption (error 80041010) —\n\
                 fix with `mofcomp \"C:\\Windows\\System32\\WBEM\\rcprov.mof\"`.",
                elapsed,
            ),
            ServiceQueryOutcome::Starting => CheckResult::warning(
                "cmrcservice",
                format!("CmRcService on {target} is in START_PENDING — wait a moment and retry"),
                "If it stays in this state, the service is hung. Restart it.",
                elapsed,
            ),
            ServiceQueryOutcome::Other(code) => CheckResult::warning(
                "cmrcservice",
                format!("CmRcService on {target} is in state code {code} (not RUNNING)"),
                "Check `Get-Service -ComputerName <target> CmRcService` for details.",
                elapsed,
            ),
            ServiceQueryOutcome::NotInstalled => CheckResult::blocker(
                "cmrcservice",
                format!("CmRcService does not exist on {target}"),
                "Either the SCCM client agent is not installed, or this target\n\
                 has Remote Control disabled at the client-settings level.",
                elapsed,
            ),
        },
        Ok(Err(e)) => match e.code() {
            c if c.0 as u32 == ERROR_ACCESS_DENIED.0 => CheckResult::warning(
                "cmrcservice",
                format!(
                    "Access denied querying SCM on {target} — you may lack admin on the target"
                ),
                "This is informational — the SCCM RC connection itself may still work\n\
                 if the user has Remote Control rights via a different mechanism.\n\
                 To enable the check, run as a target admin or via a delegated SCM ACL.",
                elapsed,
            ),
            _ => CheckResult::warning(
                "cmrcservice",
                format!(
                    "Could not query SCM on {target}: {e} (HRESULT {:?})",
                    e.code()
                ),
                "Remote SCM/RPC may be blocked by firewall (ports 135 + dynamic RPC).\n\
                 This check is best-effort and does not block the actual viewer connection.",
                elapsed,
            ),
        },
        Err(join_err) => CheckResult::warning(
            "cmrcservice",
            format!("Internal: blocking task panicked: {join_err}"),
            "Report this as a bug.",
            elapsed,
        ),
    }
}

enum ServiceQueryOutcome {
    Running,
    Stopped,
    Starting,
    NotInstalled,
    Other(u32),
}

fn query_service_state(target: &str) -> windows::core::Result<ServiceQueryOutcome> {
    let target_w = winutil::unc_target(target);
    let service_w = winutil::to_wide(SCCM_SERVICE_NAME);

    // SAFETY: pointers from winutil buffers live for the call; SCM handles
    // are closed in every exit path.
    unsafe {
        let scm = OpenSCManagerW(
            if target_w.len() <= 1 {
                windows::core::PCWSTR::null()
            } else {
                winutil::pcwstr(&target_w)
            },
            windows::core::PCWSTR::null(),
            SC_MANAGER_CONNECT,
        )?;

        let svc = match OpenServiceW(scm, winutil::pcwstr(&service_w), SERVICE_QUERY_STATUS) {
            Ok(s) => s,
            Err(e) => {
                let _ = CloseServiceHandle(scm);
                if e.code().0 as u32 == ERROR_SERVICE_DOES_NOT_EXIST.0 {
                    return Ok(ServiceQueryOutcome::NotInstalled);
                }
                return Err(e);
            }
        };

        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut bytes_needed = 0u32;
        let buf = std::slice::from_raw_parts_mut(
            (&mut status as *mut SERVICE_STATUS_PROCESS) as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        let q = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, Some(buf), &mut bytes_needed);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        q?;

        Ok(match status.dwCurrentState {
            s if s == SERVICE_RUNNING => ServiceQueryOutcome::Running,
            s if s == SERVICE_STOPPED => ServiceQueryOutcome::Stopped,
            s if s == SERVICE_START_PENDING => ServiceQueryOutcome::Starting,
            other => ServiceQueryOutcome::Other(other.0),
        })
    }
}

// ---------------------------------------------------------------- check 3
/// Check 3 — list accounts that have `SeNetworkLogonRight` on the target.
///
/// We don't try to resolve "is the viewer user in any of these (transitively
/// through groups)" because that would require expanding group nesting via
/// AD, which is brittle. Instead we present the raw list and let the human
/// (or the viewer-UI) make the comparison.
pub async fn network_logon_right(target: &str, viewer_user: &str) -> CheckResult {
    let t = target.to_string();
    let u = viewer_user.to_string();
    let start = Instant::now();
    let result = tokio::task::spawn_blocking(move || enumerate_network_logon(&t)).await;
    let elapsed = start.elapsed();

    match result {
        Ok(Ok(accounts)) => {
            let me_listed = accounts.iter().any(|n| {
                n.eq_ignore_ascii_case(&u)
                    || n.split('\\')
                        .next_back()
                        .map(|p| p.eq_ignore_ascii_case(&u))
                        .unwrap_or(false)
            });
            let list = if accounts.is_empty() {
                "  (no accounts have this right — RC will fail for everyone)".to_string()
            } else {
                accounts
                    .iter()
                    .map(|a| format!("  - {a}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let msg = format!(
                "Accounts on {target} with 'Access this computer from the network' right:\n{list}\n\n\
                 Viewer user '{viewer_user}' directly listed: {}",
                if me_listed { "YES" } else { "NO (but may be via group nesting)" }
            );
            if me_listed || !accounts.is_empty() {
                CheckResult::warning(
                    "se_network_logon_right",
                    msg,
                    "If your user (or a group they're in) is NOT in the list above,\n\
                     SCCM RC will fail silently. Add the user/group via:\n\
                       `secpol.msc` → Local Policies → User Rights Assignment\n\
                       → 'Access this computer from the network'.\n\
                     CIS / Microsoft Security Baselines often remove non-admin groups —\n\
                     create a dedicated 'SCCM RC Operators' AD group and add it here.",
                    elapsed,
                )
            } else {
                CheckResult::blocker(
                    "se_network_logon_right",
                    msg,
                    "Restore the right via secpol.msc (see warning above).",
                    elapsed,
                )
            }
        }
        Ok(Err(e)) => match e.code() {
            c if c.0 as u32 == ERROR_ACCESS_DENIED.0 => CheckResult::warning(
                "se_network_logon_right",
                format!("Access denied opening LSA policy on {target}"),
                "LSA enumeration normally requires admin on the target.\n\
                 Run this diag tool as a target admin to verify.",
                elapsed,
            ),
            _ => CheckResult::warning(
                "se_network_logon_right",
                format!("Could not enumerate via LSA on {target}: {e}"),
                "Remote LSA / RPC may be blocked. This check is informational only.",
                elapsed,
            ),
        },
        Err(join_err) => CheckResult::warning(
            "se_network_logon_right",
            format!("Internal: {join_err}"),
            "Report as a bug.",
            elapsed,
        ),
    }
}

fn enumerate_network_logon(target: &str) -> windows::core::Result<Vec<String>> {
    let target_w = winutil::unc_target(target);
    let mut system_name = LSA_UNICODE_STRING {
        Length: ((target_w.len() - 1) * 2) as u16,
        MaximumLength: (target_w.len() * 2) as u16,
        Buffer: PWSTR(target_w.as_ptr() as *mut u16),
    };
    let oa = LSA_OBJECT_ATTRIBUTES::default();
    let mut policy = LSA_HANDLE::default();

    let right = winutil::to_wide("SeNetworkLogonRight");
    let right_str = LSA_UNICODE_STRING {
        Length: ((right.len() - 1) * 2) as u16,
        MaximumLength: (right.len() * 2) as u16,
        Buffer: PWSTR(right.as_ptr() as *mut u16),
    };

    // SAFETY: all pointers live for the duration of the FFI calls; we close
    // the policy handle and free LSA-allocated buffers in every exit path.
    unsafe {
        let want_local = target_w.len() <= 1;
        let sys_ptr = if want_local {
            std::ptr::null_mut()
        } else {
            &mut system_name
        };
        let status = LsaOpenPolicy(
            Some(sys_ptr),
            &oa,
            (POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION) as u32,
            &mut policy,
        );
        if status.0 != 0 {
            let werr = LsaNtStatusToWinError(status);
            return Err(windows::core::Error::from_hresult(
                windows::core::HRESULT::from_win32(werr),
            ));
        }

        let mut buf: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut count: u32 = 0;
        let enum_status =
            LsaEnumerateAccountsWithUserRight(policy, Some(&right_str), &mut buf, &mut count);
        if enum_status.0 != 0 {
            let _ = LsaClose(policy);
            // NTSTATUS 0xC0000034 = STATUS_OBJECT_NAME_NOT_FOUND, meaning
            // no accounts have the right — treat as empty, not as error.
            if enum_status.0 == 0xC0000034u32 as i32 {
                return Ok(Vec::new());
            }
            let werr = LsaNtStatusToWinError(enum_status);
            return Err(windows::core::Error::from_hresult(
                windows::core::HRESULT::from_win32(werr),
            ));
        }

        let infos = std::slice::from_raw_parts(
            buf as *const windows::Win32::Security::Authentication::Identity::LSA_ENUMERATION_INFORMATION,
            count as usize,
        );

        let mut names = Vec::new();
        for info in infos {
            names.push(
                resolve_sid(target, info.Sid.0 as *mut _)
                    .unwrap_or_else(|| "<unresolvable SID>".to_string()),
            );
        }

        let _ = LsaFreeMemory(Some(buf));
        let _ = LsaClose(policy);
        Ok(names)
    }
}

fn resolve_sid(target: &str, sid: *mut std::ffi::c_void) -> Option<String> {
    use windows::core::PSTR;
    let target_w = winutil::unc_target(target);
    let want_local = target_w.len() <= 1;

    let mut name_buf = vec![0u16; 256];
    let mut domain_buf = vec![0u16; 256];
    let mut name_len = name_buf.len() as u32;
    let mut domain_len = domain_buf.len() as u32;
    let mut sid_type = SID_NAME_USE::default();

    // SAFETY: buffers + length-by-ref are valid; SID is non-null per caller.
    let ok = unsafe {
        let _ = PSTR::null(); // silence import-only warning
        LookupAccountSidW(
            if want_local {
                windows::core::PCWSTR::null()
            } else {
                winutil::pcwstr(&target_w)
            },
            PSID(sid),
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
    };
    if ok.is_err() {
        return None;
    }
    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
    Some(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

// ---------------------------------------------------------------- check 4
/// Check 4 — list members of the (localized) "ConfigMgr Remote Control Users"
/// local group on the target.
pub async fn permitted_viewers(target: &str, viewer_user: &str) -> CheckResult {
    let t = target.to_string();
    let u = viewer_user.to_string();
    let start = Instant::now();
    let result = tokio::task::spawn_blocking(move || enumerate_group_members(&t)).await;
    let elapsed = start.elapsed();

    match result {
        Ok(Ok((group_name, members))) => {
            let me_listed = members.iter().any(|m| {
                m.eq_ignore_ascii_case(&u)
                    || m.split('\\')
                        .next_back()
                        .map(|p| p.eq_ignore_ascii_case(&u))
                        .unwrap_or(false)
            });
            let list = if members.is_empty() {
                "  (group is empty — no one can use SCCM RC)".to_string()
            } else {
                members
                    .iter()
                    .map(|m| format!("  - {m}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let msg = format!(
                "Members of '{group_name}' on {target}:\n{list}\n\n\
                 Viewer user '{viewer_user}' directly listed: {}",
                if me_listed {
                    "YES"
                } else {
                    "NO (but may be via nested group)"
                }
            );
            CheckResult::warning(
                "permitted_viewers",
                msg,
                "If you (or a group you're in) is NOT in the list, RC will be rejected.\n\
                 Add via SCCM Client Settings → Remote Tools → 'Permitted Viewers'\n\
                 (preferred — pushes to all clients), or locally on the target:\n\
                   `net localgroup \"<group-name-above>\" DOMAIN\\user /add`",
                elapsed,
            )
        }
        Ok(Err(GroupErr::NotFound)) => CheckResult::blocker(
            "permitted_viewers",
            format!(
                "No local group on {target} matches the ConfigMgr Remote Control Users pattern"
            ),
            "Either the SCCM client agent isn't installed, or Remote Control is\n\
             disabled in Client Settings (which suppresses the group creation).",
            elapsed,
        ),
        Ok(Err(GroupErr::Win(e))) => CheckResult::warning(
            "permitted_viewers",
            format!("Could not enumerate local groups on {target}: {e}"),
            "Remote SAM may be blocked, or you lack rights to enumerate local groups.",
            elapsed,
        ),
        Err(join_err) => CheckResult::warning(
            "permitted_viewers",
            format!("Internal: {join_err}"),
            "Report as a bug.",
            elapsed,
        ),
    }
}

enum GroupErr {
    NotFound,
    Win(windows::core::Error),
}

impl From<windows::core::Error> for GroupErr {
    fn from(e: windows::core::Error) -> Self {
        GroupErr::Win(e)
    }
}

fn enumerate_group_members(target: &str) -> Result<(String, Vec<String>), GroupErr> {
    // First: find the actual (possibly localized) group name.
    let group_name = find_sccm_rc_group(target)?;

    let target_w = winutil::unc_target(target);
    let group_w = winutil::to_wide(&group_name);

    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries = 0u32;
    let mut total = 0u32;

    let server = if target_w.len() <= 1 {
        windows::core::PCWSTR::null()
    } else {
        winutil::pcwstr(&target_w)
    };

    // SAFETY: server/group buffers live for the call; we always free the
    // returned NetApi buffer.
    let rc = unsafe {
        NetLocalGroupGetMembers(
            server,
            winutil::pcwstr(&group_w),
            1,
            &mut buf_ptr,
            u32::MAX,
            &mut entries,
            &mut total,
            None,
        )
    };
    if rc != 0 {
        return Err(GroupErr::Win(windows::core::Error::from_hresult(
            windows::core::HRESULT::from_win32(rc),
        )));
    }

    let mut names = Vec::new();
    if !buf_ptr.is_null() && entries > 0 {
        let infos = unsafe {
            std::slice::from_raw_parts(
                buf_ptr as *const LOCALGROUP_MEMBERS_INFO_1,
                entries as usize,
            )
        };
        for info in infos {
            let name = unsafe { winutil::read_wide_nul(info.lgrmi1_name.0) };
            if name.is_empty() {
                continue;
            }
            names.push(name);
        }
    }

    if !buf_ptr.is_null() {
        let _ = unsafe { NetApiBufferFree(Some(buf_ptr as *const std::ffi::c_void)) };
    }
    Ok((group_name, names))
}

fn find_sccm_rc_group(target: &str) -> Result<String, GroupErr> {
    let target_w = winutil::unc_target(target);
    let server = if target_w.len() <= 1 {
        windows::core::PCWSTR::null()
    } else {
        winutil::pcwstr(&target_w)
    };

    let mut found: Option<String> = None;
    let mut resume_handle: usize = 0;

    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY: NetApi will allocate `buf`; we free in every exit.
        let rc = unsafe {
            NetLocalGroupEnum(
                server,
                0,
                &mut buf,
                8192,
                &mut entries,
                &mut total,
                Some(&mut resume_handle),
            )
        };
        // ERROR_MORE_DATA (234) is fine and means "call me again"
        if rc != 0 && rc != 234 {
            return Err(GroupErr::Win(windows::core::Error::from_hresult(
                windows::core::HRESULT::from_win32(rc),
            )));
        }

        let infos = unsafe {
            std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_0, entries as usize)
        };
        for info in infos {
            let name = unsafe { winutil::read_wide_nul(info.lgrpi0_name.0) };
            if group_matches_sccm_rc(&name) {
                found = Some(name);
                break;
            }
        }
        let _ = unsafe { NetApiBufferFree(Some(buf as *const std::ffi::c_void)) };
        if found.is_some() || rc == 0 {
            break;
        }
    }

    found.ok_or(GroupErr::NotFound)
}

// ---------------------------------------------------------------- runner
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
