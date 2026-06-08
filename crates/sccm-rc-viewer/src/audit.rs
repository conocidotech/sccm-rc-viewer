//! Lightweight session audit log (JSONL): who connected to which machine, when,
//! for how long, and in what mode. One line per event, appended to
//! `%LOCALAPPDATA%\sccm-rc\audit.jsonl` (falls back to TEMP). Addresses the
//! original "no audit" complaint about the legacy tool.

use std::io::Write;
use std::time::SystemTime;

fn audit_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("sccm-rc");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("audit.jsonl")
}

/// Rotate the audit log when it grows past a cap, keeping one previous
/// generation (`audit.jsonl.1`). Best-effort — failures are ignored. Windows
/// `rename` won't overwrite, so the stale backup is removed first.
fn rotate_if_large(path: &std::path::Path) {
    const MAX_BYTES: u64 = 5 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_BYTES {
            let bak = path.with_extension("jsonl.1");
            let _ = std::fs::remove_file(&bak);
            let _ = std::fs::rename(path, &bak);
        }
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format epoch seconds as "YYYY-MM-DD HH:MM:SS" UTC (civil time, no deps —
/// Howard Hinnant's days-from-civil algorithm, run in reverse).
fn utc_string(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Escape the few characters that would break a JSON string value.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Append one audit event. `duration_s` is set on the "disconnect" event.
pub fn log_event(target: &str, grant: &str, event: &str, duration_s: Option<u64>) {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let from = std::env::var("COMPUTERNAME").unwrap_or_default();
    let now = epoch_secs();
    let dur = duration_s
        .map(|d| format!(",\"duration_s\":{d}"))
        .unwrap_or_default();
    let line = format!(
        "{{\"ts\":{now},\"time\":\"{}\",\"event\":\"{}\",\"target\":\"{}\",\"by\":\"{}\",\"from\":\"{}\",\"grant\":\"{}\"{}}}\n",
        utc_string(now),
        esc(event),
        esc(target),
        esc(&user),
        esc(&from),
        esc(grant),
        dur
    );
    let path = audit_path();
    rotate_if_large(&path);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}
