//! Recent connection targets (most-recent-first), persisted to
//! `%LOCALAPPDATA%\sccm-rc\recent.txt` — one host per line.

use std::io::Write;

const CAP: usize = 12;

fn path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("sccm-rc");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("recent.txt")
}

/// Recent hosts, most-recent-first (capped).
pub fn load() -> Vec<String> {
    std::fs::read_to_string(path())
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .take(CAP)
        .collect()
}

/// Record `host` as the most-recent target (dedup, case-insensitive).
pub fn add(host: &str) {
    let host = host.trim();
    if host.is_empty() {
        return;
    }
    let mut list = load();
    list.retain(|h| !h.eq_ignore_ascii_case(host));
    list.insert(0, host.to_string());
    list.truncate(CAP);
    if let Ok(mut f) = std::fs::File::create(path()) {
        let _ = f.write_all(list.join("\r\n").as_bytes());
    }
}
