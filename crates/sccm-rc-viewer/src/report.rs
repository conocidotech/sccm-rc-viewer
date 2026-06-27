//! Bug-report bundler: collects the audit-log tail, a screenshot of the current
//! desktop, and a sysinfo block into a fresh folder under `%TEMP%` and opens
//! Explorer at it. No network upload — the operator attaches the files
//! themselves to an email or GitHub issue. Anything that fails is skipped
//! best-effort; the folder is returned with whatever did succeed.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = env!("GIT_HASH");

/// What the caller hands over for inclusion in the bundle.
pub struct Snapshot<'a> {
    pub target: &'a str,
    pub width: u32,
    pub height: u32,
    /// Raw RGBA framebuffer; saved as PNG when non-empty and well-formed.
    pub rgba: &'a [u8],
}

/// Build a bug-report folder and return its path.
pub fn generate(snap: Snapshot) -> std::io::Result<PathBuf> {
    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("sccm-rc-report-{epoch}"));
    fs::create_dir_all(&dir)?;

    let envs: Vec<String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("SCCM_RC_") || k == "RUST_LOG")
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let info = format!(
        "sccm-rc-viewer bug report\n\
         =========================\n\
         generated_at_epoch: {epoch}\n\
         viewer_version:     {VERSION}\n\
         viewer_git_hash:    {GIT_HASH}\n\
         target_host:        {target}\n\
         local_hostname:     {host}\n\
         local_user:         {user}\n\
         framebuffer:        {w}x{h}\n\
         os:                 {os}\n\
         env (SCCM_RC_*, RUST_LOG):\n  {envs}\n",
        target = snap.target,
        host = std::env::var("COMPUTERNAME").unwrap_or_default(),
        user = std::env::var("USERNAME").unwrap_or_default(),
        w = snap.width,
        h = snap.height,
        os = format!(
            "{} ({}) — {}",
            std::env::var("OS").unwrap_or_default(),
            std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default(),
            windows_version_line()
        ),
        envs = if envs.is_empty() {
            "(none set)".to_string()
        } else {
            envs.join("\n  ")
        },
    );
    fs::write(dir.join("sysinfo.txt"), info)?;

    // Audit-log tail (last 200 lines) — best-effort; absent if user never connected.
    if let Some(audit) = audit_path() {
        let _ = copy_tail(&audit, &dir.join("audit-tail.jsonl"), 200);
    }

    // Viewer tracing log — the most diagnostic-rich file in the bundle.
    // Grab the current day's `viewer.log` plus any prior day still on disk,
    // so a bug that happened "around midnight" still has its context.
    for path in viewer_log_files() {
        let dst_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "viewer.log".to_string());
        let _ = fs::copy(&path, dir.join(dst_name));
    }

    // Screenshot — only when we have a sensible RGBA buffer.
    if snap.width > 0
        && snap.height > 0
        && snap.rgba.len() as u64 >= snap.width as u64 * snap.height as u64 * 4
    {
        let _ = save_png(&dir.join("desktop.png"), snap.width, snap.height, snap.rgba);
    }

    Ok(dir)
}

/// Output of `cmd /c ver` — "Microsoft Windows [Version 10.0.X.Y]" — for a
/// precise OS build that `%OS%` doesn't carry.
fn windows_version_line() -> String {
    std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn audit_path() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(local).join("sccm-rc").join("audit.jsonl"))
}

/// Up to two most-recently-modified `viewer.*log` files from the log dir, so
/// the bundle covers both today's session and the previous day's tail.
fn viewer_log_files() -> Vec<PathBuf> {
    let Some(local) = std::env::var_os("LOCALAPPDATA") else {
        return Vec::new();
    };
    let dir = PathBuf::from(local).join("sccm-rc");
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            // tracing-appender daily-rotation writes "viewer.log.YYYY-MM-DD",
            // plus "viewer.log" before any rotation has occurred.
            if !name.starts_with("viewer") || !name.contains("log") {
                return None;
            }
            let meta = e.metadata().ok()?;
            let mtime = meta.modified().ok()?;
            Some((mtime, e.path()))
        })
        .collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    entries.into_iter().take(2).map(|(_, p)| p).collect()
}

fn copy_tail(src: &Path, dst: &Path, n: usize) -> std::io::Result<()> {
    let bytes = fs::read(src)?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    fs::write(dst, lines[start..].join("\n"))?;
    Ok(())
}

fn save_png(dst: &Path, width: u32, height: u32, rgba: &[u8]) -> std::io::Result<()> {
    use image::{ImageBuffer, Rgba};
    let needed = width as usize * height as usize * 4;
    let buf: ImageBuffer<Rgba<u8>, &[u8]> = ImageBuffer::from_raw(width, height, &rgba[..needed])
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "rgba size mismatch")
        })?;
    buf.save(dst)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

/// Open Explorer at the report folder via ShellExecute (`cmd /c start`), so
/// the new window actually surfaces to the foreground instead of getting
/// stacked behind the viewer.
pub fn open_in_explorer(dir: &Path) {
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", ""])
        .arg(dir)
        .spawn();
}

/// Native MessageBox confirming the report was written and asking whether to
/// open the folder. Returns true iff the user clicked Yes. On non-Windows
/// targets always returns true (so the caller still opens the folder).
#[cfg(windows)]
pub fn confirm_and_open(dir: &Path, title: &str, body: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_ICONINFORMATION, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
    };
    let body_full = format!("{body}\n\n{}", dir.display());
    let title_w: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let body_w: Vec<u16> = body_full.encode_utf16().chain(std::iter::once(0)).collect();
    let ret = unsafe {
        MessageBoxW(
            Some(HWND(std::ptr::null_mut())),
            PCWSTR(body_w.as_ptr()),
            PCWSTR(title_w.as_ptr()),
            MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND,
        )
    };
    ret == IDYES
}
