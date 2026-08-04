//! SCCM Remote Control viewer — winit window rendering the remote desktop
//! over the pure-Rust SCCM transport, with mouse + keyboard forwarding.

// Drawing/render/protocol helpers take many positional params (x, y, w, h,
// color, scale, …); bundling them into structs would hurt readability here.
#![allow(clippy::too_many_arguments)]

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::Parser;
use sccm_rc_core::rdp::{
    self, FastPathInputEvent, FrameView, InputSender, KeyboardFlags, MousePdu, PointerFlags,
    PointerUpdate, SessionSink, SessionStats, UpdateRegion,
};
use sccm_rc_core::SccmSession;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use winit::application::ApplicationHandler;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{KeyCode, ModifiersState, PhysicalKey};
use winit::platform::scancode::PhysicalKeyExtScancode;
use winit::window::{Window, WindowId};

mod audit;
mod gpu;
mod host_prompt;
mod recent;
mod record;
mod report;
mod text;
mod toolbar;
mod type_text;
#[cfg(windows)]
mod winhook;
mod wol;
use toolbar::ToolbarAction;

// Localization: embeds locales/*.yml at compile time. `t!()` resolves against the
// locale chosen by `init_locale()` at startup (the Windows UI language, or --lang).
rust_i18n::i18n!("locales", fallback = "en");
use rust_i18n::t;

/// Pick and activate the UI locale: `--lang`/`SCCM_RC_LANG` override, else the
/// Windows UI language, else English. Only en/nl/de are supported.
fn init_locale(cli_lang: Option<&str>) {
    let raw = cli_lang
        .map(str::to_string)
        .or_else(|| std::env::var("SCCM_RC_LANG").ok())
        .or_else(sys_locale::get_locale);
    let lang = match raw
        .as_deref()
        .unwrap_or("en")
        .get(0..2)
        .unwrap_or("en")
        .to_ascii_lowercase()
        .as_str()
    {
        "nl" => "nl",
        "de" => "de",
        _ => "en",
    };
    rust_i18n::set_locale(lang);
    info!(locale = lang, source = ?raw, "UI language");
}

/// Full version string for `--version`: package version + embedded git hash
/// (set by build.rs). The window title shows just the package version.
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), ")");

#[derive(Parser)]
#[command(name = "sccm-rc-viewer", about = "SCCM Remote Control viewer", version = VERSION)]
struct Cli {
    /// Target hostname or IP (like CmRcViewer). If omitted, a prompt is shown.
    target: Option<String>,
    /// Requested desktop width
    #[arg(long, default_value_t = 1280)]
    width: u16,
    /// Requested desktop height
    #[arg(long, default_value_t = 720)]
    height: u16,
    /// MAC address for Wake-on-LAN (e.g. AA-BB-CC-DD-EE-FF). Seeds the WoL cache
    /// for this target and wakes it before connecting.
    #[arg(long)]
    mac: Option<String>,
    /// Send a Wake-on-LAN magic packet before connecting (uses the cached or
    /// --mac address for the target).
    #[arg(long)]
    wake: bool,
    /// Advertise a multi-monitor layout (repeatable). Geometry per monitor:
    /// WIDTHxHEIGHT+LEFT+TOP, e.g. `--monitor 1920x1080+0+0 --monitor 1280x1024+1920+0`.
    /// The first `--monitor` is the primary; omit for a single monitor.
    #[arg(long = "monitor")]
    monitors: Vec<String>,
    /// UI language: en, nl or de. Default: follow the Windows UI language.
    #[arg(long)]
    lang: Option<String>,
    /// Capture ALL of a multi-monitor target's screens as one combined desktop
    /// (SCCM "All Screens"), instead of only the primary. Once connected you can
    /// switch between individual screens from the toolbar (or Ctrl+Tab). Note:
    /// this persistently sets UseAllMonitors=1 in the target's registry, so it
    /// also affects later remote-control sessions to that machine.
    #[arg(long = "all-screens")]
    all_screens: bool,
    /// Demo/screenshot mode: don't connect to anything — paint a synthetic
    /// multi-monitor desktop so the full UI (toolbar + monitor switcher) renders
    /// for a privacy-safe screenshot. No real machine is contacted.
    #[arg(long)]
    demo: bool,
}

/// Load the embedded application icon for the live window (taskbar / title bar).
/// The .exe also carries this icon as a Win32 resource (build.rs) so Explorer and
/// the Properties tab show it, but winit needs the window icon set explicitly.
fn load_window_icon() -> Option<winit::window::Icon> {
    let img = image::load_from_memory(include_bytes!("../assets/icon.png"))
        .ok()?
        .to_rgba8();
    let (w, h) = (img.width(), img.height());
    winit::window::Icon::from_rgba(img.into_raw(), w, h).ok()
}

/// Draw the in-app About screen into a full-window overlay buffer (0x00RRGGBB),
/// in the same centred style as the connect/closed splash. Version comes from the
/// `VERSION` const (package version + git hash); the rest is localized.
fn draw_about(buf: &mut [u32], w: u32, h: u32, font: Option<&text::TextRenderer>) {
    for px in buf.iter_mut() {
        *px = 0x0020_2020;
    }
    let cy = (h / 2) as f32;
    // (y, text, colour, font-px, bitmap-scale fallback)
    let lines: [(f32, String, u32, f32, u32); 7] = [
        (cy - 96.0, "sccm-rc".to_string(), 0x00FF_FFFF, 40.0, 3),
        (cy - 50.0, format!("v{VERSION}"), 0x00C8_D2DC, 20.0, 2),
        (cy - 16.0, t!("about.tagline").to_string(), 0x00B0_C0D0, 19.0, 2),
        (cy + 16.0, "MIT OR Apache-2.0".to_string(), 0x0090_9CA8, 17.0, 2),
        (
            cy + 44.0,
            "github.com/conocidotech/sccm-rc-viewer".to_string(),
            0x0090_9CA8,
            17.0,
            2,
        ),
        (cy + 76.0, t!("about.security").to_string(), 0x0070_C070, 17.0, 2),
        (cy + 118.0, t!("about.dismiss").to_string(), 0x0070_7880, 15.0, 1),
    ];
    for (y, text, color, size_px, scale) in lines {
        if let Some(f) = font {
            f.draw_centered(buf, w, h, y, &text, color, size_px);
        } else {
            toolbar::draw_text_centered(buf, w, h, (y as u32).saturating_sub(4), &text, color, scale);
        }
    }
}


/// Native file picker (PowerShell OpenFileDialog) → the selected path.
#[cfg(windows)]
fn pick_file() -> Option<std::path::PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = "Add-Type -AssemblyName System.Windows.Forms; \
        $d=New-Object System.Windows.Forms.OpenFileDialog; \
        $d.Title='Bestand naar de remote sturen'; \
        if($d.ShowDialog() -eq 'OK'){Write-Output $d.FileName}";
    let out = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-STA", "-Command", script])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(s))
    }
}

#[cfg(not(windows))]
fn pick_file() -> Option<std::path::PathBuf> {
    None
}

/// Read the OS clipboard as text for pasting into the connect field. Runs the
/// `OpenClipboard` call on a throwaway thread with a hard timeout: the picker
/// lives on the winit UI thread, and `OpenClipboard` is famously prone to
/// blocking while another app (Chrome/Office/RDP) holds the clipboard-owner
/// lock, which would freeze the whole window. Mirrors the guard sccm-rc-core
/// uses for the cliprdr channel. Returns None on empty/unavailable/timeout.
#[cfg(windows)]
fn read_clipboard_text() -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = clipboard_win::get_clipboard_string()
            .ok()
            .filter(|s| !s.is_empty());
        let _ = tx.send(r);
    });
    rx.recv_timeout(std::time::Duration::from_millis(1500))
        .ok()
        .flatten()
}

#[cfg(not(windows))]
fn read_clipboard_text() -> Option<String> {
    None
}

/// Draw an animated "rotating dots" spinner centered at (cx, cy). A bright head
/// dot advances around the ring over time with a fading trail.
fn draw_spinner(
    buf: &mut [u32],
    win_w: u32,
    win_h: u32,
    cx: u32,
    cy: u32,
    elapsed: std::time::Duration,
) {
    const N: usize = 12;
    let r = 24.0f32;
    let head = ((elapsed.as_millis() / 70) as usize) % N;
    for i in 0..N {
        let ang = (i as f32) / (N as f32) * std::f32::consts::TAU - std::f32::consts::FRAC_PI_2;
        let dx = (ang.cos() * r) as i32;
        let dy = (ang.sin() * r) as i32;
        let dist = (head + N - i) % N; // 0 = head (brightest)
        let b = 235u32.saturating_sub(dist as u32 * 20).max(45);
        let color = (b << 16) | (b << 8) | b;
        for oy in -2i32..=2 {
            for ox in -2i32..=2 {
                if ox * ox + oy * oy > 5 {
                    continue; // round-ish dot
                }
                let px = cx as i32 + dx + ox;
                let py = cy as i32 + dy + oy;
                if px >= 0 && py >= 0 && (px as u32) < win_w && (py as u32) < win_h {
                    buf[(py as u32 * win_w + px as u32) as usize] = color;
                }
            }
        }
    }
}

/// Wake-ups delivered from the RDP task to the winit event loop.
#[derive(Debug, Clone)]
enum UserEvent {
    Frame,
    #[allow(dead_code)] // retained for an alternate teardown path
    Closed(String),
}

/// Shared framebuffer written by the RDP task, read by the renderer.
#[derive(Default)]
struct SharedFrame {
    rgba: Vec<u8>,
    width: u32,
    height: u32,
    /// Monotonic count of graphics updates, for FPS in the toolbar.
    frames: u64,
    /// Inbound bandwidth (bytes/sec) from the last stats tick.
    bytes_per_sec: u64,
    /// Connection-progress message shown until the first frame paints.
    status: String,
    /// Transport-security summary for the toolbar (e.g. "Kerberos · versleuteld").
    security: String,
    /// True when the link is encrypted AND the server is verified (Kerberos) — the
    /// toolbar shows a green lock; otherwise amber/red.
    secure: bool,
    /// True when the link is encrypted (regardless of verification). Drives the
    /// red (unencrypted) vs amber (encrypted-but-unverified) toolbar lock colour
    /// without string-matching the localized security label.
    encrypted: bool,
    /// GPU path: accumulated dirty region since the last paint (union of all
    /// updates). `None` = nothing changed. The CPU path ignores these.
    dirty: Option<UpdateRegion>,
    /// GPU path: a full-frame copy happened since the last paint (first frame,
    /// size change, or periodic resync) — the whole texture must be re-uploaded.
    full_resync: bool,
}

/// The remote cursor shape, drawn client-side at the local mouse position so it
/// tracks instantly (no server round-trip).
#[derive(Default)]
struct CursorState {
    /// True = draw `rgba`; false = no remote cursor (fall back to OS cursor).
    draw: bool,
    width: u16,
    height: u16,
    hotspot_x: u16,
    hotspot_y: u16,
    rgba: Vec<u8>, // top-down RGBA
}

/// Sink that copies decoded frames into the shared framebuffer and wakes
/// the UI thread. Copies only the dirty region (the incoming frame is the full
/// accumulated desktop) and throttles wake-ups so a burst of small order updates
/// doesn't trigger a redraw storm.
struct FrameSink {
    shared: Arc<Mutex<SharedFrame>>,
    cursor: Arc<Mutex<CursorState>>,
    proxy: EventLoopProxy<UserEvent>,
    /// Last time we did a full-frame resync copy. The incremental dirty-region
    /// copy is fast but can drift from the (always-correct) composite if a region
    /// is ever under-reported; a periodic full copy self-heals any such drift.
    last_full: std::time::Instant,
}

impl SessionSink for FrameSink {
    fn on_graphics_update(&mut self, image: &dyn FrameView, region: UpdateRegion) {
        let iw = image.width() as u32;
        let ih = image.height() as u32;
        let src = image.data();
        {
            let mut f = self.shared.lock().unwrap();
            // Full copy on first frame, size change, or as a periodic resync that
            // heals any drift from the incremental path (cheap at ~3/sec).
            let resync = self.last_full.elapsed() >= std::time::Duration::from_millis(300);
            if f.width != iw || f.height != ih || f.rgba.len() != src.len() || resync {
                // First frame or size change (reactivation): full copy.
                f.width = iw;
                f.height = ih;
                f.rgba.clear();
                f.rgba.extend_from_slice(src);
                self.last_full = std::time::Instant::now();
                f.full_resync = true; // GPU path: re-upload the whole texture.
            } else {
                // Copy only the dirty region's rows.
                let w = iw as usize;
                let left = region.left as usize;
                let right = (region.right as usize).min(w.saturating_sub(1));
                let bottom = (region.bottom as usize).min((ih as usize).saturating_sub(1));
                let top = (region.top as usize).min(bottom);
                for y in top..=bottom {
                    let a = (y * w + left) * 4;
                    let b = (y * w + right + 1) * 4;
                    if b <= f.rgba.len() && b <= src.len() {
                        f.rgba[a..b].copy_from_slice(&src[a..b]);
                    }
                }
                // GPU path: accumulate the dirty band (union) since the last paint.
                let acc = UpdateRegion {
                    left: left as u16,
                    top: top as u16,
                    right: right as u16,
                    bottom: bottom as u16,
                };
                f.dirty = Some(match f.dirty.take() {
                    Some(d) => UpdateRegion {
                        left: d.left.min(acc.left),
                        top: d.top.min(acc.top),
                        right: d.right.max(acc.right),
                        bottom: d.bottom.max(acc.bottom),
                    },
                    None => acc,
                });
            }
            f.frames = f.frames.wrapping_add(1);
            f.status.clear(); // first/any frame painted — hide the progress text
        }
        // winit coalesces multiple request_redraw() into a single RedrawRequested,
        // so a burst of region updates results in one redraw — no throttle needed.
        let _ = self.proxy.send_event(UserEvent::Frame);
    }
    fn on_pointer(&mut self, update: PointerUpdate) {
        {
            let mut c = self.cursor.lock().unwrap();
            match update {
                PointerUpdate::Bitmap(p) => {
                    c.draw = true;
                    c.width = p.width;
                    c.height = p.height;
                    c.hotspot_x = p.hotspot_x;
                    c.hotspot_y = p.hotspot_y;
                    c.rgba = p.rgba;
                }
                // No remote cursor → fall back to the local OS cursor.
                PointerUpdate::Hidden | PointerUpdate::SystemDefault => c.draw = false,
            }
        }
        let _ = self.proxy.send_event(UserEvent::Frame);
    }
    fn on_stats(&mut self, stats: SessionStats) {
        self.shared.lock().unwrap().bytes_per_sec = stats.bytes_per_sec;
        let _ = self.proxy.send_event(UserEvent::Frame);
    }
    fn on_status(&mut self, status: &str) {
        self.shared.lock().unwrap().status = status.to_string();
        let _ = self.proxy.send_event(UserEvent::Frame);
    }
    fn on_terminate(&mut self, reason: String) {
        // Don't close the window — the reconnect loop will resume the session.
        tracing::warn!(%reason, "server ended session; will reconnect");
    }
}

/// Install a panic hook that ALSO writes synchronously to
/// `%LOCALAPPDATA%\sccm-rc\viewer-panic.log` — the non-blocking tracing
/// appender's queue is lost if the process is killed (e.g. Watson closes a
/// hung viewer), so a panic message in tracing alone often never reaches
/// disk. This separate file uses plain blocking `File::write_all`, so the
/// line is durable before the panic propagates.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let dir = std::env::var_os("LOCALAPPDATA")
            .map(|p| std::path::PathBuf::from(p).join("sccm-rc"))
            .unwrap_or_else(std::env::temp_dir);
        let _ = std::fs::create_dir_all(&dir);
        let when = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();
        let bt = std::backtrace::Backtrace::force_capture();
        let line = format!("[{when}] PANIC thread={thread}\n  {info}\n{bt}\n\n");
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.join("viewer-panic.log"))
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(line.as_bytes())
            });
        tracing::error!(thread, %info, "viewer panic");
        default(info);
    }));
}

/// Wire up tracing to BOTH the console AND a daily-rotating file at
/// `%LOCALAPPDATA%\sccm-rc\viewer.log` (falls back to `%TEMP%` if LOCALAPPDATA
/// isn't set). The file is what makes a bug-report bundle actually
/// diagnostic — without it, the most useful WARN/ERROR lines (channel-routing
/// failures, reactivation desyncs, …) vanish into stdout that nothing
/// captures. Returns the appender's `WorkerGuard` — its `Drop` flushes the
/// queue, so `main` must keep it alive for the whole program.
fn init_tracing() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // wgpu/naga log Device::maintain etc. at INFO every frame — quiet them
        // by default so the GPU path doesn't flood the log. RUST_LOG overrides.
        EnvFilter::new("info,sccm_rc_core=info,wgpu_core=warn,wgpu_hal=warn,naga=warn")
    });
    let console = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

    let log_dir = std::env::var_os("LOCALAPPDATA")
        .map(|p| std::path::PathBuf::from(p).join("sccm-rc"))
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&log_dir);

    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("viewer")
        .filename_suffix("log")
        .max_log_files(7) // keep a week of history; bug-report grabs the current + previous
        .build(&log_dir);
    match appender {
        Ok(app) => {
            let (writer, guard) = tracing_appender::non_blocking(app);
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false);
            tracing_subscriber::registry()
                .with(filter)
                .with(console)
                .with(file_layer)
                .init();
            Some(guard)
        }
        Err(e) => {
            tracing_subscriber::registry().with(filter).with(console).init();
            tracing::warn!(error = %e, "could not open viewer.log; console-only logging");
            None
        }
    }
}

fn main() -> anyhow::Result<()> {
    // Console + rolling file appender. The file lives at
    // %LOCALAPPDATA%\sccm-rc\viewer.log and rotates daily (so a single
    // file holds today's session, and yesterday's stays available for
    // bug-report bundling). The non-blocking writer needs its WorkerGuard
    // alive for the lifetime of the program — hence the `_log_guard` binding
    // kept in `main`.
    let _log_guard = init_tracing();
    install_panic_hook();
    let cli = Cli::parse();
    init_locale(cli.lang.as_deref());

    // Enable the proven feature set by default so the GUI works out of the box
    // (graphics handshake, take-over, compression, clipboard). Each can still be
    // overridden from the environment for experiments/diagnostics.
    // SCCM_RC_COMPRESS is now ON by default: the MPPC fidelity bug (#79) is fixed
    // — each fast-path fragment is bulk-decompressed independently (shared 64K
    // history) per FreeRDP, instead of reassembling the raw compressed bytes.
    // Verified against a live capture (126 records, 705 orders, 0 desync) and a
    // live render. Compression cuts wire data ~3x = much smoother over the VPN.
    // Disable with SCCM_RC_COMPRESS=0 for diagnostics.
    for (k, v) in [
        ("SCCM_RC_ARB", "1"),
        ("SCCM_RC_WLC", "1"),
        ("SCCM_RC_MSTSC_CAPS", "1"),
        ("SCCM_RC_ORDERS", "1"),
        ("SCCM_RC_ARB_EVENT", "1"),
        ("SCCM_RC_TAKEOVER", "1"),
        ("SCCM_RC_CLIP", "1"),
        ("SCCM_RC_CURTAIN", "1"),
        ("SCCM_RC_COMPRESS", "1"),
    ] {
        if std::env::var(k).is_err() {
            std::env::set_var(k, v);
        }
    }

    // --all-screens opts into SCCM "All Screens" (the combined multi-monitor
    // desktop). sccm-rc-core reads SCCM_RC_ALLMON when building the connect
    // config; the flag just sets it so the feature stays a deliberate opt-in.
    // Set here (before the session thread spawns) so the env read is race-free.
    if cli.all_screens {
        std::env::set_var("SCCM_RC_ALLMON", "1");
    }

    // Target: CLI arg (like CmRcViewer) or, if absent, the in-window host-prompt
    // overlay collects one after the event loop starts. In --demo mode we never
    // connect, so default to a placeholder name instead of prompting.
    let cli_target = cli.target.clone();
    let target = match cli_target.as_deref() {
        Some(t) => t.to_string(),
        None if cli.demo => "DEMO-PC".to_string(),
        None => String::new(), // App starts with the overlay; no session yet.
    };

    // Remember this target for next time's dropdown (only when we actually have one).
    if !target.is_empty() {
        recent::add(&target);
    }
    // Wake-on-LAN: seed the MAC cache from --mac, then wake if asked (or --mac given).
    if let Some(m) = cli.mac.as_deref().and_then(wol::parse_mac) {
        wol::cache_mac(&target, m);
    }
    if cli.wake || cli.mac.is_some() {
        match wol::cached_mac(&target) {
            Some(mac) => match wol::send(mac) {
                Ok(()) => info!(mac = %wol::fmt_mac(mac), %target, "sent Wake-on-LAN magic packet"),
                Err(e) => warn!(error = %e, "Wake-on-LAN failed"),
            },
            None => warn!(%target, "no cached MAC — pass --mac AA-BB-.. or connect once first"),
        }
    }

    let shared = Arc::new(Mutex::new(SharedFrame::default()));
    let cursor = Arc::new(Mutex::new(CursorState::default()));

    let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
    event_loop.set_control_flow(ControlFlow::Wait);
    let proxy = event_loop.create_proxy();

    // Curtain (privacy) desired state — the toolbar sets it, the session thread
    // observes it and sends the enable/disable event.
    let curtain = Arc::new(AtomicBool::new(false));
    // A file the operator picked to push to the remote (Send File button).
    let file_offer: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::new(Mutex::new(None));
    // Parse any advertised monitor layout; the first --monitor is primary. When
    // a layout is given, the requested desktop size becomes its bounding box.
    let monitors: Vec<rdp::Monitor> = cli
        .monitors
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let m = rdp::parse_monitor(s, i == 0);
            if m.is_none() {
                warn!(spec = %s, "ignoring invalid --monitor geometry (want WIDTHxHEIGHT+LEFT+TOP)");
            }
            m
        })
        .collect();
    let (w, h) = match rdp::monitors_bounding_size(&monitors) {
        Some((bw, bh)) => {
            info!(
                count = monitors.len(),
                width = bw,
                height = bh,
                "advertising multi-monitor layout"
            );
            (bw, bh)
        }
        None => (cli.width, cli.height),
    };

    // Start the first session. `spawn_session` owns the per-host reconnect loop
    // and returns the `running` flag + input sender; the Disconnect button stops
    // it and spawns a fresh one for another host. In --demo mode we skip the
    // network entirely and paint a synthetic multi-monitor desktop instead.
    // In initial-prompt mode (no CLI target) we skip it too — the in-window
    // overlay collects the target and calls `start_session` once the user
    // confirms.
    let no_initial_session = cli.demo || cli_target.is_none();
    let (running, input_tx, done_rx) = if no_initial_session {
        if cli.demo {
            demo_frame(&shared);
        }
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<FastPathInputEvent>>(1);
        let (_done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        (Arc::new(AtomicBool::new(false)), tx, done_rx)
    } else {
        spawn_session(
            target.clone(),
            w,
            h,
            shared.clone(),
            cursor.clone(),
            proxy.clone(),
            curtain.clone(),
            file_offer.clone(),
            monitors.clone(),
        )
    };

    // Install the low-level keyboard hook ONCE — it's a process-global
    // resource, so we wire it to the initial input channel. Reconnects swap
    // in a new sender via `App.input_tx`, but the hook keeps using this
    // original handle: the channel only changes when run_active_session
    // restarts, and that path goes through App.input_tx for forwarding too.
    // (A future refactor could expose `winhook::update_tx(...)`; not needed
    // until the hook's stale channel actually causes a dropped Win-key.)
    #[cfg(windows)]
    winhook::install(input_tx.clone());

    let mut app = App {
        shared,
        input_tx: Some(input_tx),
        running,
        proxy,
        width: w,
        height: h,
        monitors,
        done_rx,
        window: None,
        surface: None,
        gpu: None,
        gpu_dump: std::env::var("SCCM_RC_GPU_DUMP").ok(),
        title: format!("SCCM RC {} — {target}", env!("CARGO_PKG_VERSION")),
        last_cursor: (0, 0),
        last_move: std::time::Instant::now(),
        cursor,
        mouse_win: (0.0, 0.0),
        cursor_inside: false,
        closed: None,
        modifiers: ModifiersState::empty(),
        host: target.clone(),
        fullscreen: false,
        view_only: false,
        view: MonitorView::All,
        switch_flash: 0,
        about_open: false,
        fps: 0,
        fps_base: 0,
        fps_t: std::time::Instant::now(),
        recorder: None,
        curtain: curtain.clone(),
        file_offer: file_offer.clone(),
        font: text::TextRenderer::load(),
        connect_start: std::time::Instant::now(),
        rprof_accum: std::time::Duration::ZERO,
        rprof_n: 0,
        rprof_t: std::time::Instant::now(),
        last_paint: std::time::Instant::now(),
        redraw_pending: false,
        last_heartbeat: std::time::Instant::now(),
        host_prompt: if cli_target.is_none() && !cli.demo {
            Some(host_prompt::HostPromptOverlay::new())
        } else {
            None
        },
        type_prompt: None,
    };
    event_loop.run_app(&mut app)?;
    // Window closed: stop the session and close the input channel, which unblocks
    // run_active_session so it sends the graceful disconnect (releasing the host
    // on the server). Then WAIT for the thread to confirm teardown is done — so we
    // don't exit mid-disconnect and leave the host stuck for the next connect
    // ("existing session"). Bounded, so a mid-connect thread can't block exit.
    app.running.store(false, Ordering::Relaxed);
    app.input_tx = None;
    let _ = app.done_rx.recv_timeout(std::time::Duration::from_secs(3));
    Ok(())
}

/// Paint a synthetic multi-monitor desktop into the shared frame for `--demo`
/// mode: two side-by-side 1920×1080 "screens" with distinct tinted gradients and a
/// divider, plus a connected/secure status. The frame is two monitors wide, so the
/// full UI renders — toolbar, security lock, and the monitor switcher — for a
/// privacy-safe screenshot without contacting any real machine.
fn demo_frame(shared: &Arc<Mutex<SharedFrame>>) {
    let (w, h) = (3840u32, 1080u32);
    let half = w / 2;
    let mut rgba = vec![0u8; (w as usize) * (h as usize) * 4];
    for y in 0..h {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            let on_right = x >= half;
            let gx = (if on_right { x - half } else { x }) as f32 / half as f32;
            let gy = y as f32 / h as f32;
            let (r, g, b) = if x >= half.saturating_sub(1) && x <= half {
                (16.0, 16.0, 18.0) // 2px divider between the two screens
            } else if on_right {
                (40.0 + gx * 90.0, 70.0 + gy * 70.0, 130.0 + gx * 90.0) // screen 2
            } else {
                (30.0 + gx * 70.0, 90.0 + gy * 90.0, 110.0 + gx * 60.0) // screen 1
            };
            rgba[i] = r as u8;
            rgba[i + 1] = g as u8;
            rgba[i + 2] = b as u8;
            rgba[i + 3] = 255;
        }
    }
    let mut f = shared.lock().unwrap();
    f.rgba = rgba;
    f.width = w;
    f.height = h;
    f.frames = 1;
    f.full_resync = true;
    f.status = t!("status.connected").to_string();
    f.secure = true;
    f.encrypted = true;
    f.security = format!("Kerberos \u{00b7} {}", t!("security.encrypted"));
}

/// Spawn the dedicated tokio-runtime thread that drives one host's session, with
/// the auto-reconnect loop. Returns the session's `running` flag (clear it to
/// stop) and the input sender (drop it to unblock the active session). Called for
/// the initial host and again whenever the operator picks another host.
fn spawn_session(
    target: String,
    w: u16,
    h: u16,
    shared: Arc<Mutex<SharedFrame>>,
    cursor: Arc<Mutex<CursorState>>,
    proxy: EventLoopProxy<UserEvent>,
    curtain: Arc<AtomicBool>,
    file_offer: Arc<Mutex<Option<std::path::PathBuf>>>,
    monitors: Vec<rdp::Monitor>,
) -> (Arc<AtomicBool>, InputSender, std::sync::mpsc::Receiver<()>) {
    let running = Arc::new(AtomicBool::new(true));
    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<Vec<FastPathInputEvent>>(256);
    // Signals when the thread has fully wound down — i.e. the graceful disconnect
    // (MCS Disconnect-Provider-Ultimatum) has been sent so the SCCM server
    // releases the host. The UI waits on this before exiting / reconnecting, so
    // the next connect doesn't hit "existing session".
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let running_thread = running.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            // Auto-reconnect: a transport desync, server reset, or a dropped link
            // (detected via TCP keepalive) ends the session; rather than freezing
            // the window, reconnect and resume — the status overlay shows progress.
            let mut input_rx = input_rx;
            while running_thread.load(Ordering::Relaxed) {
                match run_session(
                    &target,
                    w,
                    h,
                    shared.clone(),
                    cursor.clone(),
                    proxy.clone(),
                    &mut input_rx,
                    curtain.clone(),
                    file_offer.clone(),
                    &monitors,
                )
                .await
                {
                    Ok(()) => info!("session ended"),
                    Err(e) => warn!(error = %e, "session error"),
                }
                if !running_thread.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        // run_session() ran session.disconnect() before returning, so by here the
        // host has been released. Tell the UI it's safe to exit / reconnect.
        let _ = done_tx.send(());
    });
    (running, input_tx, done_rx)
}

async fn run_session(
    target: &str,
    w: u16,
    h: u16,
    shared: Arc<Mutex<SharedFrame>>,
    cursor: Arc<Mutex<CursorState>>,
    proxy: EventLoopProxy<UserEvent>,
    input_rx: &mut rdp::InputReceiver,
    curtain: Arc<AtomicBool>,
    file_offer: Arc<Mutex<Option<std::path::PathBuf>>>,
    monitors: &[rdp::Monitor],
) -> anyhow::Result<()> {
    shared.lock().unwrap().status = t!("status.connecting_to", target => target).to_string();
    let _ = proxy.send_event(UserEvent::Frame);
    // Bound the WHOLE bring-up (TCP connect + SSPI handshake + grant), not just
    // the TCP connect: a peer that completes the TCP handshake but then stalls
    // mid-greeting/SSPI would otherwise hang this session thread indefinitely and
    // leak it past a host-switch. 20 s is far above a healthy sub-second connect.
    let mut session = match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        SccmSession::connect(target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            // Show a clear, actionable status for the common "existing session"
            // case (usually our own session that wasn't released) instead of
            // silently re-showing "Verbinden..." on every retry.
            if matches!(e, sccm_rc_core::Error::ExistingSession) {
                shared.lock().unwrap().status =
                    t!("status.existing_session", target => target).to_string();
                let _ = proxy.send_event(UserEvent::Frame);
            }
            return Err(e.into());
        }
        Err(_) => anyhow::bail!("{}", t!("status.connect_timeout", target => target)),
    };
    shared.lock().unwrap().status = t!("status.setting_up_display").to_string();
    let _ = proxy.send_event(UserEvent::Frame);
    // Best-effort: remember this host's MAC (from the ARP table now that we've
    // contacted it) so a later Wake-on-LAN can boot it if it's powered off.
    // Fire-and-forget — do NOT await: the ARP lookup shells out (~0.6s measured)
    // and must not delay the RDP negotiation / first paint.
    {
        let t = target.to_string();
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || wol::lookup_and_cache(&t)).await;
        });
    }
    let grant = format!("{:?}", session.grant());
    info!(grant = %grant, "session established");
    audit::log_event(target, &grant, "connect", None);
    // Transport-security summary for the toolbar.
    {
        let (encrypted, verified, package) = session.security();
        info!(encrypted, verified, package = ?package, "transport security");
        let mut f = shared.lock().unwrap();
        f.secure = encrypted && verified;
        f.encrypted = encrypted;
        f.security = match (encrypted, package) {
            (true, Some(p)) => format!("{p} \u{00b7} {}", t!("security.encrypted")),
            (true, None) => t!("security.encrypted").to_string(),
            (false, _) => t!("security.unencrypted").to_string(),
        };
    }
    let started = std::time::Instant::now();
    // From here the server has granted an RC session, so we MUST disconnect on
    // every exit path (including a failed RDP negotiation) — otherwise the host is
    // left occupied and the next connect trips "existing session".
    let res = async {
        let (result, initial_buf, share_id) =
            rdp::connect_rdp(&mut session, w, h, monitors).await?;
        info!("RDP active — streaming");
        let mut sink = FrameSink {
            shared,
            cursor,
            proxy,
            last_full: std::time::Instant::now(),
        };
        rdp::run_active_session(
            &mut session,
            result,
            initial_buf,
            share_id,
            &mut sink,
            input_rx,
            curtain,
            file_offer,
        )
        .await
    }
    .await;
    // Graceful teardown so the server releases the shadow/host before we reconnect.
    session.disconnect().await;
    audit::log_event(
        target,
        &grant,
        "disconnect",
        Some(started.elapsed().as_secs()),
    );
    res?;
    Ok(())
}

/// Which monitor of a multi-monitor (All-Screens) target the viewer shows.
/// `All` = the whole combined framebuffer; `Screen(k)` = crop to monitor `k`
/// (0-based). This is a purely client-side crop of the already-received combined
/// desktop — switching is instant and needs no reconnect (RRCV-20), unlike the
/// original CmRcViewer which can only ever show the full stitched image.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MonitorView {
    All,
    Screen(u32),
}

struct App {
    shared: Arc<Mutex<SharedFrame>>,
    input_tx: Option<InputSender>,
    running: Arc<AtomicBool>,
    /// Ingredients to (re)spawn a session thread when the user switches host.
    proxy: EventLoopProxy<UserEvent>,
    width: u16,
    height: u16,
    /// Monitor layout to advertise on (re)connect; empty = single monitor.
    monitors: Vec<rdp::Monitor>,
    /// Signalled when the current session thread has finished its graceful
    /// disconnect; the UI waits on it before exiting / reconnecting.
    done_rx: std::sync::mpsc::Receiver<()>,
    window: Option<Arc<Window>>,
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    /// GPU renderer (wgpu), used by default. `None` = the softbuffer CPU fallback
    /// (forced with SCCM_RC_GPU=0, or when GPU init fails).
    gpu: Option<gpu::GpuRenderer>,
    /// Debug: SCCM_RC_GPU_DUMP=<path> dumps the first connected GPU frame to PNG
    /// (GDI can't screenshot a Vulkan surface). Cleared after one dump.
    gpu_dump: Option<String>,
    title: String,
    last_cursor: (u16, u16),
    last_move: std::time::Instant,
    cursor: Arc<Mutex<CursorState>>,
    mouse_win: (f64, f64),
    cursor_inside: bool,
    closed: Option<String>,
    modifiers: ModifiersState,
    host: String,
    fullscreen: bool,
    /// Local view-only lock: when true, suppress all input to the remote.
    view_only: bool,
    /// Which monitor of an All-Screens target is shown (client-side crop).
    view: MonitorView,
    /// Frames left to show the transient "Switching…" indicator in the toolbar
    /// state line after a monitor-view change (RRCV-20 feedback).
    switch_flash: u32,
    /// True while the in-app About overlay is shown (toggled by the toolbar
    /// button; dismissed by a click anywhere or Esc).
    about_open: bool,
    fps: u32,
    fps_base: u64,
    fps_t: std::time::Instant,
    recorder: Option<record::Recorder>,
    /// Curtain (privacy) desired state, shared with the session thread.
    curtain: Arc<AtomicBool>,
    /// File the operator picked to push to the remote, shared with the session.
    file_offer: Arc<Mutex<Option<std::path::PathBuf>>>,
    /// Anti-aliased UI font (None → 8x8 bitmap fallback).
    font: Option<text::TextRenderer>,
    /// When the current connection attempt started, for the spinner animation.
    connect_start: std::time::Instant,
    /// Viewer-side render profiling (SCCM_RC_PROFILE=1): accumulated paint time +
    /// count, logged ~1x/s. This is the blind spot the core profile misses.
    rprof_accum: std::time::Duration,
    rprof_n: u32,
    rprof_t: std::time::Instant,
    /// Paint-rate cap: a flood of update events would otherwise trigger a full
    /// rescale on each (~300/s measured). We repaint at most ~60 fps and defer
    /// extra requests, scheduling a trailing paint so the latest frame still lands.
    last_paint: std::time::Instant,
    redraw_pending: bool,
    /// Last time the winit (main) thread emitted a heartbeat log line. If the
    /// app hangs, this is the timestamp BEFORE the freeze — comparing it to
    /// the panic/Watson timestamp tells you whether the UI thread was the one
    /// stuck. Bumped from `about_to_wait` every ~5 s.
    last_heartbeat: std::time::Instant,
    /// In-window host-picker overlay. Some = the overlay is visible and
    /// consumes keyboard input; no session is running yet. Set at startup
    /// when no CLI target was given, and by Disconnect to pick another host.
    host_prompt: Option<host_prompt::HostPromptOverlay>,
    /// Send-keystrokes overlay. Some = the operator is typing text that
    /// will be replayed as scancodes on the remote (used to enter
    /// credentials into a UAC prompt where cliprdr is blocked).
    type_prompt: Option<type_text::TypeTextOverlay>,
}

impl App {
    fn send_input(&self, ev: FastPathInputEvent) {
        if self.view_only {
            return; // local view-only lock — don't control the remote
        }
        if let Some(tx) = &self.input_tx {
            let _ = tx.try_send(vec![ev]);
        }
    }

    /// Inject the Secure Attention Sequence (Ctrl+Alt+Del) to the remote as one
    /// batch: Ctrl↓ Alt↓ Del↓ Del↑ Alt↑ Ctrl↑. Set-1 scancodes: LCtrl=0x1D,
    /// LAlt=0x38, dedicated Delete=0x53 (extended). Sent together so the chord
    /// registers regardless of the local modifier keys the user is holding.
    fn send_ctrl_alt_del(&self) {
        if self.view_only {
            return;
        }
        let down = KeyboardFlags::empty();
        let up = KeyboardFlags::RELEASE;
        let ext = KeyboardFlags::EXTENDED;
        let seq = vec![
            FastPathInputEvent::KeyboardEvent(down, 0x1D), // Ctrl down
            FastPathInputEvent::KeyboardEvent(down, 0x38), // Alt down
            FastPathInputEvent::KeyboardEvent(ext, 0x53),  // Del down (extended)
            FastPathInputEvent::KeyboardEvent(ext | up, 0x53), // Del up
            FastPathInputEvent::KeyboardEvent(up, 0x38),   // Alt up
            FastPathInputEvent::KeyboardEvent(up, 0x1D),   // Ctrl up
        ];
        if let Some(tx) = &self.input_tx {
            let _ = tx.try_send(seq);
        }
        info!("sent Ctrl+Alt+Del (SAS) to remote");
    }

    /// Inject a Windows-key tap (press+release) to the remote — the windowed-mode
    /// equivalent of the Win key, which the local OS otherwise steals to open the
    /// local Start menu. Set-1 scancode for the Left-Win key is 0xE05B (extended).
    /// Triggered by the toolbar button or by Ctrl+Esc.
    fn send_win_key(&self) {
        if self.view_only {
            return;
        }
        let ext = KeyboardFlags::EXTENDED;
        let up = KeyboardFlags::RELEASE;
        let seq = vec![
            FastPathInputEvent::KeyboardEvent(ext, 0x5B),      // Win down (extended)
            FastPathInputEvent::KeyboardEvent(ext | up, 0x5B), // Win up
        ];
        if let Some(tx) = &self.input_tx {
            let _ = tx.try_send(seq);
        }
        info!("sent Windows-key tap to remote");
    }

    /// Signal the session thread to stop and disconnect gracefully: clear
    /// `running` and drop the input sender (unblocks run_active_session).
    fn begin_shutdown(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.input_tx = None;
    }

    /// Disconnect the current host and show the in-window host-prompt overlay
    /// so the operator can pick another target. If the operator cancels the
    /// overlay (Esc) the app exits — matches the old prompt-cancelled path.
    fn switch_host(&mut self, _event_loop: &ActiveEventLoop) {
        self.begin_shutdown();
        // Let the old session confirm teardown before we reconnect — otherwise
        // reconnecting (especially to the same host) trips "existing session".
        let _ = self.done_rx.recv_timeout(std::time::Duration::from_secs(3));
        self.input_tx = None;
        #[cfg(windows)]
        winhook::set_tx(None);
        {
            let mut f = self.shared.lock().unwrap();
            *f = SharedFrame::default();
        }
        self.host_prompt = Some(host_prompt::HostPromptOverlay::new());
        self.closed = None;
        if let Some(w) = &self.window {
            w.request_redraw();
        }
    }

    /// Spawn a fresh session for `new_target`. Extracted from the old
    /// `switch_host` so the initial-prompt path (main() with no CLI target)
    /// can also kick off a session from inside the event loop.
    fn start_session(&mut self, new_target: String) {
        recent::add(&new_target);
        self.host = new_target.clone();
        self.title = format!("SCCM RC {} — {new_target}", env!("CARGO_PKG_VERSION"));
        if let Some(w) = &self.window {
            w.set_title(&self.title);
        }
        {
            let mut f = self.shared.lock().unwrap();
            *f = SharedFrame::default();
            f.status = t!("status.connecting_to", target => new_target).to_string();
        }
        self.closed = None;
        self.connect_start = std::time::Instant::now();
        let (running, input_tx, done_rx) = spawn_session(
            new_target,
            self.width,
            self.height,
            self.shared.clone(),
            self.cursor.clone(),
            self.proxy.clone(),
            self.curtain.clone(),
            self.file_offer.clone(),
            self.monitors.clone(),
        );
        self.running = running;
        #[cfg(windows)]
        winhook::set_tx(Some(input_tx.clone()));
        self.input_tx = Some(input_tx);
        self.done_rx = done_rx;
        self.host_prompt = None;
        if let Some(w) = &self.window {
            w.request_redraw();
        }
    }

    /// Number of equal-width monitors in a combined All-Screens framebuffer,
    /// inferred from the aspect ratio assuming standard ~16:9 monitors side by
    /// side (e.g. 3840×1080 → 2). This is a heuristic for the common case; a
    /// future refinement could use real per-monitor rects from the protocol.
    /// Returns 1 (no split) for a single-monitor framebuffer.
    fn monitor_count(fb_w: u32, fb_h: u32) -> u32 {
        if fb_h == 0 {
            return 1;
        }
        let n = ((fb_w as f32 / fb_h as f32) / (16.0 / 9.0)).round() as i32;
        n.max(1) as u32
    }

    /// Source crop rect (in framebuffer pixels) for the current view: `All` =
    /// the whole framebuffer; `Screen(k)` = the k-th equal-width column. A stale
    /// `Screen(k)` (k ≥ count, e.g. after reconnecting to a single monitor)
    /// falls back to the full framebuffer.
    fn crop_rect(view: MonitorView, fb_w: u32, fb_h: u32) -> (u32, u32, u32, u32) {
        match view {
            MonitorView::Screen(k) => {
                let n = Self::monitor_count(fb_w, fb_h);
                if n > 1 && k < n {
                    let colw = fb_w / n;
                    (k * colw, 0, colw, fb_h)
                } else {
                    (0, 0, fb_w, fb_h)
                }
            }
            MonitorView::All => (0, 0, fb_w, fb_h),
        }
    }

    /// Toolbar label for the monitor switcher, or `None` when the target is
    /// single-monitor (button hidden). E.g. "Screen: All" / "Screen: 1".
    fn monitor_label(&self) -> Option<String> {
        let (fb_w, fb_h) = {
            let f = self.shared.lock().unwrap();
            (f.width, f.height)
        };
        Self::monitor_label_for(self.view, fb_w, fb_h)
    }

    /// As [`monitor_label`], but takes `view`/dims directly so callers that hold
    /// the frame lock or the surface `&mut` don't re-borrow `*self`.
    fn monitor_label_for(view: MonitorView, fb_w: u32, fb_h: u32) -> Option<String> {
        let n = Self::monitor_count(fb_w, fb_h);
        if n <= 1 {
            return None;
        }
        let which = match view {
            MonitorView::All => t!("monitor.all").to_string(),
            MonitorView::Screen(k) if k < n => (k + 1).to_string(),
            MonitorView::Screen(_) => t!("monitor.all").to_string(),
        };
        Some(t!("monitor.label", which => which).to_string())
    }

    /// Cycle the monitor view: All → Screen(0) → … → Screen(n-1) → All. No-op
    /// when the target is single-monitor.
    fn cycle_view(&mut self) {
        let (fb_w, fb_h) = {
            let f = self.shared.lock().unwrap();
            (f.width, f.height)
        };
        let n = Self::monitor_count(fb_w, fb_h);
        if n <= 1 {
            return;
        }
        self.view = match self.view {
            MonitorView::All => MonitorView::Screen(0),
            MonitorView::Screen(k) if k + 1 < n => MonitorView::Screen(k + 1),
            MonitorView::Screen(_) => MonitorView::All,
        };
        // Show a brief "Switching…" flash in the toolbar state line (~12 frames);
        // the new view's pixels are already in the framebuffer so the crop itself
        // is instant — this is purely visible feedback that the view changed.
        self.switch_flash = 12;
        info!(view = ?self.monitor_label(), "switched monitor view");
        if let Some(w) = &self.window {
            w.request_redraw();
        }
    }

    /// Map a window-space cursor position to desktop coordinates, honouring the
    /// active monitor crop (so a click while viewing Screen 2 lands on the
    /// right-hand monitor's true desktop coordinate).
    fn map_cursor(&self, x: f64, y: f64) -> (u16, u16) {
        let (fb_w, fb_h) = {
            let f = self.shared.lock().unwrap();
            (f.width.max(1), f.height.max(1))
        };
        let (cx, cy, cw, ch) = Self::crop_rect(self.view, fb_w, fb_h);
        let (cw, ch) = (cw.max(1), ch.max(1));
        let (win_w, win_h) = self
            .window
            .as_ref()
            .map(|w| {
                let s = w.inner_size();
                (s.width.max(1), s.height.max(1))
            })
            .unwrap_or((1, 1));
        // The desktop occupies the window below the toolbar strip and shows only
        // the crop sub-rect, so window space maps into [cx, cx+cw) × [cy, cy+ch).
        let bar = toolbar::TOOLBAR_H as f64;
        let usable_h = (win_h as f64 - bar).max(1.0);
        let yy = (y - bar).max(0.0);
        let dx = (cx as f64 + x * cw as f64 / win_w as f64).clamp(0.0, (fb_w - 1) as f64);
        let dy = (cy as f64 + yy * ch as f64 / usable_h).clamp(0.0, (fb_h - 1) as f64);
        (dx as u16, dy as u16)
    }

    /// Run a toolbar button action.
    fn run_toolbar_action(&mut self, action: ToolbarAction, event_loop: &ActiveEventLoop) {
        match action {
            ToolbarAction::CtrlAltDel => self.send_ctrl_alt_del(),
            ToolbarAction::SendWin => self.send_win_key(),
            ToolbarAction::SendKeys => {
                self.type_prompt = Some(type_text::TypeTextOverlay::new());
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            ToolbarAction::SendFile => {
                // Spawn the picker off the UI thread — powershell startup + the
                // OpenFileDialog take 5-10 s during which .output() would freeze
                // winit long enough for Windows Watson to declare the viewer
                // "Not Responding" and kill it (application-hang 1002). The
                // file_offer Arc<Mutex<…>> the session polls already lives on
                // its own thread, so dropping the picked path in from any
                // background thread is safe.
                let file_offer = self.file_offer.clone();
                std::thread::spawn(move || {
                    if let Some(path) = pick_file() {
                        info!(file = %path.display(), "queued file to push to remote (paste there)");
                        *file_offer.lock().unwrap() = Some(path);
                    }
                });
            }
            ToolbarAction::ToggleCurtain => {
                let new = !self.curtain.load(Ordering::Relaxed);
                self.curtain.store(new, Ordering::Relaxed);
                info!(curtain = new, "toggled curtain (privacy screen)");
            }
            ToolbarAction::ToggleViewOnly => {
                self.view_only = !self.view_only;
                info!(view_only = self.view_only, "toggled view-only");
            }
            ToolbarAction::MonitorCycle => self.cycle_view(),
            ToolbarAction::ToggleRecord => {
                if self.recorder.is_some() {
                    let frames = self.recorder.as_ref().map(|r| r.frame_count()).unwrap_or(0);
                    self.recorder = None; // drop stops the writer + flushes
                    info!(frames, "recording stopped");
                } else {
                    self.recorder = record::Recorder::start();
                    match &self.recorder {
                        Some(r) => info!(dir = %r.dir().display(), "recording started"),
                        None => warn!("could not start recording (output dir)"),
                    }
                }
            }
            ToolbarAction::ToggleFullscreen => {
                self.fullscreen = !self.fullscreen;
                if let Some(w) = &self.window {
                    let fs = self
                        .fullscreen
                        .then_some(winit::window::Fullscreen::Borderless(None));
                    w.set_fullscreen(fs);
                }
            }
            ToolbarAction::Disconnect => {
                // Disconnect from the current host and pick another one (keeps the
                // app open). Closing the window (X) still exits entirely.
                self.switch_host(event_loop);
            }
            ToolbarAction::BugReport => {
                // Snapshot the current framebuffer under the lock, then write
                // the report dir outside it so PNG-encoding can't stall paint.
                let (w, h, rgba) = {
                    let f = self.shared.lock().unwrap();
                    (f.width, f.height, f.rgba.clone())
                };
                match report::generate(report::Snapshot {
                    target: &self.host,
                    width: w,
                    height: h,
                    rgba: &rgba,
                }) {
                    Ok(dir) => {
                        info!(dir = %dir.display(), "bug report bundle written");
                        self.shared.lock().unwrap().status =
                            format!("{} {}", t!("status.report_saved"), dir.display());
                        // Modal confirmation explains what was saved and asks
                        // whether to open the folder. MessageBoxW BLOCKS the
                        // calling thread until dismissed; spawn it off the UI
                        // thread so paint + remote input keep flowing while
                        // the dialog is up.
                        #[cfg(windows)]
                        {
                            let title = t!("report.dialog_title").to_string();
                            let body = t!("report.dialog_body").to_string();
                            let dir_for_dialog = dir.clone();
                            std::thread::spawn(move || {
                                if report::confirm_and_open(
                                    &dir_for_dialog,
                                    &title,
                                    &body,
                                ) {
                                    report::open_in_explorer(&dir_for_dialog);
                                }
                            });
                        }
                        #[cfg(not(windows))]
                        report::open_in_explorer(&dir);
                    }
                    Err(e) => warn!(error = %e, "could not write bug report"),
                }
            }
            ToolbarAction::About => {
                self.about_open = !self.about_open;
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
        }
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attrs = Window::default_attributes()
            .with_title(&self.title)
            .with_window_icon(load_window_icon())
            .with_inner_size(winit::dpi::LogicalSize::new(1280.0, 720.0));
        let window = Arc::new(event_loop.create_window(attrs).expect("create window"));
        let context = softbuffer::Context::new(window.clone()).expect("softbuffer context");
        let surface =
            softbuffer::Surface::new(&context, window.clone()).expect("softbuffer surface");
        self.surface = Some(surface);
        // GPU renderer (wgpu) by default; the softbuffer CPU path stays as the
        // fallback. Force CPU with SCCM_RC_GPU=0 (jump-boxes / nested RDP / weak GPU);
        // on any GPU-init failure we fall back to CPU automatically.
        if std::env::var("SCCM_RC_GPU").as_deref() != Ok("0") {
            let sz = window.inner_size();
            match gpu::GpuRenderer::new(window.clone(), sz.width.max(1), sz.height.max(1)) {
                Ok(g) => {
                    info!(backend = g.backend(), "GPU renderer (wgpu) active");
                    g.set_error_handler();
                    self.gpu = Some(g);
                }
                Err(e) => warn!(error = %e, "GPU init failed — using softbuffer (CPU)"),
            }
        } else {
            info!("GPU disabled (SCCM_RC_GPU=0) — using softbuffer (CPU)");
        }
        self.window = Some(window);
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Frame => {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            UserEvent::Closed(reason) => {
                warn!(%reason, "session closed");
                self.closed = Some(reason);
                if let Some(w) = &self.window {
                    w.request_redraw(); // paint the closed banner once
                }
                event_loop.exit();
            }
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // UI-thread heartbeat: write a log line every ~5s. If a hang
        // happens, the last heartbeat timestamp is the moment the main
        // thread last responded — the window between it and the Watson
        // "Application Hang" event is exactly where the freeze started.
        if self.last_heartbeat.elapsed() >= std::time::Duration::from_secs(5) {
            self.last_heartbeat = std::time::Instant::now();
            tracing::info!(
                fps = self.fps,
                pending_paint = self.redraw_pending,
                "ui heartbeat"
            );
        }
        // Drain any pending type-text outcome (Enter → send, Esc → cancel).
        if let Some(outcome) = self
            .type_prompt
            .as_mut()
            .and_then(|p| p.take_outcome())
        {
            match outcome {
                type_text::TypeOutcome::Confirmed(events) => {
                    if let Some(tx) = &self.input_tx {
                        let _ = tx.try_send(events);
                    }
                }
                type_text::TypeOutcome::Cancelled => {}
            }
            self.type_prompt = None;
            if let Some(w) = &self.window {
                w.request_redraw();
            }
        }
        // Drain any pending host-prompt outcome (Enter → connect, Esc → exit).
        if let Some(outcome) = self
            .host_prompt
            .as_mut()
            .and_then(|p| p.take_outcome())
        {
            match outcome {
                host_prompt::PromptOutcome::Confirmed(target) => {
                    self.start_session(target);
                }
                host_prompt::PromptOutcome::Cancelled => {
                    self.closed = Some(t!("status.disconnected").to_string());
                    event_loop.exit();
                    return;
                }
            }
        }
        // While either overlay is up, tick the caret blink by scheduling a
        // repaint every ~500ms. Cheaper than the general connect-spinner
        // branch below (60ms) and gives the caret a proper on/off cadence.
        if self.host_prompt.is_some() || self.type_prompt.is_some() {
            if let Some(w) = &self.window {
                w.request_redraw();
            }
            event_loop.set_control_flow(ControlFlow::WaitUntil(
                std::time::Instant::now() + std::time::Duration::from_millis(500),
            ));
            return;
        }
        // While still connecting (nothing painted yet), keep the spinner animating
        // by redrawing ~16x/s. Once the desktop paints, go back to event-driven.
        let painted = {
            let f = self.shared.lock().unwrap();
            f.width != 0 && !f.rgba.is_empty()
        };
        if !painted && self.closed.is_none() {
            if let Some(w) = &self.window {
                w.request_redraw();
            }
            event_loop.set_control_flow(ControlFlow::WaitUntil(
                std::time::Instant::now() + std::time::Duration::from_millis(60),
            ));
        } else if self.redraw_pending {
            // A repaint was deferred by the 60 fps cap — paint it once the frame
            // interval has elapsed (the trailing paint), so the latest update lands.
            let next = self.last_paint + std::time::Duration::from_millis(16);
            if std::time::Instant::now() >= next {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
                event_loop.set_control_flow(ControlFlow::Wait);
            } else {
                event_loop.set_control_flow(ControlFlow::WaitUntil(next));
            }
        } else {
            event_loop.set_control_flow(ControlFlow::Wait);
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => {
                // Stop the session and WAIT for its graceful disconnect (the MCS
                // Disconnect-Provider-Ultimatum, signalled via done_rx) before
                // exiting — otherwise the SCCM host keeps the session and the next
                // connect trips ERROR_EXISTING_SESSION. Same teardown contract as
                // switch_host; bounded so a wedged session thread can't hang exit.
                self.begin_shutdown();
                let _ = self.done_rx.recv_timeout(std::time::Duration::from_secs(3));
                event_loop.exit();
            }
            WindowEvent::Resized(_) => {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                self.mouse_win = (position.x, position.y);
                // Type-text overlay: swallow move events so we don't sneak
                // pointer moves onto the remote behind the modal.
                if self.type_prompt.is_some() {
                    if let Some(w) = &self.window {
                        w.set_cursor_visible(true);
                        w.request_redraw();
                    }
                    return;
                }
                // Host-prompt overlay owns the pointer while it's up: hover
                // moves the recents-selection, and nothing goes to the remote.
                if let Some(prompt) = self.host_prompt.as_mut() {
                    let (w_w, w_h) = self
                        .window
                        .as_ref()
                        .map(|w| {
                            let s = w.inner_size();
                            (s.width, s.height)
                        })
                        .unwrap_or((1, 1));
                    prompt.on_mouse_move(position.x, position.y, w_w, w_h);
                    if let Some(w) = &self.window {
                        w.set_cursor_visible(true);
                        w.request_redraw();
                    }
                    return;
                }
                // Over the toolbar: keep the OS cursor for clicking buttons and
                // don't forward the move to the remote.
                if position.y < toolbar::TOOLBAR_H as f64 {
                    if let Some(w) = &self.window {
                        w.set_cursor_visible(true);
                        w.request_redraw();
                    }
                    return;
                }
                let (x, y) = self.map_cursor(position.x, position.y);
                self.last_cursor = (x, y);
                // Redraw so the client-side cursor follows the mouse instantly
                // (winit coalesces these into one redraw per frame).
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
                // Coalesce mouse moves to ~60/s. winit emits a CursorMoved per
                // movement (hundreds/s); sending each as a sealed input frame
                // saturates the session thread and starves graphics updates.
                if self.last_move.elapsed() >= std::time::Duration::from_millis(15) {
                    self.last_move = std::time::Instant::now();
                    self.send_input(FastPathInputEvent::MouseEvent(MousePdu {
                        flags: PointerFlags::MOVE,
                        number_of_wheel_rotation_units: 0,
                        x_position: x,
                        y_position: y,
                    }));
                }
            }
            WindowEvent::CursorEntered { .. } => {
                self.cursor_inside = true;
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            WindowEvent::CursorLeft { .. } => {
                self.cursor_inside = false;
                if let Some(w) = &self.window {
                    w.set_cursor_visible(true);
                    w.request_redraw();
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                // While the About overlay is open, a left click anywhere closes it
                // and is neither hit-tested against the toolbar nor forwarded.
                if self.about_open {
                    if state == ElementState::Pressed && button == MouseButton::Left {
                        self.about_open = false;
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                    return;
                }
                // Type-text overlay: left-click on Send/Cancel confirms/dismisses.
                if let Some(prompt) = self.type_prompt.as_mut() {
                    if state == ElementState::Pressed && button == MouseButton::Left {
                        let (w_w, w_h) = self
                            .window
                            .as_ref()
                            .map(|w| {
                                let s = w.inner_size();
                                (s.width, s.height)
                            })
                            .unwrap_or((1, 1));
                        prompt.on_click(self.mouse_win.0, self.mouse_win.1, w_w, w_h);
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                    return;
                }
                // Host-prompt overlay: left-click on a recent row confirms it.
                if let Some(prompt) = self.host_prompt.as_mut() {
                    if state == ElementState::Pressed && button == MouseButton::Left {
                        let (w_w, w_h) = self
                            .window
                            .as_ref()
                            .map(|w| {
                                let s = w.inner_size();
                                (s.width, s.height)
                            })
                            .unwrap_or((1, 1));
                        prompt.on_click(self.mouse_win.0, self.mouse_win.1, w_w, w_h);
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                    return;
                }
                // Clicks on the toolbar strip are handled locally, not forwarded.
                if self.mouse_win.1 < toolbar::TOOLBAR_H as f64 {
                    if state == ElementState::Pressed && button == MouseButton::Left {
                        let win_w = self
                            .window
                            .as_ref()
                            .map(|w| w.inner_size().width.max(1))
                            .unwrap_or(1);
                        let monitor = self.monitor_label();
                        if let Some(action) = toolbar::hit_test(
                            self.mouse_win.0,
                            self.mouse_win.1,
                            win_w,
                            self.font.as_ref(),
                            monitor.as_deref(),
                        ) {
                            self.run_toolbar_action(action, event_loop);
                        }
                    }
                    return;
                }
                let down = state == ElementState::Pressed;
                let mut flags = match button {
                    MouseButton::Left => PointerFlags::LEFT_BUTTON,
                    MouseButton::Right => PointerFlags::RIGHT_BUTTON,
                    _ => PointerFlags::empty(),
                };
                if down {
                    flags |= PointerFlags::DOWN;
                }
                let (x, y) = self.last_cursor;
                self.send_input(FastPathInputEvent::MouseEvent(MousePdu {
                    flags,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                }));
            }
            WindowEvent::MouseWheel { delta, .. } => {
                // MS-RDPBCGR: a wheel event needs PTRFLAGS_VERTICAL_WHEEL
                // (0x0200) or PTRFLAGS_HORIZONTAL_WHEEL (0x0400), otherwise
                // the server ignores the rotation units field. IronRDP adds
                // the WHEEL_NEGATIVE bit automatically based on the sign of
                // number_of_wheel_rotation_units — but it does NOT set the
                // wheel-direction flag, that's on us. Without this fix
                // scrolling in the remote is a silent no-op.
                //
                // The rotation-units field is 8-bit two's complement on the
                // wire (see ironrdp-pdu Encode: `as u8`), so anything
                // outside -127..127 wraps around and points the wheel the
                // wrong way. Clamp defensively — a single click on a
                // Windows mouse is 120, a fast trackpad flick can produce
                // multiples.
                let (units, horizontal) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => {
                        if x.abs() > y.abs() {
                            ((x * 120.0) as i32, true)
                        } else {
                            ((y * 120.0) as i32, false)
                        }
                    }
                    MouseScrollDelta::PixelDelta(p) => {
                        if p.x.abs() > p.y.abs() {
                            (p.x as i32, true)
                        } else {
                            (p.y as i32, false)
                        }
                    }
                };
                if units == 0 {
                    return;
                }
                let units = units.clamp(-127, 127) as i16;
                let flags = if horizontal {
                    PointerFlags::HORIZONTAL_WHEEL
                } else {
                    PointerFlags::VERTICAL_WHEEL
                };
                self.send_input(FastPathInputEvent::MouseEvent(MousePdu {
                    flags,
                    number_of_wheel_rotation_units: units,
                    x_position: 0,
                    y_position: 0,
                }));
            }
            WindowEvent::ModifiersChanged(m) => {
                self.modifiers = m.state();
            }
            WindowEvent::Focused(has_focus) => {
                // Gate the LL keyboard hook so we only steal Win-key / Ctrl+Esc
                // while the viewer is the foreground app. Losing focus releases
                // the OS shortcuts back to whichever window the user switched to.
                #[cfg(windows)]
                winhook::set_active(has_focus);
            }
            WindowEvent::KeyboardInput { event, .. } => {
                // While the About overlay is open, swallow all keyboard input; Esc
                // closes it. Nothing reaches the remote session.
                if self.about_open {
                    if event.state == ElementState::Pressed
                        && matches!(event.physical_key, PhysicalKey::Code(KeyCode::Escape))
                    {
                        self.about_open = false;
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                    return;
                }
                // Type-text overlay owns all keyboard input while up (checked
                // before host_prompt so the two never fight if both were
                // somehow open — type_prompt can only appear over a live
                // session, host_prompt only when disconnected).
                if let Some(prompt) = self.type_prompt.as_mut() {
                    if event.state == ElementState::Pressed {
                        // Ctrl+V / Ctrl+Insert → paste OS clipboard. Critical
                        // for the intended flow: copy password from password
                        // manager → paste here → Enter → scancodes to UAC
                        // (which Windows blocks direct cliprdr paste into).
                        // Without this, the Type Text field is unusable for
                        // the very case it was designed for.
                        if self.modifiers.control_key()
                            && matches!(
                                event.physical_key,
                                PhysicalKey::Code(KeyCode::KeyV)
                                    | PhysicalKey::Code(KeyCode::Insert)
                            )
                        {
                            if let Some(clip) = read_clipboard_text() {
                                prompt.on_text(&clip);
                            }
                            if let Some(w) = &self.window {
                                w.request_redraw();
                            }
                            return;
                        }
                        // Ctrl+A / Ctrl+Delete → clear the field (see host_prompt).
                        if self.modifiers.control_key()
                            && matches!(
                                event.physical_key,
                                PhysicalKey::Code(KeyCode::KeyA)
                                    | PhysicalKey::Code(KeyCode::Delete)
                            )
                        {
                            prompt.on_clear();
                            if let Some(w) = &self.window {
                                w.request_redraw();
                            }
                            return;
                        }
                        match event.physical_key {
                            PhysicalKey::Code(KeyCode::Escape) => prompt.on_esc(),
                            PhysicalKey::Code(KeyCode::Enter)
                            | PhysicalKey::Code(KeyCode::NumpadEnter) => prompt.on_enter(),
                            PhysicalKey::Code(KeyCode::Backspace)
                            | PhysicalKey::Code(KeyCode::Delete) => prompt.on_backspace(),
                            _ => {
                                if let Some(text) = event.text.as_deref() {
                                    if !text.is_empty() {
                                        prompt.on_text(text);
                                    }
                                }
                            }
                        }
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                    return;
                }
                // Host-prompt overlay owns all keyboard input while it's up.
                if let Some(prompt) = self.host_prompt.as_mut() {
                    if event.state == ElementState::Pressed {
                        // Ctrl+V / Ctrl+Insert → paste the OS clipboard into the
                        // connect field. The spartan v1 keyboard model only
                        // appended printable chars, so a paste otherwise leaked
                        // through as a literal "v". on_text() strips control
                        // chars, so any CR/LF from a copied line is dropped.
                        if self.modifiers.control_key()
                            && matches!(
                                event.physical_key,
                                PhysicalKey::Code(KeyCode::KeyV)
                                    | PhysicalKey::Code(KeyCode::Insert)
                            )
                        {
                            if let Some(clip) = read_clipboard_text() {
                                prompt.on_text(&clip);
                            }
                            if let Some(w) = &self.window {
                                w.request_redraw();
                            }
                            return;
                        }
                        // Ctrl+A / Ctrl+Delete → clear the field. We don't
                        // render a visual selection, so "select all + type"
                        // and "clear" look the same to the operator.
                        if self.modifiers.control_key()
                            && matches!(
                                event.physical_key,
                                PhysicalKey::Code(KeyCode::KeyA)
                                    | PhysicalKey::Code(KeyCode::Delete)
                            )
                        {
                            prompt.on_clear();
                            if let Some(w) = &self.window {
                                w.request_redraw();
                            }
                            return;
                        }
                        let handled = match event.physical_key {
                            PhysicalKey::Code(KeyCode::Escape) => {
                                prompt.on_esc();
                                true
                            }
                            PhysicalKey::Code(KeyCode::Enter)
                            | PhysicalKey::Code(KeyCode::NumpadEnter) => {
                                prompt.on_enter();
                                true
                            }
                            // Delete without Ctrl behaves like Backspace here
                            // (single-line, no cursor position) — matches the
                            // "delete forward = delete at end" intuition on a
                            // caret-at-end text field.
                            PhysicalKey::Code(KeyCode::Backspace)
                            | PhysicalKey::Code(KeyCode::Delete) => {
                                prompt.on_backspace();
                                true
                            }
                            PhysicalKey::Code(KeyCode::ArrowUp) => {
                                prompt.on_arrow_up();
                                true
                            }
                            PhysicalKey::Code(KeyCode::ArrowDown) => {
                                prompt.on_arrow_down();
                                true
                            }
                            _ => {
                                // Printable text: winit puts the composed
                                // char(s) in `event.text` for us.
                                if let Some(text) = event.text.as_deref() {
                                    if !text.is_empty() {
                                        prompt.on_text(text);
                                    }
                                }
                                false
                            }
                        };
                        let _ = handled;
                        if let Some(w) = &self.window {
                            w.request_redraw();
                        }
                    }
                    return;
                }
                // Ctrl+Alt+End → send Ctrl+Alt+Del (SAS) to the remote, like
                // CmRcViewer (Ctrl+Alt+Del itself is swallowed by the local OS).
                if event.state == ElementState::Pressed
                    && self.modifiers.control_key()
                    && self.modifiers.alt_key()
                    && matches!(event.physical_key, PhysicalKey::Code(KeyCode::End))
                {
                    self.send_ctrl_alt_del();
                    return;
                }
                // Ctrl+Esc → send the Windows key to the remote. CmRcViewer only
                // passes Win-key through in fullscreen; the LL OS hook in
                // windowed mode is heavyweight, so we expose the canonical PS/2
                // alternative chord instead. Swallow both press AND release so
                // a stray Esc-up doesn't leak to the remote.
                if self.modifiers.control_key()
                    && matches!(event.physical_key, PhysicalKey::Code(KeyCode::Escape))
                {
                    if event.state == ElementState::Pressed {
                        self.send_win_key();
                    }
                    return;
                }
                // Ctrl+Tab → cycle the monitor view (All / Screen N) of a
                // multi-monitor target. Handled locally, never forwarded.
                if self.modifiers.control_key()
                    && matches!(event.physical_key, PhysicalKey::Code(KeyCode::Tab))
                {
                    if event.state == ElementState::Pressed {
                        self.cycle_view();
                    }
                    return;
                }
                // winit gives us the OS hardware scancode, which on Windows is
                // the PS/2 set-1 scancode RDP expects (0xE000 prefix = extended).
                if let Some(sc) = event.physical_key.to_scancode() {
                    let mut flags = KeyboardFlags::empty();
                    if event.state == ElementState::Released {
                        flags |= KeyboardFlags::RELEASE;
                    }
                    if sc & 0xE000 == 0xE000 || sc > 0xFF {
                        flags |= KeyboardFlags::EXTENDED;
                    }
                    let code = (sc & 0xFF) as u8;
                    self.send_input(FastPathInputEvent::KeyboardEvent(flags, code));
                }
            }
            WindowEvent::RedrawRequested => {
                // Cap repaints to ~60 fps. Excess requests just set redraw_pending;
                // about_to_wait schedules a trailing paint so the latest frame lands.
                const FRAME: std::time::Duration = std::time::Duration::from_millis(16);
                if self.last_paint.elapsed() >= FRAME {
                    self.redraw_pending = false;
                    self.last_paint = std::time::Instant::now();
                    self.render();
                } else {
                    self.redraw_pending = true;
                }
            }
            _ => {}
        }
    }
}

impl App {
    /// GPU render path (wgpu). Draws the desktop framebuffer as a quad below the
    /// toolbar, and the toolbar (or the connect/closed splash) as an overlay quad
    /// rasterised by the existing CPU code into a small buffer. Used by default;
    /// SCCM_RC_GPU=0 forces the softbuffer CPU fallback.
    fn render_gpu(&mut self) {
        let Some(window) = self.window.clone() else {
            return;
        };
        let size = window.inner_size();
        let (win_w, win_h) = (size.width.max(1), size.height.max(1));
        let bar_h = toolbar::TOOLBAR_H.min(win_h);
        let mut frame = self.shared.lock().unwrap();
        let connected = frame.width != 0 && frame.height != 0 && !frame.rgba.is_empty();
        let (fb_w, fb_h) = (frame.width, frame.height);
        // Active monitor crop (RRCV-20): source UV sub-rect + toolbar label. The
        // `_for` variants take the dims we already hold so they don't re-lock.
        let monitor_label = Self::monitor_label_for(self.view, fb_w, fb_h);
        let desktop_uv = if connected && fb_w > 0 && fb_h > 0 {
            let (cx, cy, cw, ch) = Self::crop_rect(self.view, fb_w, fb_h);
            [
                cx as f32 / fb_w as f32,
                cy as f32 / fb_h as f32,
                (cx + cw) as f32 / fb_w as f32,
                (cy + ch) as f32 / fb_h as f32,
            ]
        } else {
            [0.0, 0.0, 1.0, 1.0]
        };
        // Dirty-region upload: full on resync/size-change, else just the changed
        // row band, else nothing (the GPU texture persists across frames).
        let desktop_upload = if frame.full_resync {
            frame.full_resync = false;
            frame.dirty = None;
            gpu::DesktopUpload::Full
        } else if let Some(d) = frame.dirty.take() {
            gpu::DesktopUpload::Rows(d.top as u32, d.bottom as u32)
        } else {
            gpu::DesktopUpload::Skip
        };
        let bytes_per_sec = frame.bytes_per_sec;
        let status_msg = frame.status.clone();
        let security = frame.security.clone();
        let secure = frame.secure;
        let encrypted = frame.encrypted;
        if let Some(rec) = self.recorder.as_mut() {
            rec.maybe_capture(frame.width, frame.height, &frame.rgba);
        }

        // Rasterise the overlay into a CPU u32 buffer with the existing drawing
        // code: the toolbar strip when connected, else the full-window splash.
        let show_full_overlay = self.about_open
            || self.host_prompt.is_some()
            || self.type_prompt.is_some()
            || !connected;
        let (ov_w, ov_h, dest) = if show_full_overlay {
            (win_w, win_h, gpu::OverlayDest::Full)
        } else {
            (win_w, bar_h, gpu::OverlayDest::TopStrip(bar_h))
        };
        let mut ov = vec![0u32; (ov_w * ov_h) as usize];
        if let Some(prompt) = self.host_prompt.as_ref() {
            host_prompt::draw(&mut ov, ov_w, ov_h, self.font.as_ref(), prompt);
        } else if let Some(prompt) = self.type_prompt.as_ref() {
            type_text::draw(&mut ov, ov_w, ov_h, self.font.as_ref(), prompt);
        } else if self.about_open {
            draw_about(&mut ov, ov_w, ov_h, self.font.as_ref());
        } else if connected {
            let mode = if self.view_only {
                t!("mode.view_only")
            } else {
                t!("mode.control")
            }
            .to_string();
            let state = if self.switch_flash > 0 {
                self.switch_flash -= 1;
                // Keep animating the flash down even if no server frames arrive.
                window.request_redraw();
                t!("monitor.switching").to_string()
            } else {
                t!("status.connected").to_string()
            };
            let status = toolbar::Status {
                host: &self.host,
                mode: &mode,
                state: &state,
                connected,
                fps: self.fps,
                bytes_per_sec,
                recording: self.recorder.is_some(),
                curtain: self.curtain.load(Ordering::Relaxed),
                security: &security,
                secure,
                view_only: self.view_only,
                encrypted,
                monitor: monitor_label.as_deref(),
            };
            toolbar::draw(&mut ov, ov_w, ov_h, &status, self.font.as_ref());
        } else {
            let fill = if self.closed.is_some() {
                0x0040_0000
            } else {
                0x0020_2020
            };
            for px in ov.iter_mut() {
                *px = fill;
            }
            let msg = if let Some(reason) = &self.closed {
                t!("status.disconnected_reason", reason => reason).to_string()
            } else if status_msg.is_empty() {
                t!("status.connecting").to_string()
            } else {
                status_msg
            };
            let (cx, cy) = (ov_w / 2, ov_h / 2);
            if self.closed.is_none() {
                draw_spinner(
                    &mut ov,
                    ov_w,
                    ov_h,
                    cx,
                    cy.saturating_sub(72),
                    self.connect_start.elapsed(),
                );
            }
            if let Some(f) = self.font.as_ref() {
                f.draw_centered(
                    &mut ov,
                    ov_w,
                    ov_h,
                    cy as f32 + 4.0,
                    &self.host,
                    0x00FF_FFFF,
                    34.0,
                );
                f.draw_centered(
                    &mut ov,
                    ov_w,
                    ov_h,
                    cy as f32 + 38.0,
                    &msg,
                    0x00B0_C0D0,
                    19.0,
                );
            } else {
                toolbar::draw_text_centered(
                    &mut ov,
                    ov_w,
                    ov_h,
                    cy.saturating_sub(28),
                    &self.host,
                    0x00FF_FFFF,
                    3,
                );
                toolbar::draw_text_centered(&mut ov, ov_w, ov_h, cy + 8, &msg, 0x00B0_C0D0, 2);
            }
        }
        // Pack 0x00RRGGBB -> RGBA bytes (opaque).
        let mut ov_rgba = vec![0u8; (ov_w * ov_h * 4) as usize];
        for (i, &px) in ov.iter().enumerate() {
            let o = i * 4;
            ov_rgba[o] = ((px >> 16) & 0xff) as u8;
            ov_rgba[o + 1] = ((px >> 8) & 0xff) as u8;
            ov_rgba[o + 2] = (px & 0xff) as u8;
            ov_rgba[o + 3] = 0xff;
        }

        // Client cursor as a GPU quad at the live mouse position — the clean #87
        // fix (no CPU cursor-box-fill). Same conditions as the softbuffer path.
        let cursor = {
            let cur = self.cursor.lock().unwrap();
            let show = connected
                && cur.draw
                && !cur.rgba.is_empty()
                && self.cursor_inside
                && self.mouse_win.1 >= toolbar::TOOLBAR_H as f64;
            window.set_cursor_visible(!show);
            if show {
                let dx = self.mouse_win.0 as i32 - cur.hotspot_x as i32;
                let dy = self.mouse_win.1 as i32 - cur.hotspot_y as i32;
                Some((
                    cur.width as u32,
                    cur.height as u32,
                    cur.rgba.clone(),
                    dx,
                    dy,
                ))
            } else {
                None
            }
        };

        let desktop = if connected {
            Some((fb_w, fb_h, frame.rgba.as_slice(), desktop_upload))
        } else {
            None
        };
        let cursor_ref = cursor
            .as_ref()
            .map(|(w, h, r, x, y)| (*w, *h, r.as_slice(), *x, *y));
        let dump = if connected {
            self.gpu_dump.take()
        } else {
            None
        };
        let gpu = self.gpu.as_mut().unwrap();
        gpu.render(
            win_w,
            win_h,
            bar_h,
            desktop,
            Some((ov_w, ov_h, &ov_rgba, dest)),
            cursor_ref,
            desktop_uv,
        );
        if let Some(p) = dump {
            match gpu.dump_png(&p) {
                Ok(()) => info!(path = %p, "GPU frame dumped"),
                Err(e) => warn!(error = %e, "GPU dump failed"),
            }
        }
    }

    fn render(&mut self) {
        if self.gpu.is_some() {
            self.render_gpu();
            return;
        }
        // Capture the monitor view before borrowing the surface `&mut self.surface`
        // (which then precludes any `&self` method call for the rest of render).
        let view = self.view;
        let (Some(window), Some(surface)) = (self.window.as_ref(), self.surface.as_mut()) else {
            return;
        };
        let size = window.inner_size();
        let (win_w, win_h) = (size.width.max(1), size.height.max(1));
        let (Some(nw), Some(nh)) = (NonZeroU32::new(win_w), NonZeroU32::new(win_h)) else {
            return;
        };
        if surface.resize(nw, nh).is_err() {
            return;
        }
        let Ok(mut buffer) = surface.buffer_mut() else {
            return;
        };
        let rstart = std::time::Instant::now();

        // Host-prompt overlay owns the window while the user picks a target
        // — no desktop, no toolbar. Draw and present directly.
        if let Some(prompt) = self.host_prompt.as_ref() {
            host_prompt::draw(&mut buffer[..], win_w, win_h, self.font.as_ref(), prompt);
            let _ = buffer.present();
            return;
        }
        // Type-text overlay: same treatment — drawn on top, no session below.
        if let Some(prompt) = self.type_prompt.as_ref() {
            type_text::draw(&mut buffer[..], win_w, win_h, self.font.as_ref(), prompt);
            let _ = buffer.present();
            return;
        }
        // About overlay takes over the whole window (no desktop/toolbar), matching
        // the GPU path. Drawn and presented directly, then we're done for this paint.
        if self.about_open {
            draw_about(&mut buffer[..], win_w, win_h, self.font.as_ref());
            let _ = buffer.present();
            return;
        }

        // The remote desktop renders BELOW the toolbar strip (reserved at top).
        let bar_h = toolbar::TOOLBAR_H.min(win_h);
        let desk_h = win_h.saturating_sub(bar_h).max(1);
        let frame = self.shared.lock().unwrap();
        let frame_count = frame.frames;
        let bytes_per_sec = frame.bytes_per_sec;
        let connected = frame.width != 0 && frame.height != 0 && !frame.rgba.is_empty();
        let monitor_label = Self::monitor_label_for(view, frame.width, frame.height);
        let status = frame.status.clone();
        let security = frame.security.clone();
        let secure = frame.secure;
        let encrypted = frame.encrypted;
        // Session recording: queue the current desktop (throttled internally).
        if let Some(rec) = self.recorder.as_mut() {
            rec.maybe_capture(frame.width, frame.height, &frame.rgba);
        }
        if !connected {
            let fill = if self.closed.is_some() {
                0x0040_0000
            } else {
                0x0020_2020
            };
            for px in buffer.iter_mut() {
                *px = fill;
            }
            // Connection-progress overlay: host title + current phase + a spinner.
            let msg = if let Some(reason) = &self.closed {
                t!("status.disconnected_reason", reason => reason).to_string()
            } else if status.is_empty() {
                t!("status.connecting").to_string()
            } else {
                status
            };
            let cx = win_w / 2;
            let cy = win_h / 2;
            // Animated spinner above the text (only while still connecting).
            if self.closed.is_none() {
                draw_spinner(
                    &mut buffer[..],
                    win_w,
                    win_h,
                    cx,
                    cy.saturating_sub(72),
                    self.connect_start.elapsed(),
                );
            }
            if let Some(f) = self.font.as_ref() {
                f.draw_centered(
                    &mut buffer[..],
                    win_w,
                    win_h,
                    cy as f32 + 4.0,
                    &self.host,
                    0x00FF_FFFF,
                    34.0,
                );
                f.draw_centered(
                    &mut buffer[..],
                    win_w,
                    win_h,
                    cy as f32 + 38.0,
                    &msg,
                    0x00B0_C0D0,
                    19.0,
                );
            } else {
                toolbar::draw_text_centered(
                    &mut buffer[..],
                    win_w,
                    win_h,
                    cy.saturating_sub(28),
                    &self.host,
                    0x00FF_FFFF,
                    3,
                );
                toolbar::draw_text_centered(
                    &mut buffer[..],
                    win_w,
                    win_h,
                    cy + 8,
                    &msg,
                    0x00B0_C0D0,
                    2,
                );
            }
        } else {
            let (fb_w, fb_h) = (frame.width, frame.height);
            let src = &frame.rgba;
            let fbw = fb_w as usize;
            // Active monitor crop (RRCV-20): blit only this source sub-rect, scaled
            // to fill the desktop area. `All` = the whole framebuffer.
            let (cx, cy, cw, ch) = Self::crop_rect(view, fb_w, fb_h);
            let (cx, cy) = (cx as usize, cy as usize);
            if win_w == cw && desk_h == ch {
                // 1:1 — direct copy, sharpest (no interpolation).
                for wy in bar_h..win_h {
                    let row = (cy + (wy - bar_h) as usize) * fbw + cx;
                    let out_row = (wy * win_w) as usize;
                    for wx in 0..win_w as usize {
                        let si = (row + wx) * 4;
                        buffer[out_row + wx] = if si + 2 < src.len() {
                            ((src[si] as u32) << 16)
                                | ((src[si + 1] as u32) << 8)
                                | (src[si + 2] as u32)
                        } else {
                            0
                        };
                    }
                }
            } else {
                // Bilinear scale of the cropped sub-rect. (A dirty-region variant was
                // tried but needs a full per-frame copy to erase the client cursor,
                // costing ~the same; the 60 fps paint cap is the real client win.)
                let map = |dst: u32, dst_n: u32, src_n: u32| -> (usize, usize, u32) {
                    // saturating_sub guards a 0-dim source (the `connected` check
                    // upstream already ensures src_n > 0, but the invariant is
                    // non-local — don't let it underflow-panic here).
                    let max_i = (src_n as usize).saturating_sub(1);
                    let s = (((dst as f64 + 0.5) * src_n as f64 / dst_n as f64) - 0.5).max(0.0);
                    let i0 = (s as usize).min(max_i);
                    let i1 = (i0 + 1).min(max_i);
                    (i0, i1, ((s - i0 as f64) * 256.0) as u32)
                };
                // Column/row sample indices are taken within the crop, then shifted
                // by the crop origin (cx, cy) into the full framebuffer.
                let cols: Vec<(usize, usize, u32)> = (0..win_w)
                    .map(|wx| {
                        let (i0, i1, f) = map(wx, win_w, cw);
                        (cx + i0, cx + i1, f)
                    })
                    .collect();
                #[inline(always)]
                fn lerp(a: u32, b: u32, f: u32) -> u32 {
                    (a * (256 - f) + b * f) >> 8
                }
                for wy in bar_h..win_h {
                    let (y0, y1, fy) = map(wy - bar_h, desk_h, ch);
                    let r0 = (cy + y0) * fbw;
                    let r1 = (cy + y1) * fbw;
                    let out_row = (wy * win_w) as usize;
                    for (wx, &(x0, x1, fx)) in cols.iter().enumerate() {
                        let p00 = (r0 + x0) * 4;
                        let p01 = (r0 + x1) * 4;
                        let p10 = (r1 + x0) * 4;
                        let p11 = (r1 + x1) * 4;
                        if p11 + 2 >= src.len() {
                            continue;
                        }
                        let mut out = 0u32;
                        for ch in 0..3 {
                            let top = lerp(src[p00 + ch] as u32, src[p01 + ch] as u32, fx);
                            let bot = lerp(src[p10 + ch] as u32, src[p11 + ch] as u32, fx);
                            out |= lerp(top, bot, fy) << (16 - ch * 8);
                        }
                        buffer[out_row + wx] = out;
                    }
                }
            }
        }
        drop(frame);

        // FPS: recompute once per second from the cumulative frame counter.
        let now = std::time::Instant::now();
        let el = now.duration_since(self.fps_t);
        if el >= std::time::Duration::from_secs(1) {
            self.fps = ((frame_count.wrapping_sub(self.fps_base)) as f64 / el.as_secs_f64()) as u32;
            self.fps_base = frame_count;
            self.fps_t = now;
        }

        // Client-side cursor: draw the remote cursor shape at the LOCAL mouse
        // position so it tracks instantly (no server round-trip), and hide the OS
        // cursor while we do. Falls back to the OS cursor when there's no shape.
        let cur = self.cursor.lock().unwrap();
        let draw_remote = cur.draw
            && !cur.rgba.is_empty()
            && self.cursor_inside
            && self.mouse_win.1 >= toolbar::TOOLBAR_H as f64;
        window.set_cursor_visible(!draw_remote);
        if draw_remote {
            // The remote cursor arrives as a separate Pointer PDU (the host sends it
            // out-of-band, NOT baked into the desktop bitmap — see
            // pointer_software_rendering=false + the FullControl grant), so the
            // desktop underneath the cursor is already clean. We just alpha-blend our
            // cursor bitmap on top. RRCV-18: the old background-fill patch that hid a
            // (no-longer-present) server-baked cursor is removed — that flat patch was
            // itself visible as a block over non-uniform backgrounds.
            let (cw, ch) = (cur.width as i32, cur.height as i32);
            let ox = self.mouse_win.0 as i32 - cur.hotspot_x as i32;
            let oy = self.mouse_win.1 as i32 - cur.hotspot_y as i32;
            for j in 0..ch {
                let py = oy + j;
                if py < 0 || py >= win_h as i32 {
                    continue;
                }
                for i in 0..cw {
                    let px = ox + i;
                    if px < 0 || px >= win_w as i32 {
                        continue;
                    }
                    let si = ((j * cw + i) as usize) * 4;
                    if si + 3 >= cur.rgba.len() {
                        continue;
                    }
                    let a = cur.rgba[si + 3] as u32;
                    if a == 0 {
                        continue;
                    }
                    let (r, g, b) = (
                        cur.rgba[si] as u32,
                        cur.rgba[si + 1] as u32,
                        cur.rgba[si + 2] as u32,
                    );
                    let di = (py as u32 * win_w + px as u32) as usize;
                    buffer[di] = if a == 255 {
                        (r << 16) | (g << 8) | b
                    } else {
                        let d = buffer[di];
                        let (dr, dg, db) = ((d >> 16) & 0xff, (d >> 8) & 0xff, d & 0xff);
                        (((r * a + dr * (255 - a)) / 255) << 16)
                            | (((g * a + dg * (255 - a)) / 255) << 8)
                            | ((b * a + db * (255 - a)) / 255)
                    };
                }
            }
        }
        drop(cur);

        // Overlay toolbar/status bar on top.
        let state = if connected && self.switch_flash > 0 {
            self.switch_flash -= 1;
            if let Some(w) = &self.window {
                w.request_redraw(); // keep the flash animating without server frames
            }
            t!("monitor.switching").to_string()
        } else if connected {
            t!("status.connected").to_string()
        } else if self.closed.is_some() {
            t!("status.disconnected").to_string()
        } else {
            t!("status.connecting").to_string()
        };
        let mode = if self.view_only {
            t!("mode.view_only")
        } else {
            t!("mode.control")
        }
        .to_string();
        let status = toolbar::Status {
            host: &self.host,
            mode: &mode,
            state: &state,
            connected,
            fps: self.fps,
            bytes_per_sec,
            recording: self.recorder.is_some(),
            curtain: self.curtain.load(Ordering::Relaxed),
            security: if connected { &security } else { "" },
            secure,
            view_only: self.view_only,
            encrypted,
            monitor: monitor_label.as_deref(),
        };
        toolbar::draw(&mut buffer[..], win_w, win_h, &status, self.font.as_ref());

        // Viewer-side paint cost (scale + cursor + toolbar), excluding present.
        self.rprof_accum += rstart.elapsed();
        self.rprof_n += 1;
        if std::env::var("SCCM_RC_PROFILE").as_deref() == Ok("1")
            && self.rprof_t.elapsed() >= std::time::Duration::from_secs(1)
        {
            let n = self.rprof_n.max(1);
            let avg_us = self.rprof_accum.as_micros() as u64 / n as u64;
            info!(
                paints = self.rprof_n,
                avg_paint_us = avg_us,
                win = format!("{win_w}x{win_h}"),
                "RENDER PROFILE (viewer-side paint)"
            );
            self.rprof_accum = std::time::Duration::ZERO;
            self.rprof_n = 0;
            self.rprof_t = std::time::Instant::now();
        }

        let _ = buffer.present();
    }
}
