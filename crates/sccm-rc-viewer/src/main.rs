//! SCCM Remote Control viewer — winit window rendering the remote desktop
//! over the pure-Rust SCCM transport, with mouse + keyboard forwarding.

use std::num::NonZeroU32;
use std::rc::Rc;
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
mod recent;
mod record;
mod text;
mod toolbar;
mod wol;
use toolbar::ToolbarAction;

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
}

/// Ask for the target hostname via a native Windows input box (used when no
/// target is given on the command line — e.g. when launched by double-click).
#[cfg(windows)]
fn prompt_hostname() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // Build an editable dropdown pre-filled with recent targets.
    let items = recent::load()
        .iter()
        .map(|h| format!("'{}'", h.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
         $f=New-Object Windows.Forms.Form; $f.Text='SCCM Remote Control'; \
         $f.ClientSize=New-Object Drawing.Size(360,120); $f.StartPosition='CenterScreen'; \
         $f.FormBorderStyle='FixedDialog'; $f.MaximizeBox=$false; $f.MinimizeBox=$false; \
         $l=New-Object Windows.Forms.Label; $l.Text='Computernaam of IP-adres:'; \
         $l.AutoSize=$true; $l.Location=New-Object Drawing.Point(12,14); $f.Controls.Add($l); \
         $cb=New-Object Windows.Forms.ComboBox; $cb.Location=New-Object Drawing.Point(12,38); \
         $cb.Size=New-Object Drawing.Size(336,24); $cb.DropDownStyle='DropDown'; \
         @({items})|ForEach-Object{{[void]$cb.Items.Add($_)}}; \
         if($cb.Items.Count -gt 0){{$cb.SelectedIndex=0}}; $f.Controls.Add($cb); \
         $ok=New-Object Windows.Forms.Button; $ok.Text='Verbinden'; $ok.DialogResult='OK'; \
         $ok.Location=New-Object Drawing.Point(192,76); $f.Controls.Add($ok); $f.AcceptButton=$ok; \
         $cx=New-Object Windows.Forms.Button; $cx.Text='Annuleren'; $cx.DialogResult='Cancel'; \
         $cx.Location=New-Object Drawing.Point(273,76); $f.Controls.Add($cx); $f.CancelButton=$cx; \
         $cb.Select(); if($f.ShowDialog() -eq 'OK'){{Write-Output $cb.Text.Trim()}}",
        items = items
    );
    let out = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-STA", "-Command", &script])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(not(windows))]
fn prompt_hostname() -> Option<String> {
    None
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

/// Draw an animated "rotating dots" spinner centered at (cx, cy). A bright head
/// dot advances around the ring over time with a fading trail.
fn draw_spinner(buf: &mut [u32], win_w: u32, win_h: u32, cx: u32, cy: u32, elapsed: std::time::Duration) {
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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_core=info")))
        .init();
    let cli = Cli::parse();

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

    // Target: CLI arg (like CmRcViewer) or, if absent, a prompt.
    let target = match cli.target {
        Some(t) => t,
        None => match prompt_hostname() {
            Some(h) => h,
            None => {
                eprintln!("No target host given.");
                return Ok(());
            }
        },
    };

    // Remember this target for next time's dropdown.
    recent::add(&target);
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
            info!(count = monitors.len(), width = bw, height = bh, "advertising multi-monitor layout");
            (bw, bh)
        }
        None => (cli.width, cli.height),
    };

    // Start the first session. `spawn_session` owns the per-host reconnect loop
    // and returns the `running` flag + input sender; the Disconnect button stops
    // it and spawns a fresh one for another host.
    let (running, input_tx, done_rx) = spawn_session(
        target.clone(),
        w,
        h,
        shared.clone(),
        cursor.clone(),
        proxy.clone(),
        curtain.clone(),
        file_offer.clone(),
        monitors.clone(),
    );

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
                match run_session(&target, w, h, shared.clone(), cursor.clone(), proxy.clone(), &mut input_rx, curtain.clone(), file_offer.clone(), &monitors).await {
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
    shared.lock().unwrap().status = format!("Verbinden met {target}...");
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
        Ok(r) => r?,
        Err(_) => anyhow::bail!("verbinden met {target} duurde te lang (time-out)"),
    };
    shared.lock().unwrap().status = "Beeldverbinding opzetten...".to_string();
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
        f.security = match (encrypted, package) {
            (true, Some(p)) => format!("{p} \u{00b7} versleuteld"),
            (true, None) => "versleuteld".to_string(),
            (false, _) => "ONVERSLEUTELD".to_string(),
        };
    }
    let started = std::time::Instant::now();
    // From here the server has granted an RC session, so we MUST disconnect on
    // every exit path (including a failed RDP negotiation) — otherwise the host is
    // left occupied and the next connect trips "existing session".
    let res = async {
        let (result, initial_buf, share_id) = rdp::connect_rdp(&mut session, w, h, monitors).await?;
        info!("RDP active — streaming");
        let mut sink = FrameSink {
            shared,
            cursor,
            proxy,
            last_full: std::time::Instant::now(),
        };
        rdp::run_active_session(&mut session, result, initial_buf, share_id, &mut sink, input_rx, curtain, file_offer).await
    }
    .await;
    // Graceful teardown so the server releases the shadow/host before we reconnect.
    session.disconnect().await;
    audit::log_event(target, &grant, "disconnect", Some(started.elapsed().as_secs()));
    res?;
    Ok(())
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
    window: Option<Rc<Window>>,
    surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
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
            FastPathInputEvent::KeyboardEvent(down, 0x1D),     // Ctrl down
            FastPathInputEvent::KeyboardEvent(down, 0x38),     // Alt down
            FastPathInputEvent::KeyboardEvent(ext, 0x53),      // Del down (extended)
            FastPathInputEvent::KeyboardEvent(ext | up, 0x53), // Del up
            FastPathInputEvent::KeyboardEvent(up, 0x38),       // Alt up
            FastPathInputEvent::KeyboardEvent(up, 0x1D),       // Ctrl up
        ];
        if let Some(tx) = &self.input_tx {
            let _ = tx.try_send(seq);
        }
        info!("sent Ctrl+Alt+Del (SAS) to remote");
    }

    /// Signal the session thread to stop and disconnect gracefully: clear
    /// `running` and drop the input sender (unblocks run_active_session).
    fn begin_shutdown(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.input_tx = None;
    }

    /// Disconnect the current host and prompt for another one. Stops the current
    /// session, asks which host to connect to next, then spawns a fresh session
    /// (showing the connect overlay). If the prompt is cancelled, exits the app.
    fn switch_host(&mut self, event_loop: &ActiveEventLoop) {
        // Stop the current session and let it disconnect gracefully (the teardown
        // runs while the operator is picking the next host).
        self.begin_shutdown();
        let Some(new_target) = prompt_hostname() else {
            // No host chosen — close the app (after the teardown completes).
            let _ = self.done_rx.recv_timeout(std::time::Duration::from_secs(3));
            self.closed = Some("Verbinding verbroken".into());
            event_loop.exit();
            return;
        };
        // Wait for the old session to release the host on the server before we
        // reconnect — otherwise reconnecting (especially to the same host) trips
        // "existing session".
        let _ = self.done_rx.recv_timeout(std::time::Duration::from_secs(3));
        recent::add(&new_target);
        self.host = new_target.clone();
        self.title = format!("SCCM RC {} — {new_target}", env!("CARGO_PKG_VERSION"));
        if let Some(w) = &self.window {
            w.set_title(&self.title);
        }
        // Reset the framebuffer so the connect overlay (host + spinner) shows for
        // the new target instead of the previous desktop.
        {
            let mut f = self.shared.lock().unwrap();
            *f = SharedFrame::default();
            f.status = format!("Verbinden met {new_target}...");
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
        self.input_tx = Some(input_tx);
        self.done_rx = done_rx;
        if let Some(w) = &self.window {
            w.request_redraw();
        }
    }

    /// Map a window-space cursor position to desktop coordinates.
    fn map_cursor(&self, x: f64, y: f64) -> (u16, u16) {
        let (fb_w, fb_h) = {
            let f = self.shared.lock().unwrap();
            (f.width.max(1), f.height.max(1))
        };
        let (win_w, win_h) = self
            .window
            .as_ref()
            .map(|w| {
                let s = w.inner_size();
                (s.width.max(1), s.height.max(1))
            })
            .unwrap_or((1, 1));
        // The desktop occupies the window below the toolbar strip.
        let bar = toolbar::TOOLBAR_H as f64;
        let usable_h = (win_h as f64 - bar).max(1.0);
        let yy = (y - bar).max(0.0);
        let dx = (x * fb_w as f64 / win_w as f64).clamp(0.0, (fb_w - 1) as f64);
        let dy = (yy * fb_h as f64 / usable_h).clamp(0.0, (fb_h - 1) as f64);
        (dx as u16, dy as u16)
    }

    /// Run a toolbar button action.
    fn run_toolbar_action(&mut self, action: ToolbarAction, event_loop: &ActiveEventLoop) {
        match action {
            ToolbarAction::CtrlAltDel => self.send_ctrl_alt_del(),
            ToolbarAction::SendFile => {
                if let Some(path) = pick_file() {
                    info!(file = %path.display(), "queued file to push to remote (paste there)");
                    *self.file_offer.lock().unwrap() = Some(path);
                }
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
            .with_inner_size(winit::dpi::LogicalSize::new(1280.0, 720.0));
        let window = Rc::new(event_loop.create_window(attrs).expect("create window"));
        let context = softbuffer::Context::new(window.clone()).expect("softbuffer context");
        let surface = softbuffer::Surface::new(&context, window.clone()).expect("softbuffer surface");
        self.surface = Some(surface);
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
                self.begin_shutdown();
                event_loop.exit();
            }
            WindowEvent::Resized(_) => {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                self.mouse_win = (position.x, position.y);
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
                // Clicks on the toolbar strip are handled locally, not forwarded.
                if self.mouse_win.1 < toolbar::TOOLBAR_H as f64 {
                    if state == ElementState::Pressed && button == MouseButton::Left {
                        let win_w = self
                            .window
                            .as_ref()
                            .map(|w| w.inner_size().width.max(1))
                            .unwrap_or(1);
                        if let Some(action) =
                            toolbar::hit_test(self.mouse_win.0, self.mouse_win.1, win_w, self.font.as_ref())
                        {
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
                let units: i16 = match delta {
                    MouseScrollDelta::LineDelta(_, y) => (y * 120.0) as i16,
                    MouseScrollDelta::PixelDelta(p) => p.y as i16,
                };
                self.send_input(FastPathInputEvent::MouseEvent(MousePdu {
                    flags: PointerFlags::empty(),
                    number_of_wheel_rotation_units: units,
                    x_position: 0,
                    y_position: 0,
                }));
            }
            WindowEvent::ModifiersChanged(m) => {
                self.modifiers = m.state();
            }
            WindowEvent::KeyboardInput { event, .. } => {
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
    fn render(&mut self) {
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

        // The remote desktop renders BELOW the toolbar strip (reserved at top).
        let bar_h = toolbar::TOOLBAR_H.min(win_h);
        let desk_h = win_h.saturating_sub(bar_h).max(1);
        let frame = self.shared.lock().unwrap();
        let frame_count = frame.frames;
        let bytes_per_sec = frame.bytes_per_sec;
        let connected = frame.width != 0 && frame.height != 0 && !frame.rgba.is_empty();
        let status = frame.status.clone();
        let security = frame.security.clone();
        let secure = frame.secure;
        // Session recording: queue the current desktop (throttled internally).
        if let Some(rec) = self.recorder.as_mut() {
            rec.maybe_capture(frame.width, frame.height, &frame.rgba);
        }
        if !connected {
            let fill = if self.closed.is_some() { 0x0040_0000 } else { 0x0020_2020 };
            for px in buffer.iter_mut() {
                *px = fill;
            }
            // Connection-progress overlay: host title + current phase + a spinner.
            let msg = if let Some(reason) = &self.closed {
                format!("Verbinding verbroken — {reason}")
            } else if status.is_empty() {
                "Verbinden...".to_string()
            } else {
                status
            };
            let cx = win_w / 2;
            let cy = win_h / 2;
            // Animated spinner above the text (only while still connecting).
            if self.closed.is_none() {
                draw_spinner(&mut buffer[..], win_w, win_h, cx, cy.saturating_sub(72), self.connect_start.elapsed());
            }
            if let Some(f) = self.font.as_ref() {
                f.draw_centered(&mut buffer[..], win_w, win_h, cy as f32 + 4.0, &self.host, 0x00FF_FFFF, 34.0);
                f.draw_centered(&mut buffer[..], win_w, win_h, cy as f32 + 38.0, &msg, 0x00B0_C0D0, 19.0);
            } else {
                toolbar::draw_text_centered(&mut buffer[..], win_w, win_h, cy.saturating_sub(28), &self.host, 0x00FF_FFFF, 3);
                toolbar::draw_text_centered(&mut buffer[..], win_w, win_h, cy + 8, &msg, 0x00B0_C0D0, 2);
            }
        } else {
            let (fb_w, fb_h) = (frame.width, frame.height);
            let src = &frame.rgba;
            let fbw = fb_w as usize;
            if win_w == fb_w && desk_h == fb_h {
                // 1:1 — direct copy, sharpest (no interpolation).
                for wy in bar_h..win_h {
                    let row = (wy - bar_h) as usize * fbw;
                    let out_row = (wy * win_w) as usize;
                    for wx in 0..win_w as usize {
                        let si = (row + wx) * 4;
                        buffer[out_row + wx] = if si + 2 < src.len() {
                            ((src[si] as u32) << 16) | ((src[si + 1] as u32) << 8) | (src[si + 2] as u32)
                        } else {
                            0
                        };
                    }
                }
            } else {
                // Bilinear scale of the whole desktop. (A dirty-region variant was
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
                let cols: Vec<(usize, usize, u32)> =
                    (0..win_w).map(|wx| map(wx, win_w, fb_w)).collect();
                #[inline(always)]
                fn lerp(a: u32, b: u32, f: u32) -> u32 {
                    (a * (256 - f) + b * f) >> 8
                }
                for wy in bar_h..win_h {
                    let (y0, y1, fy) = map(wy - bar_h, desk_h, fb_h);
                    let r0 = y0 * fbw;
                    let r1 = y1 * fbw;
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
            // The server bakes its own cursor (a black box) into the desktop at
            // the live position; a refresh can't remove it (the cursor IS there).
            // Hide it: fill the box with the background colour sampled just outside
            // it (clean thanks to the cursor-trail refresh), then draw our own
            // cursor over the fill. Near-invisible on the wallpaper; a small flat
            // patch over busy content instead of a stark black square.
            {
                let mx = self.mouse_win.0 as i32;
                let my = self.mouse_win.1 as i32;
                let half = 16i32;
                let cx = |x: i32| x.clamp(0, win_w as i32 - 1) as u32;
                let cy = |y: i32| y.clamp(bar_h as i32, win_h as i32 - 1) as u32;
                let s1 = buffer[(cy(my) * win_w + cx(mx - half - 6)) as usize];
                let s2 = buffer[(cy(my) * win_w + cx(mx + half + 6)) as usize];
                let s3 = buffer[(cy(my - half - 6) * win_w + cx(mx)) as usize];
                let s4 = buffer[(cy(my + half + 6) * win_w + cx(mx)) as usize];
                let (mut r, mut g, mut b) = (0u32, 0u32, 0u32);
                for c in [s1, s2, s3, s4] {
                    r += (c >> 16) & 0xff;
                    g += (c >> 8) & 0xff;
                    b += c & 0xff;
                }
                let bg = ((r / 4) << 16) | ((g / 4) << 8) | (b / 4);
                for y in cy(my - half)..=cy(my + half) {
                    let row = y * win_w;
                    for x in cx(mx - half)..=cx(mx + half) {
                        buffer[(row + x) as usize] = bg;
                    }
                }
            }
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
                    let (r, g, b) = (cur.rgba[si] as u32, cur.rgba[si + 1] as u32, cur.rgba[si + 2] as u32);
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
        let state = if connected {
            "Connected"
        } else if self.closed.is_some() {
            "Disconnected"
        } else {
            "Connecting..."
        };
        let status = toolbar::Status {
            host: &self.host,
            mode: if self.view_only { "View Only" } else { "Control" },
            state,
            connected,
            fps: self.fps,
            bytes_per_sec,
            recording: self.recorder.is_some(),
            curtain: self.curtain.load(Ordering::Relaxed),
            security: if connected { &security } else { "" },
            secure,
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
