//! SCCM Remote Control viewer — winit window rendering the remote desktop
//! over the pure-Rust SCCM transport, with mouse + keyboard forwarding.

use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use clap::Parser;
use sccm_rc_core::rdp::{
    self, FastPathInputEvent, FrameView, InputSender, KeyboardFlags, MousePdu, PointerFlags,
    SessionSink, UpdateRegion,
};
use sccm_rc_core::SccmSession;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use winit::application::ApplicationHandler;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::platform::scancode::PhysicalKeyExtScancode;
use winit::window::{Window, WindowId};

#[derive(Parser)]
#[command(name = "sccm-rc-viewer", about = "SCCM Remote Control viewer", version)]
struct Cli {
    /// Target hostname or IP
    target: String,
    /// Requested desktop width
    #[arg(long, default_value_t = 1280)]
    width: u16,
    /// Requested desktop height
    #[arg(long, default_value_t = 720)]
    height: u16,
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
}

/// Sink that copies decoded frames into the shared framebuffer and wakes
/// the UI thread. Copies only the dirty region (the incoming frame is the full
/// accumulated desktop) and throttles wake-ups so a burst of small order updates
/// doesn't trigger a redraw storm.
struct FrameSink {
    shared: Arc<Mutex<SharedFrame>>,
    proxy: EventLoopProxy<UserEvent>,
}

impl SessionSink for FrameSink {
    fn on_graphics_update(&mut self, image: &dyn FrameView, region: UpdateRegion) {
        let iw = image.width() as u32;
        let ih = image.height() as u32;
        let src = image.data();
        {
            let mut f = self.shared.lock().unwrap();
            if f.width != iw || f.height != ih || f.rgba.len() != src.len() {
                // First frame or size change (reactivation): full copy.
                f.width = iw;
                f.height = ih;
                f.rgba.clear();
                f.rgba.extend_from_slice(src);
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
        }
        // winit coalesces multiple request_redraw() into a single RedrawRequested,
        // so a burst of region updates results in one redraw — no throttle needed.
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

    let shared = Arc::new(Mutex::new(SharedFrame::default()));
    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<Vec<FastPathInputEvent>>(256);

    let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
    event_loop.set_control_flow(ControlFlow::Wait);
    let proxy = event_loop.create_proxy();

    // RDP session runs on a dedicated tokio runtime thread.
    {
        let shared = shared.clone();
        let proxy = proxy.clone();
        let target = cli.target.clone();
        let (w, h) = (cli.width, cli.height);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                // Auto-reconnect: a transport desync or server-side reset ends the
                // session; rather than crashing the window, reconnect and resume.
                // The window closes only when the user closes it (exits the loop).
                let mut input_rx = input_rx;
                loop {
                    match run_session(&target, w, h, shared.clone(), proxy.clone(), &mut input_rx).await {
                        Ok(()) => info!("session ended; reconnecting in 1s"),
                        Err(e) => warn!(error = %e, "session error; reconnecting in 1s"),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
        });
    }

    let mut app = App {
        shared,
        input_tx,
        window: None,
        surface: None,
        title: format!("SCCM RC — {}", cli.target),
        last_cursor: (0, 0),
        closed: None,
    };
    event_loop.run_app(&mut app)?;
    Ok(())
}

async fn run_session(
    target: &str,
    w: u16,
    h: u16,
    shared: Arc<Mutex<SharedFrame>>,
    proxy: EventLoopProxy<UserEvent>,
    input_rx: &mut rdp::InputReceiver,
) -> anyhow::Result<()> {
    let mut session = SccmSession::connect(target).await?;
    info!(grant = ?session.grant(), "session established");
    let (result, initial_buf, share_id) = rdp::connect_rdp(&mut session, w, h).await?;
    info!("RDP active — streaming");
    let mut sink = FrameSink { shared, proxy };
    let res = rdp::run_active_session(&mut session, result, initial_buf, share_id, &mut sink, input_rx).await;
    // Graceful teardown so the server releases the shadow/host before we reconnect.
    session.disconnect().await;
    res?;
    Ok(())
}

struct App {
    shared: Arc<Mutex<SharedFrame>>,
    input_tx: InputSender,
    window: Option<Rc<Window>>,
    surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
    title: String,
    last_cursor: (u16, u16),
    closed: Option<String>,
}

impl App {
    fn send_input(&self, ev: FastPathInputEvent) {
        let _ = self.input_tx.try_send(vec![ev]);
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
        let dx = (x * fb_w as f64 / win_w as f64).clamp(0.0, (fb_w - 1) as f64);
        let dy = (y * fb_h as f64 / win_h as f64).clamp(0.0, (fb_h - 1) as f64);
        (dx as u16, dy as u16)
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

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::Resized(_) => {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y) = self.map_cursor(position.x, position.y);
                self.last_cursor = (x, y);
                self.send_input(FastPathInputEvent::MouseEvent(MousePdu {
                    flags: PointerFlags::MOVE,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                }));
            }
            WindowEvent::MouseInput { state, button, .. } => {
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
            WindowEvent::KeyboardInput { event, .. } => {
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
            WindowEvent::RedrawRequested => self.render(),
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

        let frame = self.shared.lock().unwrap();
        if frame.width == 0 || frame.height == 0 || frame.rgba.is_empty() {
            let fill = if self.closed.is_some() { 0x0040_0000 } else { 0x0020_2020 };
            for px in buffer.iter_mut() {
                *px = fill;
            }
        } else {
            let (fb_w, fb_h) = (frame.width, frame.height);
            for wy in 0..win_h {
                let sy = (wy as u64 * fb_h as u64 / win_h as u64) as u32;
                let row = (sy * fb_w) as usize;
                let out_row = (wy * win_w) as usize;
                for wx in 0..win_w {
                    let sx = (wx as u64 * fb_w as u64 / win_w as u64) as u32;
                    let si = (row + sx as usize) * 4;
                    let px = if si + 2 < frame.rgba.len() {
                        ((frame.rgba[si] as u32) << 16)
                            | ((frame.rgba[si + 1] as u32) << 8)
                            | (frame.rgba[si + 2] as u32)
                    } else {
                        0
                    };
                    buffer[out_row + wx as usize] = px;
                }
            }
        }
        drop(frame);
        let _ = buffer.present();
    }
}
