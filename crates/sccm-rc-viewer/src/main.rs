//! SCCM Remote Control viewer — winit window rendering the remote desktop
//! over the pure-Rust SCCM transport, with mouse + keyboard forwarding.

use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use clap::Parser;
use sccm_rc_core::rdp::{
    self, DecodedImage, FastPathInputEvent, InputSender, MousePdu, PointerFlags, SessionSink,
    UpdateRegion,
};
use sccm_rc_core::SccmSession;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use winit::application::ApplicationHandler;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
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

/// Shared framebuffer written by the RDP task, read by the renderer.
#[derive(Default)]
struct SharedFrame {
    rgba: Vec<u8>,
    width: u32,
    height: u32,
    dirty: bool,
    closed: Option<String>,
}

/// Sink that copies decoded frames into the shared framebuffer.
struct FrameSink {
    shared: Arc<Mutex<SharedFrame>>,
}

impl SessionSink for FrameSink {
    fn on_graphics_update(&mut self, image: &DecodedImage, _region: UpdateRegion) {
        let mut f = self.shared.lock().unwrap();
        f.width = image.width() as u32;
        f.height = image.height() as u32;
        f.rgba.clear();
        f.rgba.extend_from_slice(image.data());
        f.dirty = true;
    }
    fn on_terminate(&mut self, reason: String) {
        self.shared.lock().unwrap().closed = Some(reason);
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_core=info")))
        .init();
    let cli = Cli::parse();

    let shared = Arc::new(Mutex::new(SharedFrame::default()));
    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<Vec<FastPathInputEvent>>(256);

    // RDP session runs on a dedicated tokio runtime thread.
    {
        let shared = shared.clone();
        let target = cli.target.clone();
        let (w, h) = (cli.width, cli.height);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                if let Err(e) = run_session(&target, w, h, shared.clone(), input_rx).await {
                    error!(error = %e, "RDP session failed");
                    shared.lock().unwrap().closed = Some(e.to_string());
                }
            });
        });
    }

    let event_loop = EventLoop::new()?;
    event_loop.set_control_flow(ControlFlow::Poll);
    let mut app = App {
        shared,
        input_tx,
        window: None,
        surface: None,
        title: format!("SCCM RC — {}", cli.target),
    };
    event_loop.run_app(&mut app)?;
    Ok(())
}

async fn run_session(
    target: &str,
    w: u16,
    h: u16,
    shared: Arc<Mutex<SharedFrame>>,
    mut input_rx: rdp::InputReceiver,
) -> anyhow::Result<()> {
    let mut session = SccmSession::connect(target).await?;
    info!(grant = ?session.grant(), "session established");
    let result = rdp::connect_rdp(&mut session, w, h).await?;
    info!("RDP active — streaming");
    let mut sink = FrameSink { shared };
    rdp::run_active_session(&mut session, result, &mut sink, &mut input_rx).await?;
    Ok(())
}

struct App {
    shared: Arc<Mutex<SharedFrame>>,
    input_tx: InputSender,
    window: Option<Rc<Window>>,
    surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
    title: String,
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

impl ApplicationHandler for App {
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

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let mut last_cursor = (0u16, 0u16);
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y) = self.map_cursor(position.x, position.y);
                last_cursor = (x, y);
                self.send_input(FastPathInputEvent::MouseEvent(MousePdu {
                    flags: PointerFlags::MOVE,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                }));
                let _ = last_cursor;
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let down = state == ElementState::Pressed;
                let mut flags = match button {
                    MouseButton::Left => PointerFlags::LEFT_BUTTON,
                    MouseButton::Right => PointerFlags::RIGHT_BUTTON,
                    MouseButton::Middle => PointerFlags::empty(),
                    _ => PointerFlags::empty(),
                };
                if down {
                    flags |= PointerFlags::DOWN;
                }
                let (x, y) = last_cursor;
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
            WindowEvent::RedrawRequested => {
                self.render();
                if let Some(reason) = self.shared.lock().unwrap().closed.clone() {
                    warn!(%reason, "session closed — exiting");
                    event_loop.exit();
                }
            }
            _ => {}
        }
    }

    fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {
        if let Some(w) = &self.window {
            w.request_redraw();
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
        let Some(nw) = NonZeroU32::new(win_w) else { return };
        let Some(nh) = NonZeroU32::new(win_h) else { return };
        if surface.resize(nw, nh).is_err() {
            return;
        }
        let Ok(mut buffer) = surface.buffer_mut() else { return };

        let frame = self.shared.lock().unwrap();
        if frame.width == 0 || frame.height == 0 || frame.rgba.is_empty() {
            // Nothing yet — clear to dark grey.
            for px in buffer.iter_mut() {
                *px = 0x0020_2020;
            }
        } else {
            // Nearest-neighbour scale framebuffer (fb_w x fb_h) into window.
            let (fb_w, fb_h) = (frame.width, frame.height);
            for wy in 0..win_h {
                let sy = (wy as u64 * fb_h as u64 / win_h as u64) as u32;
                for wx in 0..win_w {
                    let sx = (wx as u64 * fb_w as u64 / win_w as u64) as u32;
                    let si = ((sy * fb_w + sx) * 4) as usize;
                    let (r, g, b) = if si + 2 < frame.rgba.len() {
                        (frame.rgba[si], frame.rgba[si + 1], frame.rgba[si + 2])
                    } else {
                        (0, 0, 0)
                    };
                    buffer[(wy * win_w + wx) as usize] =
                        ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
                }
            }
        }
        drop(frame);
        let _ = buffer.present();
    }
}
