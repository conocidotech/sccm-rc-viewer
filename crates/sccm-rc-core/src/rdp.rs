//! Drive an IronRDP `ClientConnector` over the sealed SCCM channel.
//!
//! The RDP connection sequence (X.224 → MCS → security → capabilities →
//! finalization) is run sans-IO: IronRDP produces PDU bytes, we seal them
//! and send them through `SccmSession`; we receive sealed frames, unseal
//! them, and feed the RDP bytes back into IronRDP until it reaches the
//! `Connected` state.

use crate::{SccmSession, Grant};
use ironrdp_connector::connection_activation::{ConnectionActivationSequence, ConnectionActivationState};
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, Config, ConnectionResult, ConnectorError, Credentials,
    DesktopSize, Sequence,
};
use ironrdp_connector::State;
use ironrdp_core::WriteBuf;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
pub use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use sccm_rc_protocol::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{debug, info, warn};

// Re-export the input event types so the UI can construct them.
pub use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
pub use ironrdp_pdu::input::mouse::PointerFlags;
pub use ironrdp_pdu::input::MousePdu;

/// Input channel: the UI sends batches of fastpath input events to the session.
pub type InputReceiver = tokio::sync::mpsc::Receiver<Vec<FastPathInputEvent>>;
pub type InputSender = tokio::sync::mpsc::Sender<Vec<FastPathInputEvent>>;

/// Build a Config for an SCCM RC session: standard RDP security (no TLS,
/// no CredSSP) since the outer SecurityFilter already encrypts everything.
pub fn sccm_rdp_config(width: u16, height: u16) -> Config {
    Config {
        desktop_size: DesktopSize { width, height },
        desktop_scale_factor: 0,
        enable_tls: false,
        enable_credssp: false,
        credentials: Credentials::UsernamePassword {
            username: whoami_user(),
            password: String::new(),
        },
        domain: None,
        client_build: 0,
        client_name: "sccm-rc".to_string(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: String::new(),
        platform: MajorPlatformType::WINDOWS,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        performance_flags: Default::default(),
        license_cache: None,
        timezone_info: Default::default(),
        enable_server_pointer: true,
        pointer_software_rendering: true,
    }
}

fn whoami_user() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string())
}

fn map_err(e: ConnectorError) -> Error {
    Error::Protocol(format!("ironrdp: {e}"))
}

/// Run the full RDP connection sequence over the established SCCM session.
/// Returns the negotiated connection result on success.
pub async fn connect_rdp(
    session: &mut SccmSession,
    width: u16,
    height: u16,
) -> Result<(ConnectionResult, Vec<u8>)> {
    if session.grant() == Grant::ViewOnly {
        debug!("session is view-only — input will be rejected by the server");
    }

    let config = sccm_rdp_config(width, height);
    // Client address is only used to fill the Client Info PDU; a placeholder
    // is fine since the real transport is our sealed channel.
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut connector = ClientConnector::new(config, client_addr);

    let mut input_buf: Vec<u8> = Vec::new();
    let mut out = WriteBuf::new();

    loop {
        if connector.state.is_terminal() {
            break;
        }

        out.clear();
        let written = if let Some(hint) = connector.next_pdu_hint() {
            // Accumulate sealed RDP bytes until a full PDU is available.
            let pdu_len = loop {
                match hint.find_size(&input_buf).map_err(|e| Error::Protocol(format!("pdu hint: {e}")))? {
                    Some((_matches, size)) => break size,
                    None => {
                        let more = session
                            .recv_rdp()
                            .await?
                            .ok_or_else(|| Error::Protocol("server closed during RDP connect".into()))?;
                        input_buf.extend_from_slice(&more);
                    }
                }
            };
            let pdu: Vec<u8> = input_buf.drain(..pdu_len).collect();
            debug!(state = connector.state.name(), pdu_len, "RDP step (with input)");
            connector.step(&pdu, &mut out).map_err(map_err)?
        } else {
            debug!(state = connector.state.name(), "RDP step (no input)");
            connector.step_no_input(&mut out).map_err(map_err)?
        };

        let _ = written;
        if out.filled_len() > 0 {
            session.send_rdp(out.filled()).await?;
        }
    }

    if let ClientConnectorState::Connected { result } = connector.state {
        info!(
            width = result.desktop_size.width,
            height = result.desktop_size.height,
            io_channel = result.io_channel_id,
            user_channel = result.user_channel_id,
            leftover = input_buf.len(),
            "✅ RDP connection sequence complete — active session"
        );
        // Any bytes still buffered are the server's first post-activation PDUs
        // (often the initial screen paint). They must be carried into the
        // active session, not dropped.
        Ok((result, input_buf))
    } else {
        Err(Error::Protocol(format!(
            "RDP connector ended in non-connected state: {}",
            connector.state.name()
        )))
    }
}

/// A graphics-update region (inclusive pixel rectangle) on the framebuffer.
#[derive(Debug, Clone, Copy)]
pub struct UpdateRegion {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

/// Callbacks for an active RDP session: receive framebuffer updates.
pub trait SessionSink: Send {
    /// Called when a region of the framebuffer changed. `image` is the full
    /// RGBA framebuffer; `region` is the dirty rectangle.
    fn on_graphics_update(&mut self, image: &DecodedImage, region: UpdateRegion);
    /// Called when the session ends.
    fn on_terminate(&mut self, reason: String);
}

/// Run the active RDP session loop: read PDUs from the sealed channel, feed
/// them to IronRDP's `ActiveStage`, send response frames back, surface
/// graphics updates to the sink, and forward UI input. Returns when the
/// session ends.
pub async fn run_active_session(
    session: &mut SccmSession,
    connection_result: ConnectionResult,
    initial_buf: Vec<u8>,
    sink: &mut dyn SessionSink,
    input_rx: &mut InputReceiver,
) -> Result<()> {
    let mut width = connection_result.desktop_size.width;
    let mut height = connection_result.desktop_size.height;
    let mut io_channel_id = connection_result.io_channel_id;
    let mut user_channel_id = connection_result.user_channel_id;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);
    let mut stage = ActiveStage::new(connection_result);

    // Seed with any PDUs left over from the connection sequence (initial paint).
    let mut buf: Vec<u8> = initial_buf;
    let mut frames = 0u64;
    let mut pdus = 0u64;

    // The server's PDUs carry a share_id that client PDUs must echo.
    let mut share_id: u32 = 0;

    // Force an initial full-screen repaint. Without this, a static remote
    // desktop (e.g. no user logged in) sends nothing and the window stays blank.
    send_refresh_rect(session, user_channel_id, io_channel_id, share_id, width, height).await?;

    loop {
        // Either a network PDU arrives, or the UI sends input.
        // Drain any complete PDU already buffered before awaiting more.
        if ironrdp_pdu::find_size(&buf)
            .map_err(|e| Error::Protocol(format!("find_size: {e}")))?
            .is_none()
        {
            tokio::select! {
                biased;
                events = input_rx.recv() => {
                    let Some(events) = events else { return Ok(()); }; // UI closed
                    let outs = stage
                        .process_fastpath_input(&mut image, &events)
                        .map_err(|e| Error::Protocol(format!("input: {e}")))?;
                    let mut sent = 0usize;
                    for out in outs {
                        if let ActiveStageOutput::ResponseFrame(bytes) = out {
                            sent += bytes.len();
                            session.send_rdp(&bytes).await?;
                        }
                    }
                    debug!(events = events.len(), sent_bytes = sent, "forwarded input");
                    continue;
                }
                more = session.recv_rdp() => {
                    match more? {
                        Some(b) => {
                            debug!(bytes = b.len(), "recv during active session");
                            buf.extend_from_slice(&b);
                        }
                        None => return Ok(()),
                    }
                    // fall through to try to parse a PDU
                    if ironrdp_pdu::find_size(&buf)
                        .map_err(|e| Error::Protocol(format!("find_size: {e}")))?
                        .is_none()
                    {
                        continue;
                    }
                }
            }
        }

        let pdu_info = ironrdp_pdu::find_size(&buf)
            .map_err(|e| Error::Protocol(format!("find_size: {e}")))?
            .expect("just checked a PDU is present");
        let frame: Vec<u8> = buf.drain(..pdu_info.length).collect();
        pdus += 1;
        if pdus % 200 == 0 {
            debug!(pdus, graphics_updates = frames, "session heartbeat");
        }

        let outputs = stage
            .process(&mut image, pdu_info.action, &frame)
            .map_err(|e| Error::Protocol(format!("active-stage: {e}")))?;

        if !outputs.is_empty() {
            let kinds: Vec<&str> = outputs
                .iter()
                .map(|o| match o {
                    ActiveStageOutput::ResponseFrame(_) => "Response",
                    ActiveStageOutput::GraphicsUpdate(_) => "Graphics",
                    ActiveStageOutput::Terminate(_) => "Terminate",
                    ActiveStageOutput::DeactivateAll(_) => "DeactivateAll",
                    ActiveStageOutput::PointerDefault => "PtrDefault",
                    ActiveStageOutput::PointerHidden => "PtrHidden",
                    ActiveStageOutput::PointerPosition { .. } => "PtrPos",
                    ActiveStageOutput::PointerBitmap(_) => "PtrBitmap",
                })
                .collect();
            debug!(action = ?pdu_info.action, ?kinds, "stage outputs");
        }

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(bytes) => {
                    session.send_rdp(&bytes).await?;
                }
                ActiveStageOutput::GraphicsUpdate(r) => {
                    frames += 1;
                    sink.on_graphics_update(
                        &image,
                        UpdateRegion {
                            left: r.left,
                            top: r.top,
                            right: r.right,
                            bottom: r.bottom,
                        },
                    );
                }
                ActiveStageOutput::Terminate(reason) => {
                    info!(?reason, frames, "RDP session terminated by server");
                    sink.on_terminate(format!("{reason:?}"));
                    return Ok(());
                }
                ActiveStageOutput::DeactivateAll(activation) => {
                    // Two triggers map to this output:
                    //  (a) a direct ServerDemandActive (SCCM's reactivation without a
                    //      preceding DeactivateAll) — the `frame` IS the DemandActive
                    //      the sequence needs, so re-feed it; or
                    //  (b) a real ServerDeactivateAll — the DemandActive is the NEXT
                    //      frame, so do not re-feed.
                    let refeed = ironrdp_connector::legacy::frame_is_server_demand_active(&frame);
                    // Capture the server's share_id so our refresh-rect echoes it.
                    if let Some(sid) = ironrdp_connector::legacy::frame_share_id(&frame) {
                        share_id = sid;
                    }
                    info!(refeed, share_id, "server reactivation — re-running capability exchange");
                    if refeed {
                        buf.splice(0..0, frame.iter().copied());
                    }
                    let new_result = drive_reactivation(session, *activation, &mut buf).await?;
                    width = new_result.desktop_size.width;
                    height = new_result.desktop_size.height;
                    io_channel_id = new_result.io_channel_id;
                    user_channel_id = new_result.user_channel_id;
                    image = DecodedImage::new(PixelFormat::RgbA32, width, height);
                    stage = ActiveStage::new(new_result);
                    info!(width, height, share_id, "reactivation complete — active session resumed");
                    // Repaint after reactivation too (with the server's share_id).
                    send_refresh_rect(session, user_channel_id, io_channel_id, share_id, width, height).await?;
                    break; // restart the outer read loop with the new stage
                }
                // Pointer updates — handled by the UI layer later.
                ActiveStageOutput::PointerDefault
                | ActiveStageOutput::PointerHidden
                | ActiveStageOutput::PointerPosition { .. }
                | ActiveStageOutput::PointerBitmap(_) => {}
            }
        }
    }
}

/// Send a Refresh Rect PDU covering the whole desktop to force a full repaint.
async fn send_refresh_rect(
    session: &mut SccmSession,
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
    width: u16,
    height: u16,
) -> Result<()> {
    use ironrdp_core::WriteBuf;
    use ironrdp_pdu::geometry::InclusiveRectangle;
    use ironrdp_pdu::rdp::headers::ShareDataPdu;
    use ironrdp_pdu::rdp::refresh_rectangle::RefreshRectanglePdu;

    let pdu = ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
        areas_to_refresh: vec![InclusiveRectangle {
            left: 0,
            top: 0,
            right: width.saturating_sub(1),
            bottom: height.saturating_sub(1),
        }],
    });
    let mut out = WriteBuf::new();
    ironrdp_connector::legacy::encode_share_data(user_channel_id, io_channel_id, share_id, pdu, &mut out)
        .map_err(|e| Error::Protocol(format!("encode refresh rect: {e}")))?;
    session.send_rdp(out.filled()).await?;
    debug!(width, height, "sent refresh-rect (full desktop)");
    Ok(())
}

/// Drive a `ConnectionActivationSequence` (capability exchange + finalization)
/// to completion, reading PDUs from `buf`/the session and sending responses,
/// then rebuild a `ConnectionResult` from the finalized state.
async fn drive_reactivation(
    session: &mut SccmSession,
    mut seq: ConnectionActivationSequence,
    buf: &mut Vec<u8>,
) -> Result<ConnectionResult> {
    use ironrdp_core::WriteBuf;
    let mut out = WriteBuf::new();
    loop {
        if let ConnectionActivationState::Finalized { .. } = seq.state {
            break;
        }
        out.clear();
        if let Some(hint) = seq.next_pdu_hint() {
            let pdu_len = loop {
                match hint.find_size(buf).map_err(|e| Error::Protocol(format!("reactivation hint: {e}")))? {
                    Some((_m, size)) => break size,
                    None => {
                        let more = session
                            .recv_rdp()
                            .await?
                            .ok_or_else(|| Error::Protocol("closed during reactivation".into()))?;
                        buf.extend_from_slice(&more);
                    }
                }
            };
            let pdu: Vec<u8> = buf.drain(..pdu_len).collect();
            seq.step(&pdu, &mut out).map_err(|e| Error::Protocol(format!("reactivation: {e}")))?;
        } else {
            seq.step_no_input(&mut out).map_err(|e| Error::Protocol(format!("reactivation: {e}")))?;
        }
        if out.filled_len() > 0 {
            session.send_rdp(out.filled()).await?;
        }
    }

    let ConnectionActivationState::Finalized {
        io_channel_id,
        user_channel_id,
        desktop_size,
        enable_server_pointer,
        pointer_software_rendering,
    } = seq.state
    else {
        return Err(Error::Protocol("reactivation did not finalize".into()));
    };

    Ok(ConnectionResult {
        io_channel_id,
        user_channel_id,
        static_channels: ironrdp_svc::StaticChannelSet::new(),
        desktop_size,
        enable_server_pointer,
        pointer_software_rendering,
        connection_activation: seq.reset_clone(),
    })
}

/// A simple headless sink that just counts + logs updates (for validation).
pub struct LoggingSink {
    pub updates: u64,
    pub total_pixels: u64,
}

impl Default for LoggingSink {
    fn default() -> Self {
        Self { updates: 0, total_pixels: 0 }
    }
}

impl SessionSink for LoggingSink {
    fn on_graphics_update(&mut self, image: &DecodedImage, region: UpdateRegion) {
        self.updates += 1;
        let w = region.right.saturating_sub(region.left) as u64 + 1;
        let h = region.bottom.saturating_sub(region.top) as u64 + 1;
        self.total_pixels += w * h;
        if self.updates <= 20 || self.updates % 50 == 0 {
            info!(
                update = self.updates,
                region = format!("{}x{} @ ({},{})", w, h, region.left, region.top),
                fb = format!("{}x{}", image.width(), image.height()),
                "graphics update"
            );
        }
    }
    fn on_terminate(&mut self, reason: String) {
        warn!(%reason, updates = self.updates, "session terminated");
    }
}

/// A sink that saves each decoded frame to a PNG (for headless visual debugging).
pub struct PngDumpSink {
    pub path: String,
    pub updates: u64,
    pub nonblack_pixels: u64,
}

impl PngDumpSink {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into(), updates: 0, nonblack_pixels: 0 }
    }
}

impl SessionSink for PngDumpSink {
    fn on_graphics_update(&mut self, image: &DecodedImage, _region: UpdateRegion) {
        self.updates += 1;
        let w = image.width() as u32;
        let h = image.height() as u32;
        let data = image.data(); // RGBA32
        // Count non-black pixels so we know if there's actual content.
        let mut nonblack = 0u64;
        for px in data.chunks_exact(4) {
            if px[0] != 0 || px[1] != 0 || px[2] != 0 {
                nonblack += 1;
            }
        }
        self.nonblack_pixels = nonblack;
        // Save as PNG (RGBA).
        if let Some(buf) = image::RgbaImage::from_raw(w, h, data.to_vec()) {
            if let Err(e) = buf.save(&self.path) {
                warn!(error = %e, "png save failed");
            } else {
                info!(update = self.updates, fb = format!("{w}x{h}"), nonblack, path = %self.path, "saved frame PNG");
            }
        }
    }
    fn on_terminate(&mut self, reason: String) {
        warn!(%reason, "session terminated");
    }
}
