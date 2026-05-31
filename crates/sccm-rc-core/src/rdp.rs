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
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use sccm_rc_protocol::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{debug, info, warn};

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
pub async fn connect_rdp(session: &mut SccmSession, width: u16, height: u16) -> Result<ConnectionResult> {
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
            "✅ RDP connection sequence complete — active session"
        );
        Ok(result)
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
/// them to IronRDP's `ActiveStage`, send response frames back, and surface
/// graphics updates to the sink. Returns when the session ends.
pub async fn run_active_session(
    session: &mut SccmSession,
    connection_result: ConnectionResult,
    sink: &mut dyn SessionSink,
) -> Result<()> {
    let width = connection_result.desktop_size.width;
    let height = connection_result.desktop_size.height;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);
    let mut stage = ActiveStage::new(connection_result);

    let mut buf: Vec<u8> = Vec::new();
    let mut frames = 0u64;
    let mut pdus = 0u64;

    loop {
        // Accumulate one full PDU (FastPath or X.224).
        let pdu_info = loop {
            match ironrdp_pdu::find_size(&buf).map_err(|e| Error::Protocol(format!("find_size: {e}")))? {
                Some(info) => break info,
                None => {
                    let more = session
                        .recv_rdp()
                        .await?
                        .ok_or_else(|| Error::Protocol("server closed during RDP session".into()))?;
                    buf.extend_from_slice(&more);
                }
            }
        };
        let frame: Vec<u8> = buf.drain(..pdu_info.length).collect();
        pdus += 1;
        if pdus % 200 == 0 {
            debug!(pdus, graphics_updates = frames, "session heartbeat");
        }

        let outputs = stage
            .process(&mut image, pdu_info.action, &frame)
            .map_err(|e| Error::Protocol(format!("active-stage: {e}")))?;

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
                    info!(refeed, "server reactivation — re-running capability exchange");
                    if refeed {
                        buf.splice(0..0, frame.iter().copied());
                    }
                    let new_result = drive_reactivation(session, *activation, &mut buf).await?;
                    let w = new_result.desktop_size.width;
                    let h = new_result.desktop_size.height;
                    image = DecodedImage::new(PixelFormat::RgbA32, w, h);
                    stage = ActiveStage::new(new_result);
                    info!(width = w, height = h, "reactivation complete — active session resumed");
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
