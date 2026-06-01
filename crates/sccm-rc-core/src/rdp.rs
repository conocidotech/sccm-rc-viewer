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
use ironrdp_core::{decode_cursor, ReadCursor, WriteBuf};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::fast_path::{FastPathHeader, FastPathUpdatePdu, Fragmentation, UpdateCode};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
pub use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use sccm_rc_orders::{ColorDepth, OrderCanvas, OrderProcessor};
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

/// A passive static virtual channel: it is declared in the MCS Connect Initial
/// and joined, but ignores all traffic. mstscax declares several channels
/// (rdpdr/rdpsnd/cliprdr/…); the SCCM server appears to withhold its
/// deactivation-reactivation (and thus all graphics) until the client presents
/// a mstscax-like channel set. We don't need the channels' functionality —
/// only their presence in the capability/channel negotiation.
#[derive(Debug)]
struct PassiveChannel {
    name: ironrdp_pdu::gcc::ChannelName,
}

impl PassiveChannel {
    fn new(name: &str) -> Self {
        Self {
            name: ironrdp_pdu::gcc::ChannelName::from_utf8(name).expect("valid 8-char channel name"),
        }
    }
}

ironrdp_svc::impl_as_any!(PassiveChannel);

impl ironrdp_svc::SvcProcessor for PassiveChannel {
    fn channel_name(&self) -> ironrdp_pdu::gcc::ChannelName {
        self.name.clone()
    }
    fn process(&mut self, _payload: &[u8]) -> ironrdp_pdu::PduResult<Vec<ironrdp_svc::SvcMessage>> {
        Ok(Vec::new())
    }
}

impl ironrdp_svc::SvcClientProcessor for PassiveChannel {}

/// Run the full RDP connection sequence over the established SCCM session.
/// Returns the negotiated connection result on success.
pub async fn connect_rdp(
    session: &mut SccmSession,
    width: u16,
    height: u16,
) -> Result<(ConnectionResult, Vec<u8>, u32)> {
    if session.grant() == Grant::ViewOnly {
        debug!("session is view-only — input will be rejected by the server");
    }

    let config = sccm_rdp_config(width, height);
    // Client address is only used to fill the Client Info PDU; a placeholder
    // is fine since the real transport is our sealed channel.
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut connector = ClientConnector::new(config, client_addr);
    // Declare mstscax-like static virtual channels (SCCM_RC_CHANNELS=1). The
    // server seems to require them before it reactivates + paints.
    if std::env::var("SCCM_RC_CHANNELS").as_deref() == Ok("1") {
        for name in ["cliprdr", "rdpsnd", "rdpdr", "drdynvc"] {
            connector = connector.with_static_channel(PassiveChannel::new(name));
        }
        info!("declared passive static virtual channels: cliprdr, rdpsnd, rdpdr, drdynvc");
    }

    let mut input_buf: Vec<u8> = Vec::new();
    let mut out = WriteBuf::new();
    // Capture the server's share_id from its DemandActive (CapabilitiesExchange)
    // so post-activation PDUs we send (Refresh Rect, Suppress Output) echo it.
    // A static lock screen only repaints on a Refresh Rect with the right id.
    let mut share_id: u32 = 0;

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
            if share_id == 0 {
                if let Some(sid) = ironrdp_connector::legacy::frame_share_id(&pdu) {
                    share_id = sid;
                    debug!(share_id, "captured server share_id from DemandActive");
                }
            }
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
        Ok((result, input_buf, share_id))
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

/// A read-only view of an RGBA32 framebuffer. Implemented by both IronRDP's
/// `DecodedImage` (bitmap/surface/RemoteFx updates) and our `OrderCanvas`
/// (drawing-order updates), so a sink can render whichever produced the frame.
pub trait FrameView {
    fn data(&self) -> &[u8];
    fn width(&self) -> u16;
    fn height(&self) -> u16;
}

impl FrameView for DecodedImage {
    fn data(&self) -> &[u8] {
        DecodedImage::data(self)
    }
    fn width(&self) -> u16 {
        DecodedImage::width(self)
    }
    fn height(&self) -> u16 {
        DecodedImage::height(self)
    }
}

impl FrameView for OrderCanvas {
    fn data(&self) -> &[u8] {
        OrderCanvas::data(self)
    }
    fn width(&self) -> u16 {
        OrderCanvas::width(self)
    }
    fn height(&self) -> u16 {
        OrderCanvas::height(self)
    }
}

/// Callbacks for an active RDP session: receive framebuffer updates.
pub trait SessionSink: Send {
    /// Called when a region of the framebuffer changed. `frame` is the full
    /// RGBA framebuffer (either IronRDP's or the order renderer's); `region` is
    /// the dirty rectangle.
    fn on_graphics_update(&mut self, frame: &dyn FrameView, region: UpdateRegion);
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
    initial_share_id: u32,
    sink: &mut dyn SessionSink,
    input_rx: &mut InputReceiver,
) -> Result<()> {
    let mut width = connection_result.desktop_size.width;
    let mut height = connection_result.desktop_size.height;
    let mut io_channel_id = connection_result.io_channel_id;
    let mut user_channel_id = connection_result.user_channel_id;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);
    let mut stage = ActiveStage::new(connection_result);

    // Drawing-order renderer for Fast-Path "Orders" updates (which IronRDP
    // drops). The SCCM RC server paints via drawing orders; `order_frag`
    // reassembles fragmented order updates.
    let mut orders = OrderProcessor::new(width, height, ColorDepth::Bpp16);
    let mut order_frag: Vec<u8> = Vec::new();
    let mut order_frag_active = false;
    // Dump the first few complete order streams raw, for offline verification
    // of cache-bitmap encoding / compression-header assumptions.
    let mut order_dump_count = 0u32;

    // Seed with any PDUs left over from the connection sequence (initial paint).
    let mut buf: Vec<u8> = initial_buf;
    let mut frames = 0u64;
    let mut pdus = 0u64;

    // The server's PDUs carry a share_id that client PDUs must echo. Seeded
    // from the DemandActive captured during the connection sequence so the very
    // first Refresh Rect is valid (a static lock screen ignores share_id=0).
    let mut share_id: u32 = initial_share_id;

    // Some servers (and possibly this SCCM RC server) withhold all graphics
    // until they receive a Persistent Bitmap Cache Key List PDU — mstscax sends
    // a flood of these right after ConfirmActive. (SCCM_RC_PERSIST=1.)
    if std::env::var("SCCM_RC_PERSIST").as_deref() == Ok("1") {
        send_persistent_key_list(session, user_channel_id, io_channel_id, share_id).await?;
    }

    // Force an initial full-screen repaint. Without this, a static remote
    // desktop (e.g. locked / no user) sends nothing and the window stays blank.
    // (SCCM_RC_NO_REFRESH=1 skips it, to test whether the server auto-paints.)
    if std::env::var("SCCM_RC_NO_REFRESH").as_deref() != Ok("1") {
        info!(share_id, "initial repaint request");
        send_refresh_rect(session, user_channel_id, io_channel_id, share_id, width, height).await?;
    } else {
        info!("skipping initial refresh (SCCM_RC_NO_REFRESH=1)");
    }

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

        // Intercept Fast-Path "Orders" updates before IronRDP (which silently
        // drops them). Render them into our OrderCanvas instead.
        if pdu_info.action == ironrdp_pdu::Action::FastPath {
            if let Some((frag, data)) = decode_fastpath_orders(&frame) {
                if let Some(complete) =
                    reassemble_orders(&mut order_frag, &mut order_frag_active, frag, data)
                {
                    if order_dump_count < 5 {
                        order_dump_count += 1;
                        let path = std::env::temp_dir()
                            .join(format!("sccm-orders-{order_dump_count:03}.bin"));
                        let _ = std::fs::write(&path, &complete);
                        let preview: Vec<String> = complete
                            .iter()
                            .take(48)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        info!(
                            n = order_dump_count,
                            len = complete.len(),
                            path = %path.display(),
                            head = %preview.join(" "),
                            "first order streams — raw dump"
                        );
                    }
                    match orders.process_orders(&complete) {
                        Ok(outcome) => {
                            debug!(
                                orders = outcome.orders,
                                skipped = outcome.skipped,
                                "rendered drawing orders"
                            );
                            if let Some(r) = outcome.dirty {
                                frames += 1;
                                let region = order_region(orders.canvas(), r);
                                sink.on_graphics_update(orders.canvas(), region);
                            }
                        }
                        Err(e) => warn!(error = %e, "order stream decode failed"),
                    }
                }
                continue; // handled — do not pass to IronRDP
            }
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
                    warn!(?reason, frames, pdus, "RDP session terminated by server");
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
                    orders.resize(width, height);
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

/// Decode a Fast-Path frame and, if it carries a drawing-order update, return
/// the fragmentation flag and the order bytes. Returns None for any other
/// update type (bitmap/surface/pointer), which IronRDP handles.
fn decode_fastpath_orders(frame: &[u8]) -> Option<(Fragmentation, Vec<u8>)> {
    let mut cur = ReadCursor::new(frame);
    let _header = decode_cursor::<FastPathHeader>(&mut cur).ok()?;
    let update = decode_cursor::<FastPathUpdatePdu<'_>>(&mut cur).ok()?;
    if update.update_code != UpdateCode::Orders {
        return None;
    }
    Some((update.fragmentation, update.data.to_vec()))
}

/// Reassemble a possibly-fragmented order update. Returns the complete order
/// stream once a Single or Last fragment arrives.
fn reassemble_orders(
    buf: &mut Vec<u8>,
    active: &mut bool,
    frag: Fragmentation,
    data: Vec<u8>,
) -> Option<Vec<u8>> {
    match frag {
        Fragmentation::Single => Some(data),
        Fragmentation::First => {
            buf.clear();
            buf.extend_from_slice(&data);
            *active = true;
            None
        }
        Fragmentation::Next => {
            if *active {
                buf.extend_from_slice(&data);
            }
            None
        }
        Fragmentation::Last => {
            if *active {
                buf.extend_from_slice(&data);
                *active = false;
                Some(std::mem::take(buf))
            } else {
                None
            }
        }
    }
}

/// Convert an order-renderer dirty `Rect` (exclusive, i32) to an inclusive,
/// canvas-clamped `UpdateRegion`.
fn order_region(canvas: &OrderCanvas, r: sccm_rc_orders::Rect) -> UpdateRegion {
    let w = canvas.width() as i32;
    let h = canvas.height() as i32;
    let clampx = |v: i32| v.clamp(0, (w - 1).max(0)) as u16;
    let clampy = |v: i32| v.clamp(0, (h - 1).max(0)) as u16;
    UpdateRegion {
        left: clampx(r.x),
        top: clampy(r.y),
        right: clampx(r.right() - 1),
        bottom: clampy(r.bottom() - 1),
    }
}

/// Send an (empty) Persistent Bitmap Cache Key List PDU. mstscax sends a flood
/// of these right after ConfirmActive; a server that advertised expecting them
/// may withhold all graphics until it receives one. An empty list (zero
/// entries, FIRST|LAST) tells the server we have nothing cached, unblocking it.
async fn send_persistent_key_list(
    session: &mut SccmSession,
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
) -> Result<()> {
    // IronRDP can't encode ShareDataPdu::BitmapCachePersistentList (it's a
    // decode-only raw variant), so build the Share Data PDU bytes by hand,
    // matching IronRDP's framing exactly (Share Control Header 10 bytes incl.
    // shareId + Share Data Header 8 bytes + body).
    let mut out = WriteBuf::new();
    ironrdp_connector::legacy::encode_send_data_request(
        user_channel_id,
        io_channel_id,
        &PersistentKeyListPdu {
            pdu_source: user_channel_id,
            share_id,
        },
        &mut out,
    )
    .map_err(|e| Error::Protocol(format!("encode persistent key list: {e}")))?;
    session.send_rdp(out.filled()).await?;
    info!(share_id, "sent empty persistent bitmap cache key list");
    Ok(())
}

/// An empty TS_BITMAPCACHE_PERSISTENT_LIST_PDU (MS-RDPBCGR 2.2.1.17.1) wrapped
/// in a Share Control + Share Data header. Encoded by hand because IronRDP's
/// `ShareDataPdu::BitmapCachePersistentList` is decode-only.
struct PersistentKeyListPdu {
    pdu_source: u16,
    share_id: u32,
}

impl ironrdp_core::Encode for PersistentKeyListPdu {
    fn encode(&self, dst: &mut ironrdp_core::WriteCursor<'_>) -> ironrdp_core::EncodeResult<()> {
        // Body: numEntriesCache0..4 (5xu16=0), totalEntriesCache0..4 (5xu16=0),
        // bBitMask = PERSIST_FIRST_PDU|PERSIST_LAST_PDU (0x03), Pad2(1), Pad3(2).
        const BODY_LEN: usize = 24;
        // Share Control Header (10 bytes: totalLength, pduType, pduSource, shareId).
        dst.write_u16((18 + BODY_LEN) as u16); // totalLength = control(10)+data(8)+body
        dst.write_u16(0x10 | 0x07); // PROTOCOL_VERSION | PDUTYPE_DATAPDU
        dst.write_u16(self.pdu_source);
        dst.write_u32(self.share_id);
        // Share Data Header (8 bytes).
        dst.write_u8(0); // pad1
        dst.write_u8(2); // streamId = STREAM_MED
        dst.write_u16((BODY_LEN + 4) as u16); // uncompressedLength = body + pduType2+comp+compLen
        dst.write_u8(0x2b); // pduType2 = PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST
        dst.write_u8(0); // compressionFlags
        dst.write_u16(0); // compressedLength
        // Body.
        let mut body = [0u8; BODY_LEN];
        body[20] = 0x03; // bBitMask = PERSIST_FIRST_PDU | PERSIST_LAST_PDU
        dst.write_slice(&body);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "PersistentKeyListPdu"
    }

    fn size(&self) -> usize {
        18 + 24
    }
}

/// Tell the server to (re)send display updates, then force a full repaint.
/// Sends a Suppress Output PDU with allowDisplayUpdates=ALLOW for the whole
/// desktop, followed by a Refresh Rect. Some servers won't paint until the
/// client explicitly allows output.
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
    use ironrdp_pdu::rdp::suppress_output::SuppressOutputPdu;

    let full = InclusiveRectangle {
        left: 0,
        top: 0,
        right: width.saturating_sub(1),
        bottom: height.saturating_sub(1),
    };

    // 1. Allow display updates for the whole desktop.
    let allow = ShareDataPdu::SuppressOutput(SuppressOutputPdu {
        desktop_rect: Some(full.clone()),
    });
    let mut out = WriteBuf::new();
    ironrdp_connector::legacy::encode_share_data(user_channel_id, io_channel_id, share_id, allow, &mut out)
        .map_err(|e| Error::Protocol(format!("encode suppress-output: {e}")))?;
    session.send_rdp(out.filled()).await?;

    // 2. Refresh the whole desktop.
    let refresh = ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
        areas_to_refresh: vec![full],
    });
    let mut out2 = WriteBuf::new();
    ironrdp_connector::legacy::encode_share_data(user_channel_id, io_channel_id, share_id, refresh, &mut out2)
        .map_err(|e| Error::Protocol(format!("encode refresh rect: {e}")))?;
    session.send_rdp(out2.filled()).await?;

    debug!(width, height, share_id, "sent allow-output + refresh-rect");
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
    fn on_graphics_update(&mut self, image: &dyn FrameView, region: UpdateRegion) {
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
    fn on_graphics_update(&mut self, image: &dyn FrameView, _region: UpdateRegion) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap order bytes in a real Fast-Path Orders update frame
    /// (FastPathHeader + FastPathUpdatePdu, Single fragment, no compression).
    fn fastpath_orders_frame(order_data: &[u8]) -> Vec<u8> {
        let pdu_len = 1 /* updateHeader */ + 2 /* size */ + order_data.len();
        let total = 1 /* fp header */ + 1 /* per length */ + pdu_len;
        assert!(total < 0x80, "test helper only supports short frames");
        let mut f = vec![0x00u8, total as u8, 0x00];
        f.extend_from_slice(&(order_data.len() as u16).to_le_bytes());
        f.extend_from_slice(order_data);
        f
    }

    #[test]
    fn decode_fastpath_orders_extracts_order_bytes() {
        // numberOrders=1 + an OpaqueRect order.
        let order_data = [
            0x01, 0x00, // numberOrders
            0x09, 0x0A, 0x7F, 10, 0, 20, 0, 30, 0, 40, 0, 0x11, 0x22, 0x33,
        ];
        let frame = fastpath_orders_frame(&order_data);
        let (frag, data) = decode_fastpath_orders(&frame).expect("orders update");
        assert_eq!(frag, Fragmentation::Single);
        assert_eq!(data, order_data);
    }

    #[test]
    fn non_order_fastpath_returns_none() {
        // updateCode = 1 (Bitmap), not Orders.
        let mut frame = vec![0x00u8, 0x05, 0x01];
        frame.extend_from_slice(&0u16.to_le_bytes());
        assert!(decode_fastpath_orders(&frame).is_none());
    }

    #[test]
    fn reassemble_orders_joins_fragments() {
        let mut buf = Vec::new();
        let mut active = false;
        assert_eq!(
            reassemble_orders(&mut buf, &mut active, Fragmentation::First, vec![1, 2]),
            None
        );
        assert_eq!(
            reassemble_orders(&mut buf, &mut active, Fragmentation::Next, vec![3]),
            None
        );
        assert_eq!(
            reassemble_orders(&mut buf, &mut active, Fragmentation::Last, vec![4, 5]),
            Some(vec![1, 2, 3, 4, 5])
        );
        // A stray Last without a First is ignored.
        assert_eq!(
            reassemble_orders(&mut buf, &mut active, Fragmentation::Last, vec![9]),
            None
        );
    }

    #[test]
    fn order_region_clamps_to_canvas() {
        let canvas = OrderCanvas::new(100, 50);
        let r = sccm_rc_orders::Rect::new(-5, 10, 200, 200);
        let region = order_region(&canvas, r);
        assert_eq!(region.left, 0);
        assert_eq!(region.top, 10);
        assert_eq!(region.right, 99);
        assert_eq!(region.bottom, 49);
    }
}
