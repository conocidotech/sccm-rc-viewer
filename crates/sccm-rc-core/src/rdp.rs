//! Drive an IronRDP `ClientConnector` over the sealed SCCM channel.
//!
//! The RDP connection sequence (X.224 → MCS → security → capabilities →
//! finalization) is run sans-IO: IronRDP produces PDU bytes, we seal them
//! and send them through `SccmSession`; we receive sealed frames, unseal
//! them, and feed the RDP bytes back into IronRDP until it reaches the
//! `Connected` state.

use crate::{Grant, SccmSession};
use ironrdp_connector::connection_activation::{
    ConnectionActivationSequence, ConnectionActivationState,
};
use ironrdp_connector::State;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, Config, ConnectionResult, ConnectorError, Credentials,
    DesktopSize, Sequence,
};
use ironrdp_core::{decode_cursor, ReadCursor, WriteBuf};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::fast_path::{FastPathHeader, FastPathUpdatePdu, Fragmentation, UpdateCode};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::PerformanceFlags;
pub use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use sccm_rc_orders::{ColorDepth, OrderCanvas, OrderProcessor};
use sccm_rc_protocol::cliprdr::{self, ClipPdu};
use sccm_rc_protocol::mppc::MppcDecompressor;
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
pub fn sccm_rdp_config(
    width: u16,
    height: u16,
    monitors: Vec<ironrdp_pdu::gcc::Monitor>,
) -> Config {
    Config {
        desktop_size: DesktopSize { width, height },
        monitors,
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
        // RRCV-20 "All Screens": RdpCoreSccm on the TARGET reads bit 0x1000 of the
        // client's performanceFlags (CRDPWLC FUN_1007c22c) and, when set, writes
        // HKLM ...\SMS\Client\...\Remote Control\UseAllMonitors=1 so the desktop
        // encoder (CRDPWDUMXStack::SetDesktopParams) captures the FULL multi-monitor
        // geometry instead of only the primary. 0x1000 is unused by standard RDP
        // perf flags (max standard bit = 0x100), so this is the SCCM extension.
        // Gated behind SCCM_RC_ALLMON=1 (note: it persistently sets UseAllMonitors
        // in the target's HKLM, affecting future RC sessions too).
        performance_flags: if std::env::var("SCCM_RC_ALLMON").as_deref() == Ok("1") {
            PerformanceFlags::from_bits_retain(PerformanceFlags::default().bits() | 0x1000)
        } else {
            PerformanceFlags::default()
        },
        license_cache: None,
        timezone_info: Default::default(),
        enable_server_pointer: true,
        // #87 fix: when TRUE, ironrdp-session composites the cursor *into* our
        // framebuffer (`image.update_pointer`, fast_path.rs) — that is the grey
        // "blokje" baked into `frame.rgba`, and no `PointerBitmap` is emitted.
        // FALSE makes the session emit the cursor as a separate PointerBitmap/
        // Position/Hidden/Default update, which the viewer already draws as a
        // clean GPU cursor-quad at the live mouse position (main.rs render_gpu).
        // Override with `SCCM_RC_PTR_SW=1` to restore the old baking behaviour
        // (useful for an A/B live comparison of the cursor box).
        pointer_software_rendering: std::env::var("SCCM_RC_PTR_SW")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    }
}

fn whoami_user() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string())
}

/// Re-exported so the viewer can build a monitor layout without taking a direct
/// dependency on ironrdp-pdu.
pub use ironrdp_pdu::gcc::{Monitor, MonitorFlags};

/// Parse a `--monitor` geometry string `WIDTHxHEIGHT+LEFT+TOP` (e.g.
/// `1920x1080+0+0`; the `+LEFT+TOP` is optional and defaults to `+0+0`) into a
/// [`Monitor`] with inclusive right/bottom edges. `primary` marks it as the
/// layout's primary monitor.
pub fn parse_monitor(s: &str, primary: bool) -> Option<Monitor> {
    let (size, pos) = match s.split_once('+') {
        Some((sz, rest)) => (sz, Some(rest)),
        None => (s, None),
    };
    let (w, h) = size.split_once('x')?;
    let w: i32 = w.trim().parse().ok()?;
    let h: i32 = h.trim().parse().ok()?;
    if w <= 0 || h <= 0 {
        return None;
    }
    let (left, top) = match pos {
        Some(p) => {
            let (l, t) = p.split_once('+')?;
            (l.trim().parse().ok()?, t.trim().parse().ok()?)
        }
        None => (0, 0),
    };
    Some(Monitor {
        left,
        top,
        right: left + w - 1,
        bottom: top + h - 1,
        flags: if primary {
            MonitorFlags::PRIMARY
        } else {
            MonitorFlags::empty()
        },
    })
}

/// Bounding-box size `(width, height)` of a monitor layout — the value the RDP
/// `desktop_size` must be set to when advertising the layout (else the server
/// silently drops the monitor block). `None` for an empty layout.
pub fn monitors_bounding_size(monitors: &[Monitor]) -> Option<(u16, u16)> {
    let left = monitors.iter().map(|m| m.left).min()?;
    let top = monitors.iter().map(|m| m.top).min()?;
    let right = monitors.iter().map(|m| m.right).max()?;
    let bottom = monitors.iter().map(|m| m.bottom).max()?;
    let w = (right - left + 1).clamp(1, u16::MAX as i32) as u16;
    let h = (bottom - top + 1).clamp(1, u16::MAX as i32) as u16;
    Some((w, h))
}

#[cfg(test)]
mod monitor_tests {
    use super::{monitors_bounding_size, parse_monitor, MonitorFlags};

    #[test]
    fn monitor_layout_parses_and_bboxes() {
        let m0 = parse_monitor("1920x1080+0+0", true).unwrap();
        let m1 = parse_monitor("1280x1024+1920+0", false).unwrap();
        assert_eq!((m0.right, m0.bottom), (1919, 1079));
        assert!(m0.flags.contains(MonitorFlags::PRIMARY));
        assert!(!m1.flags.contains(MonitorFlags::PRIMARY));
        assert_eq!(m1.left, 1920);
        // Bounding box spans both side-by-side monitors.
        assert_eq!(monitors_bounding_size(&[m0, m1]), Some((3200, 1080)));
        assert_eq!(monitors_bounding_size(&[]), None);
        // Defaulted origin + rejected garbage.
        assert_eq!(parse_monitor("800x600", false).unwrap().left, 0);
        assert!(parse_monitor("garbage", true).is_none());
        assert!(parse_monitor("0x600", true).is_none());
    }
}

fn map_err(e: ConnectorError) -> Error {
    Error::Protocol(format!("ironrdp: {e}"))
}

/// The SCCM RC server's reactivation DemandActive carries a Bitmap Cache Rev2
/// capability whose body is 24 bytes (it omits the 12-byte trailing pad).
/// IronRDP's decoder requires the full 36-byte fixed part and errors. Pad any
/// short Rev2 cap (type 0x13) up to a 36-byte body with zeros, fixing every
/// enclosing length field (cap length, lengthCombinedCapabilities, share
/// control totalLength, MCS per-length, TPKT length).
fn fix_short_bitmap_cache_rev2(frame: &[u8]) -> Option<Vec<u8>> {
    const REV2_TYPE: u16 = 0x13;
    const REV2_FULL_BODY: usize = 36;
    if frame.len() < 15 || frame[0] != 0x03 {
        return None; // not a TPKT frame
    }
    // TPKT(4) + X224(3) + MCS SendDataIndication header.
    if frame[7] != 0x68 {
        return None; // not a SendDataIndication
    }
    // per-length of the MCS user data at offset 13.
    let (mcs_len_off, mcs_user_off) = if frame[13] & 0x80 != 0 {
        (13usize, 15usize)
    } else {
        (13, 14)
    };
    // Share Control Header at mcs_user_off: totalLength(2), pduType(2), src(2).
    let sc = mcs_user_off;
    let pdu_type = u16::from_le_bytes([frame[sc + 2], frame[sc + 3]]);
    if pdu_type & 0x0f != 0x01 {
        return None; // not a DemandActive
    }
    // DemandActive: shareId(4), lenSrcDesc(2), lenCombCaps(2), srcDesc, numCaps(2), pad(2)
    let da = sc + 6;
    let len_src = u16::from_le_bytes([frame[da + 4], frame[da + 5]]) as usize;
    let lcc_off = da + 6; // lengthCombinedCapabilities field
    let num_caps_off = da + 8 + len_src;
    let num_caps = u16::from_le_bytes([frame[num_caps_off], frame[num_caps_off + 1]]) as usize;
    let mut p = num_caps_off + 4; // skip numCaps(2)+pad(2)

    for _ in 0..num_caps {
        if p + 4 > frame.len() {
            return None;
        }
        let ctype = u16::from_le_bytes([frame[p], frame[p + 1]]);
        let clen = u16::from_le_bytes([frame[p + 2], frame[p + 3]]) as usize;
        if ctype == REV2_TYPE && clen < REV2_FULL_BODY + 4 {
            let pad = (REV2_FULL_BODY + 4) - clen; // bytes to add
            let mut out = Vec::with_capacity(frame.len() + pad);
            out.extend_from_slice(&frame[..p + clen]); // up to end of short cap body
            out.extend(std::iter::repeat_n(0u8, pad)); // pad the cap body
            out.extend_from_slice(&frame[p + clen..]); // rest of frame
                                                       // Patch lengths (+pad).
            let new_cap_len = (clen + pad) as u16;
            out[p + 2..p + 4].copy_from_slice(&new_cap_len.to_le_bytes());
            let lcc = u16::from_le_bytes([out[lcc_off], out[lcc_off + 1]]) + pad as u16;
            out[lcc_off..lcc_off + 2].copy_from_slice(&lcc.to_le_bytes());
            let tot = u16::from_le_bytes([out[sc], out[sc + 1]]) + pad as u16;
            out[sc..sc + 2].copy_from_slice(&tot.to_le_bytes());
            // MCS per-length (2-byte form, high bit set).
            if frame[13] & 0x80 != 0 {
                let mcs = (((frame[mcs_len_off] as usize & 0x7f) << 8)
                    | frame[mcs_len_off + 1] as usize)
                    + pad;
                out[mcs_len_off] = 0x80 | ((mcs >> 8) as u8);
                out[mcs_len_off + 1] = (mcs & 0xff) as u8;
            }
            // TPKT length (big-endian u16).
            let tpkt = u16::from_be_bytes([frame[2], frame[3]]) + pad as u16;
            out[2..4].copy_from_slice(&tpkt.to_be_bytes());
            return Some(out);
        }
        p += clen;
    }
    None
}

/// Decode the server's DemandActive frame and log its source descriptor and
/// every capability set (full Debug). Used for byte-level RE: comparing what
/// the server advertises/expects against what our ConfirmActive sends.
fn log_demand_active(frame: &[u8]) {
    use ironrdp_pdu::rdp::headers::ShareControlPdu;
    let Ok(send) = ironrdp_connector::legacy::decode_send_data_indication(frame) else {
        warn!("dump-caps: could not decode SendDataIndication");
        return;
    };
    let Ok(sc) = ironrdp_connector::legacy::decode_share_control(send) else {
        warn!("dump-caps: could not decode ShareControl");
        return;
    };
    if let ShareControlPdu::ServerDemandActive(da) = sc.pdu {
        info!(
            source = %da.pdu.source_descriptor,
            count = da.pdu.capability_sets.len(),
            "=== server DemandActive capability sets ==="
        );
        for cap in &da.pdu.capability_sets {
            info!("  server cap: {cap:?}");
        }
    } else {
        warn!(pdu = ?sc.pdu, "dump-caps: frame was not a ServerDemandActive");
    }
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
            name: ironrdp_pdu::gcc::ChannelName::from_utf8(name)
                .expect("valid 8-char channel name"),
        }
    }
}

ironrdp_svc::impl_as_any!(PassiveChannel);

impl ironrdp_svc::SvcProcessor for PassiveChannel {
    fn channel_name(&self) -> ironrdp_pdu::gcc::ChannelName {
        self.name.clone()
    }
    fn process(&mut self, payload: &[u8]) -> ironrdp_pdu::PduResult<Vec<ironrdp_svc::SvcMessage>> {
        // EGFX spike: surface anything the server sends on a passive channel. For
        // "drdynvc", an inbound PDU whose header high-nibble (Cmd) is 0x5 is a
        // DYNVC CAPABILITY_REQUEST — proof the server supports dynamic channels
        // (the prerequisite for the RDPEGFX/H.264 graphics pipeline).
        if !payload.is_empty() && std::env::var("SCCM_RC_DBG_DVC").is_ok() {
            let name = self.name.as_bytes();
            let name = String::from_utf8_lossy(name);
            let cmd = payload[0] >> 4;
            let cmd_str = match cmd {
                0x01 => "CREATE",
                0x02 => "DATA_FIRST",
                0x03 => "DATA",
                0x04 => "CLOSE",
                0x05 => "CAPABILITY_REQUEST",
                0x06 => "DATA_FIRST_COMPRESSED",
                0x07 => "DATA_COMPRESSED",
                0x08 => "SOFT_SYNC_REQUEST",
                _ => "?",
            };
            let head = &payload[..payload.len().min(16)];
            tracing::warn!(
                "DVC dbg: channel={:?} len={} cmd=0x{:x}({}) head={:02x?}",
                name,
                payload.len(),
                cmd,
                cmd_str,
                head
            );
        }
        // RRCV-20 capture: dump the FULL inbound payload of a control channel
        // (e.g. dskcfg = monitor config) as hex, so the on-wire monitor-list /
        // monitor-select message can be reverse-engineered. SCCM_RC_DBG_DSKCFG=1
        // (or a comma-list of channel names) selects which channels to dump.
        if !payload.is_empty() {
            if let Ok(want) = std::env::var("SCCM_RC_DBG_DSKCFG") {
                let name = String::from_utf8_lossy(self.name.as_bytes())
                    .trim_end_matches('\0')
                    .to_string();
                let dump = want == "1" || want.split(',').any(|w| w.trim() == name);
                if dump {
                    let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
                    tracing::warn!(channel = %name, len = payload.len(), "passive-channel inbound hex: {hex}");
                }
            }
        }
        Ok(Vec::new())
    }
}

impl ironrdp_svc::SvcClientProcessor for PassiveChannel {}

/// The SCCM RC session-arbitration static virtual channel ("sessarb"). The
/// server withholds the shadow-attach (and thus all graphics) until the client
/// arbitrates the session over this channel. RE of RdpCoreSccm.dll: the event
/// is a 16-byte payload `[u32 tag=2][u32 len=16][u32 eventType][u32 arg2]`.
/// We log every byte the server sends back (its Host Allowed/Idle/InUse/Denied).
#[derive(Debug, Default)]
pub struct ArbitrationChannel {
    replies_sent: u32,
    takeover_sent: bool,
}

impl ArbitrationChannel {
    /// Build the 16-byte arbitration event payload.
    pub fn event(event_type: u32, arg2: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&2u32.to_le_bytes()); // tag
        v.extend_from_slice(&16u32.to_le_bytes()); // length
        v.extend_from_slice(&event_type.to_le_bytes());
        v.extend_from_slice(&arg2.to_le_bytes());
        v
    }

    /// Build the HostInUse take-over event (sessarb type 5). Same event family as
    /// `event` but carries the requesting client's machine name in a 512-wchar
    /// (1024-byte) zero-padded field; total length 1036. Reverse-engineered from
    /// CmRcViewer: when the server reports HostInUse(1), CmRcViewer sends this to
    /// take over the busy host, and the server then grants HostAllowed(4) and
    /// attaches the shadow. (IronRDP prepends the CHANNEL_PDU_HEADER.)
    pub fn takeover(client_name: &str) -> Vec<u8> {
        const TOTAL: usize = 1036;
        let mut v = vec![0u8; TOTAL];
        v[0..4].copy_from_slice(&2u32.to_le_bytes()); // tag
        v[4..8].copy_from_slice(&(TOTAL as u32).to_le_bytes()); // length
        v[8..12].copy_from_slice(&5u32.to_le_bytes()); // type = take-over
        for (i, u) in client_name.encode_utf16().enumerate() {
            let o = 12 + i * 2;
            if o + 2 <= TOTAL {
                v[o..o + 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        v
    }
}

ironrdp_svc::impl_as_any!(ArbitrationChannel);

impl ironrdp_svc::SvcProcessor for ArbitrationChannel {
    fn channel_name(&self) -> ironrdp_pdu::gcc::ChannelName {
        ironrdp_pdu::gcc::ChannelName::from_utf8("sessarb").expect("valid name")
    }
    fn process(&mut self, payload: &[u8]) -> ironrdp_pdu::PduResult<Vec<ironrdp_svc::SvcMessage>> {
        let hex: Vec<String> = payload
            .iter()
            .take(32)
            .map(|b| format!("{b:02x}"))
            .collect();
        let server_event = if payload.len() >= 12 {
            u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]])
        } else {
            0
        };
        info!(len = payload.len(), server_event, bytes = %hex.join(" "), "sessarb: server arbitration event");

        // HostInUse(1): the host has an active session/user. Take it over by
        // replaying CmRcViewer's type-5 event with our machine name; the server
        // then grants HostAllowed(4) and attaches the shadow. Gated by
        // SCCM_RC_TAKEOVER=1 (it forcibly takes over a busy host).
        if server_event == 1
            && !self.takeover_sent
            && std::env::var("SCCM_RC_TAKEOVER").as_deref() == Ok("1")
        {
            self.takeover_sent = true;
            let name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "RUSTCLIENT".to_string());
            info!(client = %name, "sessarb: HostInUse — sending take-over request (type 5)");
            return Ok(vec![ironrdp_svc::SvcMessage::from(
                ArbitrationChannel::takeover(&name),
            )]);
        }

        // Optionally send a follow-up event in response (SCCM_RC_ARB_REPLY=<type>),
        // once, to complete the arbitration handshake.
        if let Ok(reply) = std::env::var("SCCM_RC_ARB_REPLY") {
            if let Ok(reply_type) = reply.parse::<u32>() {
                if self.replies_sent == 0 {
                    self.replies_sent += 1;
                    info!(reply_type, "sessarb: sending follow-up arbitration event");
                    return Ok(vec![ironrdp_svc::SvcMessage::from(
                        ArbitrationChannel::event(reply_type, 0),
                    )]);
                }
            }
        }
        Ok(Vec::new())
    }
}

impl ironrdp_svc::SvcClientProcessor for ArbitrationChannel {}

/// Clipboard sharing over the `cliprdr` static virtual channel (MS-RDPECLIP),
/// text only. Reactive parts (handshake, remote→local paste, answering the
/// server's data requests) happen in `process`; the local→remote direction is
/// driven by the active loop polling `local_changed`. `known` is the last
/// clipboard text we are aware of — it suppresses echoing a value we just set
/// from the remote straight back to the server.
#[derive(Debug, Default)]
pub struct CliprdrChannel {
    known: Option<String>,
    /// A local file the operator offered to push to the remote (paste there).
    pending_file: Option<std::path::PathBuf>,
    /// True once the server sent CB_MONITOR_READY. Before that we must not send a
    /// FormatList (the periodic poll would otherwise announce out of sequence,
    /// which a strict server can drop — losing the local→remote path).
    ready: bool,
}

impl CliprdrChannel {
    fn read_local() -> Option<String> {
        clipboard_win::get_clipboard_string()
            .ok()
            .filter(|s| !s.is_empty())
    }

    fn write_local(&mut self, text: &str) {
        match clipboard_win::set_clipboard_string(text) {
            Ok(()) => {
                self.known = Some(text.to_string());
                info!(len = text.len(), "cliprdr: local clipboard set from remote");
            }
            Err(e) => warn!(error = %e, "cliprdr: failed to set local clipboard"),
        }
    }

    /// Build the Format List advertising what we currently offer (long format
    /// names): the local clipboard text and/or a pending file.
    fn format_list(&self) -> Vec<u8> {
        let mut formats: Vec<(u32, &str)> = Vec::new();
        if self.known.is_some() {
            formats.push((cliprdr::CF_UNICODETEXT, ""));
        }
        if self.pending_file.is_some() {
            formats.push((cliprdr::CF_FILEGROUPDESCRIPTORW, "FileGroupDescriptorW"));
        }
        cliprdr::format_list_long(&formats)
    }

    /// Offer a local file to the remote (the operator pastes it there). Returns
    /// the Format List PDU to send announcing it.
    pub fn offer_file(&mut self, path: std::path::PathBuf) -> Vec<u8> {
        info!(file = %path.display(), "cliprdr: offering file to remote");
        self.pending_file = Some(path);
        self.format_list()
    }

    fn file_name_size(&self) -> Option<(String, u64)> {
        let p = self.pending_file.as_ref()?;
        let name = p.file_name()?.to_string_lossy().into_owned();
        let size = std::fs::metadata(p).ok()?.len();
        Some((name, size))
    }

    fn read_range(&self, pos: u64, len: usize) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let p = self.pending_file.as_ref()?;
        let mut f = std::fs::File::open(p).ok()?;
        f.seek(SeekFrom::Start(pos)).ok()?;
        let mut buf = vec![0u8; len.min(8 * 1024 * 1024)];
        let n = f.read(&mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Called periodically by the active loop. If the local OS clipboard text
    /// changed (and it isn't a value we just received from the remote), returns
    /// a Format List PDU announcing it to the server.
    pub fn local_changed(&mut self) -> Option<Vec<u8>> {
        if !self.ready {
            return None; // CB_MONITOR_READY not seen yet — don't announce early.
        }
        let cur = Self::read_local();
        if cur != self.known {
            self.known = cur.clone();
            return Some(self.format_list());
        }
        None
    }

    fn msg(bytes: Vec<u8>) -> ironrdp_svc::SvcMessage {
        ironrdp_svc::SvcMessage::from(bytes)
    }
}

ironrdp_svc::impl_as_any!(CliprdrChannel);

impl ironrdp_svc::SvcProcessor for CliprdrChannel {
    fn channel_name(&self) -> ironrdp_pdu::gcc::ChannelName {
        ironrdp_pdu::gcc::ChannelName::from_utf8("cliprdr").expect("valid name")
    }

    fn process(&mut self, payload: &[u8]) -> ironrdp_pdu::PduResult<Vec<ironrdp_svc::SvcMessage>> {
        let Some(pdu) = cliprdr::parse(payload) else {
            return Ok(Vec::new());
        };
        match pdu {
            ClipPdu::MonitorReady => {
                // Handshake is up: future local changes may be announced, and the
                // format_list below already announces the current clipboard.
                self.ready = true;
                self.known = Self::read_local();
                info!(
                    has_text = self.known.is_some(),
                    "cliprdr: monitor ready — sending caps + format list"
                );
                Ok(vec![
                    Self::msg(cliprdr::capabilities_files()),
                    Self::msg(self.format_list()),
                ])
            }
            ClipPdu::Capabilities => Ok(Vec::new()),
            ClipPdu::FormatList { has_text } => {
                // Acknowledge, then pull the text so it lands on our clipboard.
                let mut out = vec![Self::msg(cliprdr::format_list_response_ok())];
                if has_text {
                    out.push(Self::msg(cliprdr::format_data_request(
                        cliprdr::CF_UNICODETEXT,
                    )));
                }
                Ok(out)
            }
            ClipPdu::FormatListResponse { .. } => Ok(Vec::new()),
            ClipPdu::FormatDataRequest { format_id } => {
                // The remote pastes — wants our text or our offered file's descriptor.
                if format_id == cliprdr::CF_FILEGROUPDESCRIPTORW {
                    if let Some((name, size)) = self.file_name_size() {
                        return Ok(vec![Self::msg(cliprdr::format_data_response_bytes(
                            &cliprdr::file_group_descriptor(&name, size),
                        ))]);
                    }
                } else if format_id == cliprdr::CF_UNICODETEXT || format_id == 1 {
                    if let Some(t) = Self::read_local() {
                        return Ok(vec![Self::msg(cliprdr::format_data_response_text(&t))]);
                    }
                }
                Ok(vec![Self::msg(cliprdr::format_data_response_fail())])
            }
            ClipPdu::FileContentsRequest {
                stream_id,
                lindex: _,
                size_only,
                position,
                requested,
            } => {
                if size_only {
                    if let Some((_, size)) = self.file_name_size() {
                        return Ok(vec![Self::msg(cliprdr::file_contents_response_size(
                            stream_id, size,
                        ))]);
                    }
                } else if let Some(bytes) = self.read_range(position, requested as usize) {
                    return Ok(vec![Self::msg(cliprdr::file_contents_response_range(
                        stream_id, &bytes,
                    ))]);
                }
                Ok(vec![Self::msg(cliprdr::file_contents_response_fail(
                    stream_id,
                ))])
            }
            ClipPdu::FormatDataResponse { ok, text } => {
                if ok {
                    if let Some(t) = text {
                        if !t.is_empty() {
                            self.write_local(&t);
                        }
                    }
                }
                Ok(Vec::new())
            }
            ClipPdu::Other { msg_type } => {
                debug!(msg_type, "cliprdr: unhandled message");
                Ok(Vec::new())
            }
        }
    }
}

impl ironrdp_svc::SvcClientProcessor for CliprdrChannel {}

/// Curtain (privacy) static virtual channel ("curtain"). Enabling it makes the
/// SCCM server BOTH blank the remote machine's physical screen AND block the
/// console's local keyboard/mouse (`USER32!BlockInput`, policy-gated) — the two
/// are one operation in `CRDPENCWin32DesktopProxy::EnableCurtainInternal`. So
/// curtain == privacy screen-blank + remote-input lock. Disable restores both.
///
/// Wire format reverse-engineered from RdpCoreSccm `CRDPWLCCurtainVC`
/// (FUN_1009649d builds the payload, FUN_100961f3/FUN_10096277 pick the type):
/// the WLC event envelope `[u32 fieldCount][u32 byteLen][fields…]` — same family
/// as sessarb's `[2][16][type][arg]`. Curtain uses fieldCount=1, byteLen=12, one
/// field = the type: ENABLE = 4|5 (4 + (arg>=0)), DISABLE = 6|7. Defaults 5/6;
/// overridable via SCCM_RC_CURTAIN_ON / SCCM_RC_CURTAIN_OFF for live tuning.
#[derive(Debug, Default)]
pub struct CurtainChannel;

impl CurtainChannel {
    fn event(type_code: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&1u32.to_le_bytes()); // fieldCount
        v.extend_from_slice(&12u32.to_le_bytes()); // total byte length
        v.extend_from_slice(&type_code.to_le_bytes());
        v
    }
    fn env_type(var: &str, default: u32) -> u32 {
        std::env::var(var)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    }
    pub fn enable() -> Vec<u8> {
        Self::event(Self::env_type("SCCM_RC_CURTAIN_ON", 5))
    }
    pub fn disable() -> Vec<u8> {
        Self::event(Self::env_type("SCCM_RC_CURTAIN_OFF", 6))
    }
}

ironrdp_svc::impl_as_any!(CurtainChannel);

impl ironrdp_svc::SvcProcessor for CurtainChannel {
    fn channel_name(&self) -> ironrdp_pdu::gcc::ChannelName {
        ironrdp_pdu::gcc::ChannelName::from_utf8("curtain").expect("valid name")
    }
    fn process(&mut self, payload: &[u8]) -> ironrdp_pdu::PduResult<Vec<ironrdp_svc::SvcMessage>> {
        if !payload.is_empty() && std::env::var("SCCM_RC_DBG_DVC").is_ok() {
            tracing::warn!(
                "curtain: server payload {:02x?}",
                &payload[..payload.len().min(24)]
            );
        }
        Ok(Vec::new())
    }
}

impl ironrdp_svc::SvcClientProcessor for CurtainChannel {}

/// Run the full RDP connection sequence over the established SCCM session.
/// Returns the negotiated connection result on success.
pub async fn connect_rdp(
    session: &mut SccmSession,
    width: u16,
    height: u16,
    monitors: &[ironrdp_pdu::gcc::Monitor],
) -> Result<(ConnectionResult, Vec<u8>, u32)> {
    if session.grant() == Grant::ViewOnly {
        debug!("session is view-only — input will be rejected by the server");
    }

    let config = sccm_rdp_config(width, height, monitors.to_vec());
    // Client address is only used to fill the Client Info PDU; a placeholder
    // is fine since the real transport is our sealed channel.
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut connector = ClientConnector::new(config, client_addr);
    // Declare mstscax-like static virtual channels (SCCM_RC_CHANNELS=1). The
    // server seems to require them before it reactivates + paints.
    // The SCCM RC session-arbitration channel (SCCM_RC_ARB=1). Required for the
    // server to attach the shadow. We declare the full WLC static virtual channel
    // set in the EXACT order the real CmRcViewer advertises it (captured
    // 2026-06-03): rdpdr, rdpsnd, cliprdr, curtain, sessarb, dynres, dskcfg,
    // drdynvc — with sessarb being our active ArbitrationChannel. The server
    // assigns MCS ids 03ec..03f3 to these in this order.
    if std::env::var("SCCM_RC_ARB").as_deref() == Ok("1") {
        connector = connector.with_static_channel(PassiveChannel::new("rdpdr"));
        connector = connector.with_static_channel(PassiveChannel::new("rdpsnd"));
        // Real clipboard channel (SCCM_RC_CLIP=1) — a DISTINCT type so it actually
        // survives in the StaticChannelSet (which is keyed by TypeId; all the
        // PassiveChannel siblings collide and only the last is kept). Otherwise a
        // passive placeholder, matching the proven default path.
        if std::env::var("SCCM_RC_CLIP").as_deref() == Ok("1") {
            connector = connector.with_static_channel(CliprdrChannel::default());
        } else {
            connector = connector.with_static_channel(PassiveChannel::new("cliprdr"));
        }
        // Curtain (privacy screen-blank) — real distinct-type channel when
        // SCCM_RC_CURTAIN=1, else a passive placeholder.
        if std::env::var("SCCM_RC_CURTAIN").as_deref() == Ok("1") {
            connector = connector.with_static_channel(CurtainChannel);
        } else {
            connector = connector.with_static_channel(PassiveChannel::new("curtain"));
        }
        connector = connector.with_static_channel(ArbitrationChannel::default());
        connector = connector.with_static_channel(PassiveChannel::new("dynres"));
        connector = connector.with_static_channel(PassiveChannel::new("dskcfg"));
        connector = connector.with_static_channel(PassiveChannel::new("drdynvc"));
        info!("declared WLC channels (mstscax order): rdpdr,rdpsnd,cliprdr,curtain,sessarb,dynres,dskcfg,drdynvc");
    } else if std::env::var("SCCM_RC_CHANNELS").as_deref() == Ok("1") {
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
                match hint
                    .find_size(&input_buf)
                    .map_err(|e| Error::Protocol(format!("pdu hint: {e}")))?
                {
                    Some((_matches, size)) => break size,
                    None => {
                        let more = session.recv_rdp().await?.ok_or_else(|| {
                            Error::Protocol("server closed during RDP connect".into())
                        })?;
                        input_buf.extend_from_slice(&more);
                    }
                }
            };
            let pdu: Vec<u8> = input_buf.drain(..pdu_len).collect();
            debug!(
                state = connector.state.name(),
                pdu_len, "RDP step (with input)"
            );
            if share_id == 0 {
                if let Some(sid) = ironrdp_connector::legacy::frame_share_id(&pdu) {
                    share_id = sid;
                    debug!(share_id, "captured server share_id from DemandActive");
                    if std::env::var("SCCM_RC_DUMP_CAPS").as_deref() == Ok("1") {
                        log_demand_active(&pdu);
                    }
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

/// A unified RGBA32 framebuffer that composites both graphics sources. The SCCM
/// RC server paints some regions via drawing orders (our `OrderCanvas`) and
/// others via bitmap/surface updates (IronRDP's `DecodedImage`); each writes its
/// own buffer. We blit every dirty region from whichever source produced it into
/// this composite so the sink always sees the complete desktop.
pub struct CompositeFrame {
    data: Vec<u8>,
    width: u16,
    height: u16,
}

impl CompositeFrame {
    fn new(width: u16, height: u16) -> Self {
        Self {
            data: vec![0u8; width as usize * height as usize * 4],
            width,
            height,
        }
    }

    fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.data = vec![0u8; width as usize * height as usize * 4];
    }

    /// Copy the pixels in `region` (inclusive) from `src` into the composite.
    fn blit(&mut self, src: &dyn FrameView, region: UpdateRegion) {
        if src.width() != self.width || src.height() != self.height {
            return; // size mismatch (mid-reactivation); skip this update
        }
        let w = self.width as usize;
        let right = (region.right as usize).min(w.saturating_sub(1));
        let bottom = (region.bottom as usize).min((self.height as usize).saturating_sub(1));
        let left = (region.left as usize).min(right);
        let top = (region.top as usize).min(bottom);
        let src = src.data();
        for y in top..=bottom {
            let row = y * w * 4;
            let a = row + left * 4;
            let b = row + (right + 1) * 4;
            if b <= self.data.len() && b <= src.len() {
                self.data[a..b].copy_from_slice(&src[a..b]);
            }
        }
    }
}

impl FrameView for CompositeFrame {
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn width(&self) -> u16 {
        self.width
    }
    fn height(&self) -> u16 {
        self.height
    }
}

/// A mouse-cursor image (RGBA32, top-down) plus its hotspot, for client-side
/// cursor rendering (drawn at the local mouse position so it tracks instantly).
pub struct PointerImage {
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub rgba: Vec<u8>,
}

/// A change to the remote mouse cursor.
pub enum PointerUpdate {
    /// New cursor shape.
    Bitmap(PointerImage),
    /// Cursor hidden (e.g. text caret / no pointer).
    Hidden,
    /// Reset to the default system arrow.
    SystemDefault,
}

/// Callbacks for an active RDP session: receive framebuffer updates.
/// Periodic live-session statistics for the viewer's diagnostics readout.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionStats {
    /// Inbound (sealed) bytes/second over the last interval.
    pub bytes_per_sec: u64,
}

pub trait SessionSink: Send {
    /// Called when a region of the framebuffer changed. `frame` is the full
    /// RGBA framebuffer (either IronRDP's or the order renderer's); `region` is
    /// the dirty rectangle.
    fn on_graphics_update(&mut self, frame: &dyn FrameView, region: UpdateRegion);
    /// Called when the remote cursor shape/visibility changes. Default: ignore.
    fn on_pointer(&mut self, _update: PointerUpdate) {}
    /// Called ~once per second with live session statistics. Default: ignore.
    fn on_stats(&mut self, _stats: SessionStats) {}
    /// Connection-progress phase (shown until the first frame paints). Default: ignore.
    fn on_status(&mut self, _status: &str) {}
    /// Called when the session ends.
    fn on_terminate(&mut self, reason: String);
}

/// Run the active RDP session loop: read PDUs from the sealed channel, feed
/// them to IronRDP's `ActiveStage`, send response frames back, surface
/// graphics updates to the sink, and forward UI input. Returns when the
/// session ends.
#[allow(clippy::too_many_arguments)]
pub async fn run_active_session(
    session: &mut SccmSession,
    connection_result: ConnectionResult,
    initial_buf: Vec<u8>,
    initial_share_id: u32,
    sink: &mut dyn SessionSink,
    input_rx: &mut InputReceiver,
    curtain_on: std::sync::Arc<std::sync::atomic::AtomicBool>,
    file_offer: std::sync::Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
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
    // Unified framebuffer compositing the order renderer and IronRDP's bitmap/
    // surface output, so the sink always sees the complete desktop.
    let mut composite = CompositeFrame::new(width, height);
    // Bulk decompressor for the server's compressed fast-path stream (when
    // SCCM_RC_COMPRESS=1). Stateful: the 64K history persists across updates.
    let mut decomp = MppcDecompressor::new();
    // A single compressed fast-path PDU can carry several update structures; we
    // decompress them all at once (to keep the shared MPPC history in sync) and
    // process the first now, queueing the rest (already uncompressed) here to be
    // fed back through the per-update processing on the next loop iterations.
    let mut decompressed_extra: std::collections::VecDeque<Vec<u8>> =
        std::collections::VecDeque::new();
    // Clipboard sharing (SCCM_RC_CLIP=1): poll the local OS clipboard on a timer
    // and announce changes to the server (the local→remote direction). The
    // remote→local direction and request-answering are reactive in CliprdrChannel.
    let clip_enabled = std::env::var("SCCM_RC_CLIP").as_deref() == Ok("1");
    let mut last_clip_poll = std::time::Instant::now();
    // Curtain (privacy) — send enable/disable on the "curtain" channel when the
    // viewer toggles `curtain_on` (only when the real channel is registered).
    let curtain_enabled = std::env::var("SCCM_RC_CURTAIN").as_deref() == Ok("1");
    let mut curtain_applied = false;
    // Live bandwidth stats for the viewer toolbar (emitted ~1/sec).
    let mut stats_bytes: u64 = 0;
    let mut stats_last = std::time::Instant::now();
    // Cursor-trail cleanup (SCCM_RC_CURSOR_REFRESH, default on): the server bakes
    // the shadowed software cursor into the desktop tiles and never erases old
    // positions → a trail of cursor stamps. We accumulate the desktop rect the
    // cursor has passed through (from mouse input) and ask the server to re-send
    // it (cursor-free background) ~8x/sec.
    let cursor_refresh = std::env::var("SCCM_RC_CURSOR_REFRESH").as_deref() != Ok("0");
    let mut cursor_trail: Option<(u16, u16, u16, u16)> = None;
    let mut last_cursor_refresh = std::time::Instant::now();
    const CURSOR_PAD: u16 = 48; // half-extent of the area to refresh around a point
                                // Coalesce graphics updates: every order/bitmap update blits into `composite`
                                // immediately (cheap region copy) but accumulates one union dirty rect that is
                                // pushed to the sink at most ~60x/s — collapsing a burst of small updates into
                                // a single sink copy + redraw instead of dozens.
    let mut pending: Option<UpdateRegion> = None;
    let mut last_flush = std::time::Instant::now();
    // Profiling (SCCM_RC_PROFILE=1): where does the time go — waiting on the
    // network, or rendering? Accumulated and logged every ~2s.
    let profile = std::env::var("SCCM_RC_PROFILE").as_deref() == Ok("1");
    let mut prof_last = std::time::Instant::now();
    let mut p_proc = std::time::Duration::ZERO;
    let (mut p_bytes, mut p_frames, mut p_orders) = (0u64, 0u64, 0u64);
    let mut order_frag: Vec<u8> = Vec::new();
    let mut order_frag_active = false;
    // Dump the first few complete order streams raw, for offline verification
    // of cache-bitmap encoding / compression-header assumptions.
    let mut order_dump_count = 0u32;
    // Diagnostic env flags, read ONCE here (not per-PDU in the hot loop).
    // OFF by default: order streams contain remote-desktop drawing data, so we
    // never write them to %TEMP% unless explicitly enabled. SCCM_RC_DUMP_ORDERS=N
    // dumps the first N streams (offline replay/debug only).
    let order_dump_cap: u32 = std::env::var("SCCM_RC_DUMP_ORDERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let force_paint = std::env::var("SCCM_RC_FORCE_PAINT").as_deref() == Ok("1");
    // Order-stream decode-failure tracking. A handful of genuinely unsupported
    // orders is fine, but a sustained run of failures means the order stream has
    // desynced (e.g. the stateful MPPC history diverged and now decompresses to
    // garbage) — which never self-heals, so the picture freezes. We bail and let
    // the reconnect loop rebuild the session (resetting MPPC/order state).
    //
    // A desynced stream yields a MIX of Err and the odd stray Ok, so a hard
    // reset-to-0 on every success could keep the streak pinned below the limit
    // forever. Instead the streak is only cleared after ORDER_OK_RESET
    // *consecutive* clean streams; sporadic single successes never reach that,
    // so the streak still climbs to ORDER_FAIL_RECONNECT and triggers recovery.
    let mut order_fail_streak = 0u32;
    let mut order_ok_streak = 0u32;
    const ORDER_FAIL_RECONNECT: u32 = 60;
    const ORDER_OK_RESET: u32 = 8;

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

    // SCCM RC session arbitration: send the arbitration request event over the
    // "sessarb" channel so the server attaches the shadow. Event type is
    // configurable (SCCM_RC_ARB_EVENT, default 1) while we determine which one
    // the real client sends to initiate.
    sink.on_status("Sessie koppelen...");
    // SCCM_RC_ARB_EVENT=0 → send nothing and just wait for the server's own
    // HostInUse/HostAllowed (the real CmRcViewer sends no initial event).
    if std::env::var("SCCM_RC_ARB").as_deref() == Ok("1")
        && std::env::var("SCCM_RC_ARB_EVENT").as_deref() != Ok("0")
    {
        let event_type: u32 = std::env::var("SCCM_RC_ARB_EVENT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let payload = ArbitrationChannel::event(event_type, 0);
        let msgs = ironrdp_svc::SvcProcessorMessages::<ArbitrationChannel>::new(vec![
            ironrdp_svc::SvcMessage::from(payload),
        ]);
        match stage.process_svc_processor_messages(msgs) {
            Ok(bytes) => {
                session.send_rdp(&bytes).await?;
                info!(
                    event_type,
                    sent = bytes.len(),
                    "sent sessarb arbitration event"
                );
            }
            Err(e) => warn!(error = %e, "failed to encode sessarb arbitration event"),
        }
    }

    // SCCM RC WLC desktop capability handshake (SCCM_RC_WLC=1). The MSTSC
    // capability envelope + control TLVs over the I/O channel are what make the
    // server begin desktop fast-path graphics. Sent both here (first activation)
    // and again after reactivation, mirroring the real CmRcViewer.
    if std::env::var("SCCM_RC_WLC").as_deref() == Ok("1") {
        send_wlc_desktop_caps(session, user_channel_id, io_channel_id).await?;
    }

    // Force an initial full-screen repaint. Without this, a static remote
    // desktop (e.g. locked / no user) sends nothing and the window stays blank.
    // (SCCM_RC_NO_REFRESH=1 skips it, to test whether the server auto-paints.)
    if std::env::var("SCCM_RC_NO_REFRESH").as_deref() != Ok("1") {
        info!(share_id, "initial repaint request");
        send_refresh_rect(
            session,
            user_channel_id,
            io_channel_id,
            share_id,
            width,
            height,
        )
        .await?;
    } else {
        info!("skipping initial refresh (SCCM_RC_NO_REFRESH=1)");
    }

    loop {
        // Either a network PDU arrives, or the UI sends input.
        // A queued, already-decompressed update (from a multi-update compressed
        // PDU) takes priority — process it before reading more from the network.
        let (frame, action) = if let Some(f) = decompressed_extra.pop_front() {
            (f, ironrdp_pdu::Action::FastPath)
        } else {
            // Drain any complete PDU already buffered before awaiting more.
            if ironrdp_pdu::find_size(&buf)
                .map_err(|e| Error::Protocol(format!("find_size: {e}")))?
                .is_none()
            {
                // Buffer drained — flush any accumulated graphics before we wait.
                if let Some(region) = pending.take() {
                    frames += 1;
                    sink.on_graphics_update(&composite, region);
                    last_flush = std::time::Instant::now();
                }
                tokio::select! {
                    biased;
                    events = input_rx.recv() => {
                        let Some(events) = events else { return Ok(()); }; // UI closed
                        // Track the desktop area the cursor passes through so we can
                        // erase the server's baked-in cursor stamps (the trail).
                        if cursor_refresh {
                            for ev in &events {
                                if let FastPathInputEvent::MouseEvent(m) = ev {
                                    let l = m.x_position.saturating_sub(CURSOR_PAD);
                                    let t = m.y_position.saturating_sub(CURSOR_PAD);
                                    let r = m.x_position.saturating_add(CURSOR_PAD).min(width.saturating_sub(1));
                                    let b = m.y_position.saturating_add(CURSOR_PAD).min(height.saturating_sub(1));
                                    cursor_trail = Some(match cursor_trail {
                                        Some((cl, ct, cr, cb)) => (cl.min(l), ct.min(t), cr.max(r), cb.max(b)),
                                        None => (l, t, r, b),
                                    });
                                }
                            }
                        }
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
                        // Refresh the trail ~8x/sec during continuous movement.
                        if cursor_refresh
                            && cursor_trail.is_some()
                            && last_cursor_refresh.elapsed() >= std::time::Duration::from_millis(120)
                        {
                            flush_cursor_trail(session, user_channel_id, io_channel_id, share_id, &mut cursor_trail, &mut last_cursor_refresh).await?;
                        }
                        continue;
                    }
                    // Movement stopped (no input/data for 120 ms) — do ONE full
                    // refresh to clear any residual cursor stamps the per-segment
                    // refreshes missed. Cheap: unchanged tiles come back as
                    // bitmap-cache MemBlts, only the cursor tiles are re-sent.
                    _ = tokio::time::sleep(std::time::Duration::from_millis(120)),
                        if cursor_refresh && cursor_trail.is_some() =>
                    {
                        cursor_trail = None;
                        last_cursor_refresh = std::time::Instant::now();
                        let full = ironrdp_pdu::geometry::InclusiveRectangle {
                            left: 0,
                            top: 0,
                            right: width.saturating_sub(1),
                            bottom: height.saturating_sub(1),
                        };
                        let _ = send_refresh_area(session, user_channel_id, io_channel_id, share_id, full).await;
                        continue;
                    }
                    more = session.recv_rdp() => {
                        match more? {
                            Some(b) => {
                                debug!(bytes = b.len(), "recv during active session");
                                p_bytes += b.len() as u64;
                                stats_bytes += b.len() as u64;
                                p_frames += 1;
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
            (frame, pdu_info.action)
        };
        pdus += 1;
        if pdus.is_multiple_of(200) {
            debug!(pdus, graphics_updates = frames, "session heartbeat");
        }
        // Emit live bandwidth stats to the sink ~once per second.
        if stats_last.elapsed() >= std::time::Duration::from_millis(1000) {
            let secs = stats_last.elapsed().as_secs_f64().max(0.001);
            sink.on_stats(SessionStats {
                bytes_per_sec: (stats_bytes as f64 / secs) as u64,
            });
            stats_bytes = 0;
            stats_last = std::time::Instant::now();
        }
        // Clipboard sharing: announce a local clipboard change to the server so
        // the remote can paste it. Throttled to keep OS-clipboard reads cheap.
        if clip_enabled && last_clip_poll.elapsed() >= std::time::Duration::from_millis(700) {
            last_clip_poll = std::time::Instant::now();
            let list = stage
                .get_svc_processor_mut::<CliprdrChannel>()
                .and_then(|c| c.local_changed());
            if let Some(list) = list {
                let msgs = ironrdp_svc::SvcProcessorMessages::<CliprdrChannel>::new(vec![
                    ironrdp_svc::SvcMessage::from(list),
                ]);
                match stage.process_svc_processor_messages(msgs) {
                    Ok(bytes) => {
                        session.send_rdp(&bytes).await?;
                        debug!("cliprdr: announced local clipboard change");
                    }
                    Err(e) => warn!(error = %e, "cliprdr: failed to encode format list"),
                }
            }
        }
        // File transfer: the operator picked a file to push to the remote. Offer
        // it on the cliprdr channel (the remote then pastes it).
        if clip_enabled {
            let path = file_offer.lock().unwrap().take();
            if let Some(path) = path {
                let list = stage
                    .get_svc_processor_mut::<CliprdrChannel>()
                    .map(|c| c.offer_file(path));
                if let Some(list) = list {
                    let msgs = ironrdp_svc::SvcProcessorMessages::<CliprdrChannel>::new(vec![
                        ironrdp_svc::SvcMessage::from(list),
                    ]);
                    match stage.process_svc_processor_messages(msgs) {
                        Ok(bytes) => {
                            session.send_rdp(&bytes).await?;
                            info!("cliprdr: announced file offer to remote");
                        }
                        Err(e) => warn!(error = %e, "cliprdr: failed to encode file offer"),
                    }
                }
            }
        }
        // Curtain: when the viewer toggles the privacy screen, send the matching
        // enable/disable event on the "curtain" channel.
        if curtain_enabled {
            let desired = curtain_on.load(std::sync::atomic::Ordering::Relaxed);
            if desired != curtain_applied {
                let payload = if desired {
                    CurtainChannel::enable()
                } else {
                    CurtainChannel::disable()
                };
                let msgs = ironrdp_svc::SvcProcessorMessages::<CurtainChannel>::new(vec![
                    ironrdp_svc::SvcMessage::from(payload),
                ]);
                match stage.process_svc_processor_messages(msgs) {
                    Ok(bytes) => {
                        session.send_rdp(&bytes).await?;
                        info!(curtain = desired, "sent curtain event");
                    }
                    Err(e) => warn!(error = %e, "failed to encode curtain event"),
                }
                curtain_applied = desired;
            }
        }
        // Cap update latency during a continuous stream: flush accumulated
        // graphics at ~60 fps even while more PDUs remain buffered.
        if pending.is_some() && last_flush.elapsed() >= std::time::Duration::from_millis(16) {
            if let Some(region) = pending.take() {
                frames += 1;
                sink.on_graphics_update(&composite, region);
            }
            last_flush = std::time::Instant::now();
        }
        if profile && prof_last.elapsed() >= std::time::Duration::from_secs(2) {
            let wall = prof_last.elapsed();
            info!(
                wall_ms = wall.as_millis() as u64,
                render_ms = p_proc.as_millis() as u64,
                net_wait_ms = wall.saturating_sub(p_proc).as_millis() as u64,
                recv_frames = p_frames,
                recv_kb = p_bytes / 1024,
                order_streams = p_orders,
                painted = frames,
                "PROFILE: render vs network"
            );
            prof_last = std::time::Instant::now();
            p_proc = std::time::Duration::ZERO;
            p_bytes = 0;
            p_frames = 0;
            p_orders = 0;
        }

        // Decompress the bulk-compressed fast-path stream (when the server
        // compresses it). A PDU may carry several updates and updates may be
        // fragmented across PDUs (reassembled in `comp_frag`); the first ready
        // update is returned here, the rest are queued in `decompressed_extra`.
        let frame = if action == ironrdp_pdu::Action::FastPath {
            match maybe_decompress(&frame, &mut decomp, &mut decompressed_extra) {
                Decomp::Passthrough => frame,
                Decomp::Ready(f) => f,
                Decomp::Pending => continue, // only accumulating fragments — nothing yet
            }
        } else {
            frame
        };

        // Intercept Fast-Path "Orders" updates before IronRDP (which silently
        // drops them). Render them into our OrderCanvas instead.
        if action == ironrdp_pdu::Action::FastPath {
            if let Some((frag, data)) = decode_fastpath_orders(&frame) {
                if let Some(complete) =
                    reassemble_orders(&mut order_frag, &mut order_frag_active, frag, data)
                {
                    // Dump order streams to disk for offline replay/debug. Default
                    // 5; SCCM_RC_DUMP_ORDERS=N raises the cap (N up to a few hundred
                    // captures a full desktop paint).
                    if order_dump_count < order_dump_cap {
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
                    let _pt = std::time::Instant::now();
                    let order_result = orders.process_orders(&complete);
                    if profile {
                        p_proc += _pt.elapsed();
                        p_orders += 1;
                    }
                    match order_result {
                        Ok(outcome) => {
                            // Healthy stream: clear the desync counter only after a
                            // run of consecutive clean streams (see ORDER_OK_RESET).
                            order_ok_streak = order_ok_streak.saturating_add(1);
                            if order_ok_streak >= ORDER_OK_RESET {
                                order_fail_streak = 0;
                            }
                            debug!(
                                orders = outcome.orders,
                                skipped = outcome.skipped,
                                "rendered drawing orders"
                            );
                            if let Some(r) = outcome.dirty {
                                let region = order_region(orders.canvas(), r);
                                composite.blit(orders.canvas(), region);
                                pending = union_region(pending, region);
                            } else if force_paint && pdus.is_multiple_of(40) {
                                // Diagnostic: flush the whole composite even with no
                                // dirty region, to see whether pixels are landing.
                                frames += 1;
                                let (w, h) = (composite.width(), composite.height());
                                composite.blit(
                                    orders.canvas(),
                                    UpdateRegion {
                                        left: 0,
                                        top: 0,
                                        right: w.saturating_sub(1),
                                        bottom: h.saturating_sub(1),
                                    },
                                );
                                sink.on_graphics_update(
                                    &composite,
                                    UpdateRegion {
                                        left: 0,
                                        top: 0,
                                        right: w.saturating_sub(1),
                                        bottom: h.saturating_sub(1),
                                    },
                                );
                            }
                        }
                        Err(e) => {
                            order_ok_streak = 0;
                            order_fail_streak += 1;
                            warn!(error = %e, streak = order_fail_streak, "order stream decode failed");
                            if order_fail_streak >= ORDER_FAIL_RECONNECT {
                                warn!(
                                    streak = order_fail_streak,
                                    "order stream desynced — forcing reconnect to reset decoder state"
                                );
                                sink.on_status("Beeld hersteld — opnieuw verbinden...");
                                return Err(Error::Protocol(
                                    "order stream desync — reconnecting to reset MPPC/order state"
                                        .into(),
                                ));
                            }
                        }
                    }
                }
                continue; // handled — do not pass to IronRDP
            }
        }

        let outputs = match stage.process(&mut image, action, &frame) {
            Ok(o) => o,
            Err(e) => {
                // After arbitration HostAllowed the SCCM server restarts the
                // session (Server Control PDUs: Cooperate / Granted Control, Font
                // Map, etc.) before the reactivation DemandActive. IronRDP's active
                // stage treats these as a fatal "unhandled PDU"; swallow them so the
                // session survives to the reactivation + graphics.
                let msg = e.to_string();
                if msg.contains("unhandled PDU") {
                    debug!(error = %msg, "ignoring benign unhandled PDU in active session");
                    continue;
                }
                return Err(Error::Protocol(format!("active-stage: {e}")));
            }
        };

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
            debug!(?action, ?kinds, "stage outputs");
        }

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(bytes) => {
                    session.send_rdp(&bytes).await?;
                }
                ActiveStageOutput::GraphicsUpdate(r) => {
                    frames += 1;
                    let region = UpdateRegion {
                        left: r.left,
                        top: r.top,
                        right: r.right,
                        bottom: r.bottom,
                    };
                    composite.blit(&image, region);
                    pending = union_region(pending, region);
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
                    info!(
                        refeed,
                        share_id, "server reactivation — re-running capability exchange"
                    );
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
                    composite.resize(width, height);
                    pending = None; // stale region from the old desktop size
                                    // Drop queued (pre-reactivation) decompressed updates — they
                                    // belong to the old desktop. Do NOT reset the MPPC decompressor
                                    // history here: the server's bulk compressor does not
                                    // necessarily restart across the reactivation, so clearing our
                                    // history would desync us from its (retained) history. We honor
                                    // the on-wire PACKET_FLUSHED / PACKET_AT_FRONT flags instead.
                    decompressed_extra.clear();
                    // Drop any half-assembled order fragment from the old desktop:
                    // if reactivation lands mid FIRST..LAST, the leftover bytes would
                    // be prepended to the first post-reactivation order stream and
                    // corrupt it.
                    order_frag.clear();
                    order_frag_active = false;
                    // Fresh decoder state after reactivation — don't carry a
                    // pre-reactivation failure streak into the new desktop.
                    order_fail_streak = 0;
                    order_ok_streak = 0;
                    stage = ActiveStage::new(new_result);
                    sink.on_status("Bureaublad laden...");
                    info!(
                        width,
                        height, share_id, "reactivation complete — active session resumed"
                    );
                    // Re-send the WLC desktop handshake after the shadow-attach
                    // reactivation — this is what triggers the server to start the
                    // desktop capture/stream. (SCCM_RC_WLC_ONCE=1 sends it only on the
                    // first activation, to A/B whether it causes the later desync.)
                    if std::env::var("SCCM_RC_WLC").as_deref() == Ok("1")
                        && std::env::var("SCCM_RC_WLC_ONCE").as_deref() != Ok("1")
                    {
                        send_wlc_desktop_caps(session, user_channel_id, io_channel_id).await?;
                    }
                    // Repaint after reactivation too (with the server's share_id).
                    send_refresh_rect(
                        session,
                        user_channel_id,
                        io_channel_id,
                        share_id,
                        width,
                        height,
                    )
                    .await?;
                    break; // restart the outer read loop with the new stage
                }
                // Cursor updates → the sink renders them client-side at the local
                // mouse position (instant tracking). Position updates are ignored;
                // we draw at the local cursor, not the server-reported one.
                ActiveStageOutput::PointerBitmap(p) => {
                    sink.on_pointer(PointerUpdate::Bitmap(PointerImage {
                        width: p.width,
                        height: p.height,
                        hotspot_x: p.hotspot_x,
                        hotspot_y: p.hotspot_y,
                        rgba: p.bitmap_data.clone(),
                    }));
                }
                ActiveStageOutput::PointerHidden => sink.on_pointer(PointerUpdate::Hidden),
                ActiveStageOutput::PointerDefault => sink.on_pointer(PointerUpdate::SystemDefault),
                ActiveStageOutput::PointerPosition { .. } => {}
            }
        }
    }
}

/// Wrap a Fast-Path update body (`updateHeader` + payload) in a Fast-Path output
/// PDU header `[fpOutputHeader][length]` (1- or 2-byte length per MS-RDPBCGR).
fn wrap_fastpath(fph: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + body.len());
    out.push(fph);
    let total1 = 2 + body.len(); // fph(1) + len(1) + body
    if total1 < 0x80 {
        out.push(total1 as u8);
    } else {
        let total2 = 3 + body.len(); // fph(1) + len(2) + body
        out.push(0x80 | (total2 >> 8) as u8);
        out.push((total2 & 0xff) as u8);
    }
    out.extend_from_slice(body);
    out
}

/// Optional raw-capture of compressed fast-path updates, for offline MPPC
/// debugging. Enabled by `SCCM_RC_DUMP_MPPC=<path>`; every compressed update is
/// appended verbatim as `[u8 updateHeader][u8 compressionFlags][u16 LE size]
/// [size bytes data]` — exactly the bytes the decompressor consumes, so the
/// `mppc-replay` test can replay the live stream offline and find the desync.
fn dump_mppc_record(uh: u8, cflags: u8, data: &[u8]) {
    use std::io::Write;
    static SINK: std::sync::OnceLock<Option<std::sync::Mutex<std::fs::File>>> =
        std::sync::OnceLock::new();
    let sink = SINK.get_or_init(|| {
        std::env::var("SCCM_RC_DUMP_MPPC")
            .ok()
            .and_then(|p| std::fs::File::create(&p).ok().map(std::sync::Mutex::new))
    });
    if let Some(m) = sink {
        if let Ok(mut f) = m.lock() {
            let mut rec = Vec::with_capacity(4 + data.len());
            rec.push(uh);
            rec.push(cflags);
            rec.extend_from_slice(&(data.len() as u16).to_le_bytes());
            rec.extend_from_slice(data);
            let _ = f.write_all(&rec);
        }
    }
}

/// Result of running `maybe_decompress` over one fast-path PDU.
enum Decomp {
    /// Not a compressed fast-path frame — process the original frame unchanged.
    Passthrough,
    /// A complete (decompressed) update to process now; further complete updates
    /// from this PDU were pushed to `extra`.
    Ready(Vec<u8>),
    /// The PDU only carried compressed fragments still being reassembled — nothing
    /// to process yet.
    Pending,
}

/// Decompress a fast-path PDU's update(s). A PDU may carry several updates; each
/// compressed update fragment is bulk-decompressed independently (sharing the
/// persistent MPPC history) and rebuilt as an uncompressed update that keeps its
/// fragmentation, so the order layer reassembles the plaintext fragments.
fn maybe_decompress(
    frame: &[u8],
    dec: &mut MppcDecompressor,
    extra: &mut std::collections::VecDeque<Vec<u8>>,
) -> Decomp {
    if frame.len() < 3 || frame[0] & 0x03 != 0 {
        return Decomp::Passthrough; // not fast-path
    }
    let fph = frame[0];
    let dbg = std::env::var("SCCM_RC_DBG_MPPC").is_ok();
    let mut pos = if frame[1] & 0x80 != 0 { 3 } else { 2 };

    let mut ready: Vec<Vec<u8>> = Vec::new();
    let mut any_compressed = false;

    // Decompress one complete (reassembled) compressed blob → a rebuilt
    // uncompressed, SINGLE-fragment fast-path update.
    let emit = |code_uh: u8, plain: Vec<u8>| -> Option<Vec<u8>> {
        if plain.is_empty() || plain.len() > 0xFFFF {
            return None;
        }
        let mut body = Vec::with_capacity(3 + plain.len());
        // Keep updateCode + fragmentation (bits 0-5); clear only the compression
        // bits (6-7) since the data is now plaintext. Preserving fragmentation lets
        // the downstream order reassembly (`reassemble_orders`) join multi-fragment
        // updates — exactly as it does for a natively-uncompressed stream.
        body.push(code_uh & 0x3F);
        body.extend_from_slice(&(plain.len() as u16).to_le_bytes());
        body.extend_from_slice(&plain);
        Some(wrap_fastpath(fph, &body))
    };

    while pos < frame.len() {
        let uh = frame[pos];
        if uh & 0xC0 == 0x80 {
            // Compressed update: updateHeader(1) compressionFlags(1) size(2) data.
            if pos + 4 > frame.len() {
                break;
            }
            let cflags = frame[pos + 1];
            let size = u16::from_le_bytes([frame[pos + 2], frame[pos + 3]]) as usize;
            let dstart = pos + 4;
            if dstart + size > frame.len() {
                break;
            }
            let data = &frame[dstart..dstart + size];
            pos = dstart + size;
            any_compressed = true;
            dump_mppc_record(uh, cflags, data); // raw-capture for offline replay
            let frag_bits = (uh >> 4) & 0x03; // 0=SINGLE 1=LAST 2=FIRST 3=NEXT
            if dbg {
                tracing::warn!(
                    "MPPC dbg: uh={uh:#04x} frag={frag_bits} cflags={cflags:#04x} insz={}",
                    data.len()
                );
            }
            // Decompress THIS fragment with its OWN compression flags. Each
            // fast-path fragment is an independent, byte-aligned MPPC packet that
            // shares only the persistent 64K history with the others (per FreeRDP
            // fastpath_recv_update_data: bulk_decompress each fragment, THEN
            // Stream_Write the plaintext into the reassembly buffer). We rebuild
            // each fragment as an uncompressed update that keeps its fragmentation,
            // so `reassemble_orders` joins the plaintext fragments downstream.
            //
            // Reassembling the *compressed* bytes first (the previous approach) is
            // wrong: it splices each fragment's trailing bit-padding into the next
            // fragment's bitstream and discards per-fragment AT_FRONT/FLUSHED flags
            // → the bitstream desyncs right after the first fragment.
            let _ = frag_bits;
            let plain = dec.decompress(
                data,
                cflags & 0x20 != 0,
                cflags & 0x40 != 0,
                cflags & 0x80 != 0,
            );
            if let Some(f) = emit(uh, plain) {
                ready.push(f);
            }
        } else {
            // Uncompressed update: updateHeader(1) size(2) data(size) — verbatim.
            if pos + 3 > frame.len() {
                break;
            }
            let size = u16::from_le_bytes([frame[pos + 1], frame[pos + 2]]) as usize;
            let end = pos + 3 + size;
            if end > frame.len() {
                break;
            }
            ready.push(wrap_fastpath(fph, &frame[pos..end]));
            pos = end;
        }
    }

    if !any_compressed {
        return Decomp::Passthrough; // nothing compressed — use the original frame
    }
    let mut it = ready.into_iter();
    match it.next() {
        Some(first) => {
            for f in it {
                extra.push_back(f);
            }
            Decomp::Ready(first)
        }
        None => Decomp::Pending, // only accumulating fragments so far
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
    if let Some(cf) = update.compression_flags {
        debug!(compression_flags = ?cf, frag = ?update.fragmentation, data = update.data.len(),
            "fastpath ORDERS update is COMPRESSED");
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

/// Union two inclusive `UpdateRegion`s (for coalescing graphics updates).
fn union_region(a: Option<UpdateRegion>, b: UpdateRegion) -> Option<UpdateRegion> {
    Some(match a {
        None => b,
        Some(a) => UpdateRegion {
            left: a.left.min(b.left),
            top: a.top.min(b.top),
            right: a.right.max(b.right),
            bottom: a.bottom.max(b.bottom),
        },
    })
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

// ---------------------------------------------------------------------------
// WLC desktop capability handshake (captured from the real CmRcViewer, 2026-06-03;
// see experiments/captures/DECODE.md). These are the client->server messages on
// the I/O channel (MCS id 03eb) that make the SCCM RC server begin sending desktop
// fast-path graphics. They are constant capability advertisements wrapped in the
// WLC inner envelope `[u16 innerLen][u16 type][u16 src=03f4][u16 dst=03ea]...`,
// replayed verbatim. WLC_MSTSC = the "MSTSC" capability envelope (C#16); WLC_TLV1..4
// = the curtain/dynres/dskcfg control TLVs (C#17..20). IronRDP re-adds the MCS
// Send-Data header, so these are the raw user-data payloads only.
// Kept for reference; the ConfirmActive is now emitted by the vendored connector.
#[allow(dead_code)]
const WLC_MSTSC: &[u8] = &[
    0xea, 0x01, 0x13, 0x00, 0xf4, 0x03, 0xea, 0x03, 0x01, 0x00, 0xea, 0x03, 0x06, 0x00, 0xd4, 0x01,
    0x4d, 0x53, 0x54, 0x53, 0x43, 0x00, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x01, 0x00,
    0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x70, 0x04,
    0x58, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xaa, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xa1, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xe4, 0x04, 0x00, 0x00, 0x13, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 0x03, 0x78, 0x00,
    0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x51, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x08, 0x00,
    0x0a, 0x00, 0x01, 0x00, 0x14, 0x00, 0x15, 0x00, 0x09, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x58, 0x00, 0xb1, 0x00, 0x00, 0x00, 0x09, 0x04, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x0e, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x34, 0x00, 0xfe, 0x00, 0x04, 0x00,
    0xfe, 0x00, 0x04, 0x00, 0xfe, 0x00, 0x08, 0x00, 0xfe, 0x00, 0x08, 0x00, 0xfe, 0x00, 0x10, 0x00,
    0xfe, 0x00, 0x20, 0x00, 0xfe, 0x00, 0x40, 0x00, 0xfe, 0x00, 0x80, 0x00, 0xfe, 0x00, 0x00, 0x01,
    0x40, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x08, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, 0x64, 0x00,
    0x14, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x0c, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x1a, 0x00, 0x08, 0x00, 0x2b, 0x48, 0x09, 0x00,
    0x1c, 0x00, 0x0c, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x06, 0x00,
    0x01, 0x00, 0x1e, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
];
const WLC_TLV1: &[u8] = &[
    0x16, 0x00, 0x17, 0x00, 0xf4, 0x03, 0xea, 0x03, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x1f, 0x00,
    0x00, 0x00, 0x01, 0x00, 0xea, 0x03,
];
const WLC_TLV2: &[u8] = &[
    0x1a, 0x00, 0x17, 0x00, 0xf4, 0x03, 0xea, 0x03, 0x01, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x14, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const WLC_TLV3: &[u8] = &[
    0x1a, 0x00, 0x17, 0x00, 0xf4, 0x03, 0xea, 0x03, 0x01, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x14, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const WLC_TLV4: &[u8] = &[
    0x1a, 0x00, 0x17, 0x00, 0xf4, 0x03, 0xea, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x27, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00,
];

/// A raw WLC user-data payload sent over the MCS I/O channel. The WLC desktop
/// protocol is not a Share PDU, so we emit the captured bytes verbatim and let
/// `encode_send_data_request` wrap them in the MCS Send-Data header.
struct WlcRawPdu<'a> {
    payload: &'a [u8],
}

impl ironrdp_core::Encode for WlcRawPdu<'_> {
    fn encode(&self, dst: &mut ironrdp_core::WriteCursor<'_>) -> ironrdp_core::EncodeResult<()> {
        dst.write_slice(self.payload);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "WlcRawPdu"
    }
    fn size(&self) -> usize {
        self.payload.len()
    }
}

/// Send the WLC desktop capability handshake (MSTSC envelope + curtain/dynres/
/// dskcfg control TLVs) over the I/O channel. This is the trigger the SCCM RC
/// server waits for before it starts sending desktop fast-path graphics; without
/// it, arbitration + reactivation succeed but no pixels ever arrive.
async fn send_wlc_desktop_caps(
    session: &mut SccmSession,
    user_channel_id: u16,
    io_channel_id: u16,
) -> Result<()> {
    // NOTE: the "MSTSC" ConfirmActive is now emitted by the vendored connector
    // (SCCM_RC_MSTSC_CAPS=1); sending it here too would be a duplicate ConfirmActive.
    // We only send the 4 WLC control Share-Data PDUs (curtain/dynres/dskcfg).
    for (label, payload) in [
        ("TLV1", WLC_TLV1),
        ("TLV2", WLC_TLV2),
        ("TLV3", WLC_TLV3),
        ("TLV4", WLC_TLV4),
    ] {
        let mut out = WriteBuf::new();
        ironrdp_connector::legacy::encode_send_data_request(
            user_channel_id,
            io_channel_id,
            &WlcRawPdu { payload },
            &mut out,
        )
        .map_err(|e| Error::Protocol(format!("encode WLC {label}: {e}")))?;
        session.send_rdp(out.filled()).await?;
        debug!(label, len = payload.len(), "sent WLC desktop message");
    }
    info!("sent WLC desktop capability handshake (MSTSC + 4 control TLVs)");
    Ok(())
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
    ironrdp_connector::legacy::encode_share_data(
        user_channel_id,
        io_channel_id,
        share_id,
        allow,
        &mut out,
    )
    .map_err(|e| Error::Protocol(format!("encode suppress-output: {e}")))?;
    session.send_rdp(out.filled()).await?;

    // 2. Refresh the whole desktop.
    let refresh = ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
        areas_to_refresh: vec![full],
    });
    let mut out2 = WriteBuf::new();
    ironrdp_connector::legacy::encode_share_data(
        user_channel_id,
        io_channel_id,
        share_id,
        refresh,
        &mut out2,
    )
    .map_err(|e| Error::Protocol(format!("encode refresh rect: {e}")))?;
    session.send_rdp(out2.filled()).await?;

    debug!(width, height, share_id, "sent allow-output + refresh-rect");
    Ok(())
}

/// Ask the server to re-send a single rectangle. Used to erase the server's
/// baked-in software-cursor stamps: the SCCM RC server captures the shadowed
/// session's framebuffer INCLUDING its software cursor, re-sends the 64x64 tiles
/// under the cursor as it moves, but never erases the old positions → a trail.
/// Refreshing the regions the cursor passed through makes the server re-send the
/// (now cursor-free) background there.
async fn send_refresh_area(
    session: &mut SccmSession,
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
    rect: ironrdp_pdu::geometry::InclusiveRectangle,
) -> Result<()> {
    use ironrdp_core::WriteBuf;
    use ironrdp_pdu::rdp::headers::ShareDataPdu;
    use ironrdp_pdu::rdp::refresh_rectangle::RefreshRectanglePdu;
    let refresh = ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
        areas_to_refresh: vec![rect],
    });
    let mut out = WriteBuf::new();
    ironrdp_connector::legacy::encode_share_data(
        user_channel_id,
        io_channel_id,
        share_id,
        refresh,
        &mut out,
    )
    .map_err(|e| Error::Protocol(format!("encode refresh area: {e}")))?;
    session.send_rdp(out.filled()).await?;
    Ok(())
}

/// Flush the accumulated cursor-trail rectangle (if any) via a refresh request.
async fn flush_cursor_trail(
    session: &mut SccmSession,
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
    trail: &mut Option<(u16, u16, u16, u16)>,
    last: &mut std::time::Instant,
) -> Result<()> {
    if let Some((left, top, right, bottom)) = trail.take() {
        // Skip a degenerate/inverted rect: mouse coordinates beyond the desktop
        // can make `left > right` (the min corner isn't clamped to the max), which
        // would be a malformed RefreshRectangle on the wire.
        if left <= right && top <= bottom {
            let rect = ironrdp_pdu::geometry::InclusiveRectangle {
                left,
                top,
                right,
                bottom,
            };
            send_refresh_area(session, user_channel_id, io_channel_id, share_id, rect).await?;
            *last = std::time::Instant::now();
        }
    }
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
                match hint
                    .find_size(buf)
                    .map_err(|e| Error::Protocol(format!("reactivation hint: {e}")))?
                {
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
            let mut pdu: Vec<u8> = buf.drain(..pdu_len).collect();
            // The SCCM reactivation DemandActive has a short Bitmap Cache Rev2
            // cap that IronRDP can't decode; pad it before processing.
            if let Some(fixed) = fix_short_bitmap_cache_rev2(&pdu) {
                debug!(
                    old = pdu.len(),
                    new = fixed.len(),
                    "padded short BitmapCacheRev2 in reactivation DemandActive"
                );
                pdu = fixed;
            }
            let state_name = seq.state.name();
            if let Err(e) = seq.step(&pdu, &mut out) {
                let path = std::env::temp_dir().join("sccm-reactivation-demandactive.bin");
                let _ = std::fs::write(&path, &pdu);
                warn!(state = state_name, len = pdu.len(), error = %e, path = %path.display(), "reactivation step failed — frame dumped");
                log_demand_active(&pdu);
                return Err(Error::Protocol(format!("reactivation: {e}")));
            }
        } else {
            seq.step_no_input(&mut out)
                .map_err(|e| Error::Protocol(format!("reactivation: {e}")))?;
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
#[derive(Default)]
pub struct LoggingSink {
    pub updates: u64,
    pub total_pixels: u64,
}


impl SessionSink for LoggingSink {
    fn on_graphics_update(&mut self, image: &dyn FrameView, region: UpdateRegion) {
        self.updates += 1;
        let w = region.right.saturating_sub(region.left) as u64 + 1;
        let h = region.bottom.saturating_sub(region.top) as u64 + 1;
        self.total_pixels += w * h;
        if self.updates <= 20 || self.updates.is_multiple_of(50) {
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
        Self {
            path: path.into(),
            updates: 0,
            nonblack_pixels: 0,
        }
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
        // Save as PNG (RGBA). Write to a temp file then rename, so a reader (or a
        // killed process) never sees a half-written/0-byte PNG.
        if let Some(buf) = image::RgbaImage::from_raw(w, h, data.to_vec()) {
            let tmp = format!("{}.tmp", self.path);
            match buf.save_with_format(&tmp, image::ImageFormat::Png) {
                Ok(()) => {
                    if let Err(e) = std::fs::rename(&tmp, &self.path) {
                        warn!(error = %e, "png rename failed");
                    } else if self.updates <= 3 || self.updates.is_multiple_of(25) {
                        info!(update = self.updates, fb = format!("{w}x{h}"), nonblack, path = %self.path, "saved frame PNG");
                    }
                }
                Err(e) => warn!(error = %e, "png save failed"),
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

    #[test]
    fn fragmented_compressed_update_decompresses_per_fragment() {
        // Model (B), per FreeRDP: each fast-path fragment is an INDEPENDENT,
        // byte-aligned MPPC packet that only shares the persistent history. We
        // decompress each fragment on its own and rebuild it KEEPING its
        // fragmentation, so the order layer (`reassemble_orders`) joins the
        // plaintext. Two ORDERS fragments FIRST("AB") + LAST("CD") → "ABCD".
        //
        // 'A'(0x41) 'B'(0x42) as `0`+7-bit literals = 0100_0001 0100_0010;
        // 'C'(0x43) 'D'(0x44) = 0100_0011 0100_0100. Each is a complete, padded
        // MPPC packet on its own — exactly how the server fragments.
        let ab = [0b0100_0001u8, 0b0100_0010];
        let cd = [0b0100_0011u8, 0b0100_0100];
        let mk = |uh: u8, cflags: u8, data: &[u8]| -> Vec<u8> {
            let mut body = vec![uh, cflags];
            body.extend_from_slice(&(data.len() as u16).to_le_bytes());
            body.extend_from_slice(data);
            wrap_fastpath(0x00, &body)
        };
        // updateCode 0 = ORDERS, compression bit 0x80 set; FIRST(2)=0xA0 LAST(1)=0x90.
        let f1 = mk(0xA0, 0x21, &ab); // FIRST, COMPRESSED (64K)
        let f2 = mk(0x90, 0x21, &cd); // LAST,  COMPRESSED (64K)

        let mut dec = MppcDecompressor::new();
        let mut extra = std::collections::VecDeque::new();

        // Each fragment now decompresses immediately to a rebuilt *uncompressed*
        // ORDERS update that preserves its fragmentation (no more Pending).
        let r1 = match maybe_decompress(&f1, &mut dec, &mut extra) {
            Decomp::Ready(f) => f,
            _ => panic!("FIRST fragment should produce a Ready update"),
        };
        let r2 = match maybe_decompress(&f2, &mut dec, &mut extra) {
            Decomp::Ready(f) => f,
            _ => panic!("LAST fragment should produce a Ready update"),
        };

        // The downstream order reassembly joins the two plaintext fragments.
        let mut buf = Vec::new();
        let mut active = false;
        let (fr1, d1) = decode_fastpath_orders(&r1).expect("r1 is an ORDERS update");
        assert_eq!(fr1, Fragmentation::First);
        assert!(reassemble_orders(&mut buf, &mut active, fr1, d1).is_none());
        let (fr2, d2) = decode_fastpath_orders(&r2).expect("r2 is an ORDERS update");
        assert_eq!(fr2, Fragmentation::Last);
        let joined = reassemble_orders(&mut buf, &mut active, fr2, d2).expect("LAST completes");
        assert_eq!(joined, b"ABCD");
    }

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

    /// Offline replay of a captured live MPPC stream (from `SCCM_RC_DUMP_MPPC`).
    /// Runs the exact production path — `maybe_decompress` (with the shared 64K
    /// history + FIRST/NEXT/LAST reassembly) → `decode_fastpath_orders` →
    /// `OrderProcessor::process_orders` — over every captured compressed update,
    /// and reports the first record where the decompressed bytes no longer parse
    /// as valid drawing orders. That record (or the one just before it) is where
    /// the decompressor desyncs from the server's bulk compressor.
    ///
    /// Inert unless `SCCM_RC_REPLAY=<capture-file>` is set. Desktop defaults to
    /// 1920x1080 (override with `SCCM_RC_REPLAY_W` / `SCCM_RC_REPLAY_H`). Run with:
    ///   cargo test -p sccm-rc-core replay_mppc_capture -- --nocapture
    #[test]
    fn replay_mppc_capture() {
        let path = match std::env::var("SCCM_RC_REPLAY") {
            Ok(p) => p,
            Err(_) => return, // no capture supplied — nothing to do
        };
        let raw = std::fs::read(&path).expect("read capture file");
        // Parse records: [u8 uh][u8 cflags][u16 LE size][size bytes data].
        let mut recs: Vec<(u8, u8, Vec<u8>)> = Vec::new();
        let mut i = 0usize;
        while i + 4 <= raw.len() {
            let uh = raw[i];
            let cflags = raw[i + 1];
            let size = u16::from_le_bytes([raw[i + 2], raw[i + 3]]) as usize;
            if i + 4 + size > raw.len() {
                eprintln!("replay: truncated trailing record at {i}");
                break;
            }
            recs.push((uh, cflags, raw[i + 4..i + 4 + size].to_vec()));
            i += 4 + size;
        }
        let w: u16 = std::env::var("SCCM_RC_REPLAY_W")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1920);
        let h: u16 = std::env::var("SCCM_RC_REPLAY_H")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1080);
        eprintln!("replay: {} compressed records, desktop {w}x{h}", recs.len());

        let mut dec = MppcDecompressor::new();
        let mut orders = OrderProcessor::new(w, h, ColorDepth::Bpp16);
        let mut order_frag: Vec<u8> = Vec::new();
        let mut order_frag_active = false;
        let (mut ok_updates, mut total_orders) = (0u64, 0u64);

        for (n, (uh, cflags, data)) in recs.iter().enumerate() {
            // Rebuild a single-update fast-path PDU and run the live decompress path.
            let mut body = vec![*uh, *cflags];
            body.extend_from_slice(&(data.len() as u16).to_le_bytes());
            body.extend_from_slice(data);
            let pdu = wrap_fastpath(0x00, &body);
            let mut extra = std::collections::VecDeque::new();
            let mut updates: Vec<Vec<u8>> = Vec::new();
            match maybe_decompress(&pdu, &mut dec, &mut extra) {
                Decomp::Ready(f) => updates.push(f),
                Decomp::Pending => {} // still reassembling fragments
                Decomp::Passthrough => {
                    eprintln!("replay rec {n}: unexpected Passthrough (uh={uh:#04x})");
                }
            }
            updates.extend(extra.drain(..));

            for u in updates {
                let Some((fr, d)) = decode_fastpath_orders(&u) else {
                    continue; // not an ORDERS update (pointer/etc.) — skip validation
                };
                if let Some(complete) =
                    reassemble_orders(&mut order_frag, &mut order_frag_active, fr, d)
                {
                    match orders.process_orders(&complete) {
                        Ok(o) => {
                            ok_updates += 1;
                            total_orders += o.orders as u64;
                        }
                        Err(e) => {
                            let head: Vec<String> = complete
                                .iter()
                                .take(32)
                                .map(|b| format!("{b:02x}"))
                                .collect();
                            panic!(
                                "DESYNC at record {n} (uh={uh:#04x} cflags={cflags:#04x} insz={}): \
                                 order stream decode failed: {e}\n  decompressed {} bytes, head: {}",
                                data.len(),
                                complete.len(),
                                head.join(" ")
                            );
                        }
                    }
                }
            }
        }
        eprintln!("replay OK: {ok_updates} order updates parsed, {total_orders} orders total");
    }
}
