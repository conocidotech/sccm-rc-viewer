//! Clipboard virtual-channel protocol (MS-RDPECLIP) — text only for now.
//!
//! Flows over the static virtual channel named `cliprdr`. Message framing is a
//! 8-byte `CLIPRDR_HEADER` (`msgType` u16, `msgFlags` u16, `dataLen` u32 LE)
//! followed by `dataLen` bytes of body. The handshake is:
//!
//! ```text
//!  server → CB_CLIP_CAPS (optional) + CB_MONITOR_READY
//!  client → CB_CLIP_CAPS + CB_FORMAT_LIST            (announce our formats)
//!  server → CB_FORMAT_LIST_RESPONSE(ok)
//! ```
//!
//! Then either side announces a clipboard change with `CB_FORMAT_LIST`; the peer
//! pulls the data with `CB_FORMAT_DATA_REQUEST` → `CB_FORMAT_DATA_RESPONSE`.
//!
//! We negotiate **short** format names (no `CB_USE_LONG_FORMAT_NAMES`) and only
//! handle `CF_UNICODETEXT` (formatId 13) — enough for text copy/paste.

/// Standard clipboard format: Unicode (UTF-16LE) text.
pub const CF_UNICODETEXT: u32 = 13;

// CLIPRDR_HEADER msgType values (MS-RDPECLIP 2.2.1).
pub const CB_MONITOR_READY: u16 = 0x0001;
pub const CB_FORMAT_LIST: u16 = 0x0002;
pub const CB_FORMAT_LIST_RESPONSE: u16 = 0x0003;
pub const CB_FORMAT_DATA_REQUEST: u16 = 0x0004;
pub const CB_FORMAT_DATA_RESPONSE: u16 = 0x0005;
pub const CB_CLIP_CAPS: u16 = 0x0007;
pub const CB_FILECONTENTS_REQUEST: u16 = 0x0008;
pub const CB_FILECONTENTS_RESPONSE: u16 = 0x0009;

// msgFlags.
pub const CB_RESPONSE_OK: u16 = 0x0001;
#[allow(dead_code)]
pub const CB_RESPONSE_FAIL: u16 = 0x0002;

// FileContents request dwFlags.
pub const FILECONTENTS_SIZE: u32 = 0x0001;
pub const FILECONTENTS_RANGE: u32 = 0x0002;

/// Our advertised format id for the registered "FileGroupDescriptorW" format
/// (the peer maps the long name to this id). Any value works; the receiver
/// requests data by this id.
pub const CF_FILEGROUPDESCRIPTORW: u32 = 0xC0DE;

/// A decoded inbound clipboard PDU (only the variants we act on).
#[derive(Debug, Clone)]
pub enum ClipPdu {
    MonitorReady,
    Capabilities,
    /// Peer announced its available formats; `has_text` is true if it offers
    /// `CF_UNICODETEXT` (or `CF_TEXT`).
    FormatList { has_text: bool },
    FormatListResponse { ok: bool },
    /// Peer wants the data for `format_id` (we should reply with a data response).
    FormatDataRequest { format_id: u32 },
    /// Peer sent the requested data; `text` is decoded if it was Unicode text.
    FormatDataResponse { ok: bool, text: Option<String> },
    /// Peer requested a chunk of a file we offered (for file transfer).
    FileContentsRequest {
        stream_id: u32,
        lindex: u32,
        size_only: bool,
        position: u64,
        requested: u32,
    },
    /// Any other message type we don't handle.
    Other { msg_type: u16 },
}

/// True if the Format List in `pdu` (a `FormatList`) advertised files.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatListKinds {
    pub has_text: bool,
    pub has_files: bool,
}

fn header(msg_type: u16, msg_flags: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + data.len());
    v.extend_from_slice(&msg_type.to_le_bytes());
    v.extend_from_slice(&msg_flags.to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// Build a Clipboard Capabilities PDU advertising a single General capability
/// set with no special flags (short format names, text only).
pub fn capabilities() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes()); // cCapabilitiesSets
    body.extend_from_slice(&0u16.to_le_bytes()); // pad
    // General Capability Set.
    body.extend_from_slice(&1u16.to_le_bytes()); // capabilitySetType = CB_CAPSTYPE_GENERAL
    body.extend_from_slice(&12u16.to_le_bytes()); // lengthCapability
    body.extend_from_slice(&2u32.to_le_bytes()); // version = CB_CAPS_VERSION_2
    body.extend_from_slice(&0u32.to_le_bytes()); // generalFlags = 0 (short names)
    header(CB_CLIP_CAPS, 0, &body)
}

/// Build a Format List PDU (short format names). If `with_text` is true we
/// announce `CF_UNICODETEXT`; otherwise the list is empty (we hold nothing).
pub fn format_list_text(with_text: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if with_text {
        // CLIPRDR_SHORT_FORMAT_NAME: formatId(4) + 32-byte name (empty for a
        // standard format id).
        body.extend_from_slice(&CF_UNICODETEXT.to_le_bytes());
        body.extend_from_slice(&[0u8; 32]);
    }
    header(CB_FORMAT_LIST, 0, &body)
}

/// Build a Format List Response PDU (success).
pub fn format_list_response_ok() -> Vec<u8> {
    header(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, &[])
}

/// Build a Format Data Request PDU for `format_id`.
pub fn format_data_request(format_id: u32) -> Vec<u8> {
    header(CB_FORMAT_DATA_REQUEST, 0, &format_id.to_le_bytes())
}

/// Build a Format Data Response PDU carrying `text` as `CF_UNICODETEXT`
/// (UTF-16LE, null-terminated).
pub fn format_data_response_text(text: &str) -> Vec<u8> {
    let mut data: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    data.extend_from_slice(&[0, 0]); // null terminator
    header(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, &data)
}

/// Build a failed Format Data Response PDU (we had nothing to give).
pub fn format_data_response_fail() -> Vec<u8> {
    header(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, &[])
}

/// Generic Format Data Response carrying raw bytes (e.g. a file group descriptor).
pub fn format_data_response_bytes(data: &[u8]) -> Vec<u8> {
    header(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, data)
}

// ---- File transfer (MS-RDPECLIP file copy) ----

/// Capabilities advertising long format names + stream-based file clipboard
/// (required so we can advertise the registered "FileGroupDescriptorW" format).
pub fn capabilities_files() -> Vec<u8> {
    // CB_USE_LONG_FORMAT_NAMES 0x02 | CB_STREAM_FILECLIP_ENABLED 0x04 |
    // CB_FILECLIP_NO_FILE_PATHS 0x08.
    let general_flags: u32 = 0x02 | 0x04 | 0x08;
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes()); // cCapabilitiesSets
    body.extend_from_slice(&0u16.to_le_bytes()); // pad
    body.extend_from_slice(&1u16.to_le_bytes()); // CB_CAPSTYPE_GENERAL
    body.extend_from_slice(&12u16.to_le_bytes()); // lengthCapability
    body.extend_from_slice(&2u32.to_le_bytes()); // version
    body.extend_from_slice(&general_flags.to_le_bytes());
    header(CB_CLIP_CAPS, 0, &body)
}

/// Format List using LONG format names. `formats` = (formatId, name) pairs; a
/// standard format (e.g. CF_UNICODETEXT) uses an empty name.
pub fn format_list_long(formats: &[(u32, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (id, name) in formats {
        body.extend_from_slice(&id.to_le_bytes());
        for u in name.encode_utf16() {
            body.extend_from_slice(&u.to_le_bytes());
        }
        body.extend_from_slice(&[0, 0]); // UTF-16 null terminator
    }
    header(CB_FORMAT_LIST, 0, &body)
}

/// Build a `FILEGROUPDESCRIPTORW` (one file): cItems + a 592-byte CLIPRDR_FILEDESCRIPTOR.
pub fn file_group_descriptor(name: &str, size: u64) -> Vec<u8> {
    const FD_ATTRIBUTES: u32 = 0x04;
    const FD_FILESIZE: u32 = 0x40;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let mut v = Vec::with_capacity(4 + 592);
    v.extend_from_slice(&1u32.to_le_bytes()); // cItems = 1
    // CLIPRDR_FILEDESCRIPTOR
    v.extend_from_slice(&(FD_ATTRIBUTES | FD_FILESIZE).to_le_bytes()); // flags
    v.extend_from_slice(&[0u8; 32]); // reserved1
    v.extend_from_slice(&FILE_ATTRIBUTE_NORMAL.to_le_bytes()); // fileAttributes
    v.extend_from_slice(&[0u8; 16]); // reserved2
    v.extend_from_slice(&[0u8; 8]); // lastWriteTime
    v.extend_from_slice(&((size >> 32) as u32).to_le_bytes()); // fileSizeHigh
    v.extend_from_slice(&(size as u32).to_le_bytes()); // fileSizeLow
    // fileName: 260 WCHAR (520 bytes), null-padded.
    let mut fname = [0u8; 520];
    for (i, u) in name.encode_utf16().take(259).enumerate() {
        fname[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    v.extend_from_slice(&fname);
    v
}

/// FileContents response carrying the file's total size (reply to a SIZE request).
pub fn file_contents_response_size(stream_id: u32, size: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&stream_id.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    header(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, &data)
}

/// FileContents response carrying a range of file bytes (reply to a RANGE request).
pub fn file_contents_response_range(stream_id: u32, bytes: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + bytes.len());
    data.extend_from_slice(&stream_id.to_le_bytes());
    data.extend_from_slice(bytes);
    header(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, &data)
}

/// Failed FileContents response.
pub fn file_contents_response_fail(stream_id: u32) -> Vec<u8> {
    header(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, &stream_id.to_le_bytes())
}

/// Parse one inbound clipboard PDU. Returns `None` if the buffer is too short.
pub fn parse(payload: &[u8]) -> Option<ClipPdu> {
    if payload.len() < 8 {
        return None;
    }
    let msg_type = u16::from_le_bytes([payload[0], payload[1]]);
    let msg_flags = u16::from_le_bytes([payload[2], payload[3]]);
    let data_len = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let data = &payload[8..(8 + data_len).min(payload.len())];

    Some(match msg_type {
        CB_MONITOR_READY => ClipPdu::MonitorReady,
        CB_CLIP_CAPS => ClipPdu::Capabilities,
        CB_FORMAT_LIST => {
            // Scan the (short or long) format-name entries for a text format id.
            let has_text = scan_for_text_format(data, msg_flags);
            ClipPdu::FormatList { has_text }
        }
        CB_FORMAT_LIST_RESPONSE => ClipPdu::FormatListResponse {
            ok: msg_flags & CB_RESPONSE_OK != 0,
        },
        CB_FORMAT_DATA_REQUEST => {
            let format_id = if data.len() >= 4 {
                u32::from_le_bytes([data[0], data[1], data[2], data[3]])
            } else {
                0
            };
            ClipPdu::FormatDataRequest { format_id }
        }
        CB_FORMAT_DATA_RESPONSE => {
            let ok = msg_flags & CB_RESPONSE_OK != 0;
            let text = if ok { decode_unicode_text(data) } else { None };
            ClipPdu::FormatDataResponse { ok, text }
        }
        CB_FILECONTENTS_REQUEST if data.len() >= 24 => {
            let u = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
            let flags = u(8);
            ClipPdu::FileContentsRequest {
                stream_id: u(0),
                lindex: u(4),
                size_only: flags & FILECONTENTS_SIZE != 0,
                position: (u(12) as u64) | ((u(16) as u64) << 32),
                requested: u(20),
            }
        }
        other => ClipPdu::Other { msg_type: other },
    })
}

/// True if the Format List body advertises CF_UNICODETEXT (13) or CF_TEXT (1).
/// Handles both short (4 + 32 bytes/entry) and long (4 + null-terminated UTF-16
/// name) format-name layouts by just scanning the leading format ids.
fn scan_for_text_format(data: &[u8], msg_flags: u16) -> bool {
    // CB_USE_LONG_FORMAT_NAMES was negotiated off on our side, but the peer may
    // still send long names; detect a text id either way.
    let long_names = msg_flags & 0x0004 == 0 && data.len() % 36 != 0 && !data.is_empty();
    if !long_names {
        // Short format names: fixed 36-byte entries.
        let mut i = 0;
        while i + 4 <= data.len() {
            let id = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if id == CF_UNICODETEXT || id == 1 {
                return true;
            }
            i += 36;
        }
        return false;
    }
    // Long format names: formatId(4) + null-terminated UTF-16 name. Walk entries.
    let mut i = 0;
    while i + 4 <= data.len() {
        let id = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if id == CF_UNICODETEXT || id == 1 {
            return true;
        }
        i += 4;
        // Skip the UTF-16 name up to and including its 00 00 terminator.
        while i + 2 <= data.len() && !(data[i] == 0 && data[i + 1] == 0) {
            i += 2;
        }
        i += 2;
    }
    false
}

/// Decode a CF_UNICODETEXT data blob (UTF-16LE, possibly null-terminated).
fn decode_unicode_text(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return Some(String::new());
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0) // stop at the null terminator
        .collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_format_data_response_text() {
        let pdu = format_data_response_text("Hi!");
        match parse(&pdu).unwrap() {
            ClipPdu::FormatDataResponse { ok, text } => {
                assert!(ok);
                assert_eq!(text.as_deref(), Some("Hi!"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn format_list_text_is_detected() {
        let pdu = format_list_text(true);
        match parse(&pdu).unwrap() {
            ClipPdu::FormatList { has_text } => assert!(has_text),
            other => panic!("wrong variant: {other:?}"),
        }
        let empty = format_list_text(false);
        match parse(&empty).unwrap() {
            ClipPdu::FormatList { has_text } => assert!(!has_text),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parse_format_data_request() {
        let pdu = format_data_request(CF_UNICODETEXT);
        match parse(&pdu).unwrap() {
            ClipPdu::FormatDataRequest { format_id } => assert_eq!(format_id, CF_UNICODETEXT),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn file_group_descriptor_layout() {
        // cItems(4) + one 592-byte CLIPRDR_FILEDESCRIPTOR.
        let fgd = file_group_descriptor("tool.exe", 0x1_0000_0042);
        assert_eq!(fgd.len(), 4 + 592);
        assert_eq!(&fgd[0..4], &1u32.to_le_bytes()); // cItems = 1
        // fileSizeHigh/Low at offset 4 + flags(4)+resv1(32)+attr(4)+resv2(16)+time(8) = 68/72.
        assert_eq!(&fgd[68..72], &1u32.to_le_bytes()); // high
        assert_eq!(&fgd[72..76], &0x42u32.to_le_bytes()); // low
    }

    #[test]
    fn file_contents_request_parses() {
        // streamId=9, lindex=0, RANGE, position=0x1_0000_0005, requested=4096.
        let mut data = Vec::new();
        data.extend_from_slice(&9u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&FILECONTENTS_RANGE.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes()); // posLow
        data.extend_from_slice(&1u32.to_le_bytes()); // posHigh
        data.extend_from_slice(&4096u32.to_le_bytes());
        let pdu = header(CB_FILECONTENTS_REQUEST, 0, &data);
        match parse(&pdu).unwrap() {
            ClipPdu::FileContentsRequest {
                stream_id,
                size_only,
                position,
                requested,
                ..
            } => {
                assert_eq!(stream_id, 9);
                assert!(!size_only);
                assert_eq!(position, 0x1_0000_0005);
                assert_eq!(requested, 4096);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
