//! SCCM RC message framing — discovered + confirmed against a real target.
//!
//! Wire format (see `docs/SPEC.md` § 0):
//! ```text
//!   [u32 LE header] [body...]
//!   header: low 24 bits = body length, high byte = message type
//! ```
//! Message types:
//! - 0x80 = control: body is `[u16 LE strlen][UTF-16LE string][00 00]`
//! - 0x00 = data/SSPI:
//!     - during handshake: body is `[u16 LE token_len][SSPI token]`
//!     - post-handshake:   body is the SecurityFilter-wrapped chunk

pub const MSG_TYPE_DATA: u8 = 0x00;
pub const MSG_TYPE_CONTROL: u8 = 0x80;

/// Encode an SSPI handshake token as a complete on-wire message:
/// outer frame header + inner u16 length prefix + token.
pub fn encode_handshake_token(token: &[u8]) -> Vec<u8> {
    let inner_len = token.len();
    let body_len = 2 + inner_len;
    let header = (body_len as u32) | ((MSG_TYPE_DATA as u32) << 24);
    let mut v = Vec::with_capacity(4 + body_len);
    v.extend_from_slice(&header.to_le_bytes());
    v.extend_from_slice(&(inner_len as u16).to_le_bytes());
    v.extend_from_slice(token);
    v
}

/// Parsed message header.
#[derive(Debug, Clone, Copy)]
pub struct MsgHeader {
    pub msg_type: u8,
    pub body_len: usize,
}

/// Parse the 4-byte frame header.
pub fn parse_header(bytes: &[u8]) -> Option<MsgHeader> {
    if bytes.len() < 4 {
        return None;
    }
    let hdr = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Some(MsgHeader {
        msg_type: (hdr >> 24) as u8,
        body_len: (hdr & 0x00ff_ffff) as usize,
    })
}

/// Extract the inner SSPI token from a handshake-message body
/// (`[u16 LE len][token]`).
pub fn decode_handshake_body(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 2 {
        return None;
    }
    let inner_len = u16::from_le_bytes([body[0], body[1]]) as usize;
    if 2 + inner_len > body.len() {
        return None;
    }
    Some(&body[2..2 + inner_len])
}

/// Decode a control message body (`[u16 LE strlen][UTF-16LE][00 00]`) to a String.
pub fn decode_control_string(body: &[u8]) -> Option<String> {
    if body.len() < 2 {
        return None;
    }
    let slen = u16::from_le_bytes([body[0], body[1]]) as usize;
    if 2 + slen > body.len() {
        return None;
    }
    let utf16: Vec<u16> = body[2..2 + slen]
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
        .collect();
    Some(String::from_utf16_lossy(&utf16).trim_end_matches('\u{0}').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_handshake_token() {
        let token = b"\x60\x82\x0d\x63 fake AP-REQ";
        let wire = encode_handshake_token(token);
        // header
        let h = parse_header(&wire).unwrap();
        assert_eq!(h.msg_type, MSG_TYPE_DATA);
        assert_eq!(h.body_len, 2 + token.len());
        // body
        let body = &wire[4..];
        assert_eq!(decode_handshake_body(body).unwrap(), token);
    }

    #[test]
    fn parses_real_ap_rep_header() {
        // From the live capture: bb 00 00 00 b9 00 a1 81 b6 ...
        let wire = [0xbb, 0x00, 0x00, 0x00, 0xb9, 0x00, 0xa1, 0x81, 0xb6];
        let h = parse_header(&wire).unwrap();
        assert_eq!(h.msg_type, 0x00);
        assert_eq!(h.body_len, 0xbb); // 187
    }

    #[test]
    fn decodes_start_handshake_control() {
        // 20 00 then "START_HANDSHAKE" in UTF-16LE then 00 00
        let mut body = vec![0x20, 0x00];
        for ch in "START_HANDSHAKE".encode_utf16() {
            body.extend_from_slice(&ch.to_le_bytes());
        }
        body.extend_from_slice(&[0, 0]);
        assert_eq!(decode_control_string(&body).as_deref(), Some("START_HANDSHAKE"));
    }
}
