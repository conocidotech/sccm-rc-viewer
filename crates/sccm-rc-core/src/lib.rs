//! High-level SCCM Remote Control session.
//!
//! Encapsulates the full bring-up — TCP/2701, the unencrypted greeting,
//! the SSPI Negotiate handshake, and the data-phase control grant — and
//! then exposes a sealed byte-channel (`send_rdp` / `recv_rdp`) that carries
//! the RDP stream. The RDP layer (IronRDP) sits on top of this channel.

#![forbid(unsafe_op_in_unsafe_fn)]

use sccm_rc_protocol::framing::{self, MSG_TYPE_CONTROL, MSG_TYPE_DATA};
use sccm_rc_protocol::handshake::SspiSession;
use sccm_rc_protocol::transport::RawConnection;
use sccm_rc_protocol::{Error, Result};
use tracing::{debug, info};

pub mod rdp;

/// The access level the target granted for this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    FullControl,
    ViewOnly,
}

/// An authenticated, sealed SCCM RC session ready to carry RDP.
pub struct SccmSession {
    conn: RawConnection,
    sspi: SspiSession,
    grant: Grant,
    /// Leftover decrypted RDP bytes not yet consumed by the caller.
    rx_buf: Vec<u8>,
}

impl std::fmt::Debug for SccmSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SccmSession")
            .field("grant", &self.grant)
            .field("buffered_rx", &self.rx_buf.len())
            .finish()
    }
}

impl SccmSession {
    /// Connect, authenticate (SSO via current user), and read the access
    /// grant. After this returns, RDP can flow via `send_rdp`/`recv_rdp`.
    pub async fn connect(target: &str) -> Result<Self> {
        let mut conn = RawConnection::connect(target).await?;
        info!(%target, "TCP connected");

        // 1. greeting (unencrypted control message)
        let greeting = conn
            .recv_frame()
            .await?
            .ok_or_else(|| Error::Protocol("closed before greeting".into()))?;
        let g = framing::decode_control_string(&greeting.body).unwrap_or_default();
        debug!(greeting = %g, "server greeting");
        if g != "START_HANDSHAKE" {
            return Err(Error::Protocol(format!("unexpected greeting: {g}")));
        }

        // 2. SSPI Negotiate handshake
        let mut sspi = SspiSession::new_for_target(target)?;
        let mut peer: Vec<u8> = Vec::new();
        loop {
            let step = sspi.step(&peer)?;
            if !step.output.is_empty() {
                conn.send_handshake_token(&step.output).await?;
            }
            if step.done {
                break;
            }
            let f = conn
                .recv_frame()
                .await?
                .ok_or_else(|| Error::Protocol("closed mid-handshake".into()))?;
            if f.msg_type == MSG_TYPE_CONTROL {
                let s = framing::decode_control_string(&f.body).unwrap_or_default();
                return Err(Error::Protocol(format!("server rejected handshake: {s}")));
            }
            peer = framing::decode_handshake_body(&f.body)
                .ok_or_else(|| Error::Protocol("malformed handshake token".into()))?
                .to_vec();
        }
        sspi.message_sizes()?; // establishes + caches the sealing sizes
        info!("SSPI handshake complete");

        // 3. data-phase control grant
        let grant_frame = conn
            .recv_frame()
            .await?
            .ok_or_else(|| Error::Protocol("closed before grant".into()))?;
        let grant_plain = sspi.unseal(&grant_frame.body)?;
        let grant_str = decode_control_utf16(&grant_plain)
            .ok_or_else(|| Error::Protocol("grant not a control string".into()))?;
        let grant = match grant_str.as_str() {
            "SUCCESS_FULL_CONTROL" => Grant::FullControl,
            "SUCCESS_VIEW_ONLY" => Grant::ViewOnly,
            other => return Err(Error::Protocol(format!("access not granted: {other}"))),
        };
        info!(?grant, "remote control session granted");

        Ok(Self {
            conn,
            sspi,
            grant,
            rx_buf: Vec::new(),
        })
    }

    pub fn grant(&self) -> Grant {
        self.grant
    }

    /// Seal and send a chunk of RDP bytes as one data frame.
    pub async fn send_rdp(&mut self, rdp_bytes: &[u8]) -> Result<()> {
        let sealed = self.sspi.seal(rdp_bytes)?;
        let header = (sealed.len() as u32) | ((MSG_TYPE_DATA as u32) << 24);
        let mut wire = Vec::with_capacity(4 + sealed.len());
        wire.extend_from_slice(&header.to_le_bytes());
        wire.extend_from_slice(&sealed);
        self.conn.send_raw(&wire).await?;
        debug!(rdp_bytes = rdp_bytes.len(), "sent sealed RDP");
        Ok(())
    }

    /// Receive the next chunk of RDP bytes. Transparently unseals data
    /// frames and surfaces (but skips) any interleaved control messages,
    /// returning them via `last_control`. Returns `Ok(None)` on clean close.
    pub async fn recv_rdp(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.rx_buf.is_empty() {
            return Ok(Some(std::mem::take(&mut self.rx_buf)));
        }
        loop {
            let frame = match self.conn.recv_frame().await? {
                Some(f) => f,
                None => return Ok(None),
            };
            if frame.msg_type != MSG_TYPE_DATA {
                // Unencrypted control frame — unusual mid-session; skip.
                continue;
            }
            let plain = self.sspi.unseal(&frame.body)?;
            // A sealed control string (e.g. a status update) — skip; the
            // caller only wants RDP bytes.
            if decode_control_utf16(&plain).is_some() && !plain.starts_with(&[0x03, 0x00]) {
                debug!("skipped sealed control message");
                continue;
            }
            return Ok(Some(plain));
        }
    }
}

/// Decode a decrypted SCCM control payload (raw UTF-16LE, no length prefix).
fn decode_control_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return None;
    }
    let u: Vec<u16> = bytes
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&u);
    let s = s.trim_end_matches('\u{0}');
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == '_') {
        Some(s.to_string())
    } else {
        None
    }
}
