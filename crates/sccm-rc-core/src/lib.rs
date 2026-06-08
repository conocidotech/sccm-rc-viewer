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
use tracing::{debug, info, warn};

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
    /// Diagnostics: sealed frames sent / unsealed (for desync analysis).
    data_sent: u64,
    data_recvd: u64,
    /// Total unsealed (plaintext RDP) bytes received — for bandwidth analysis.
    data_recvd_bytes: u64,
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
            data_sent: 0,
            data_recvd: 0,
            data_recvd_bytes: 0,
        })
    }

    pub fn grant(&self) -> Grant {
        self.grant
    }

    /// Transport security for the UI: `(encrypted, server_verified, package)`.
    /// `encrypted` = the SSPI context negotiated confidentiality (every RDP frame
    /// is sealed/encrypted). `server_verified` = the package is Kerberos, which
    /// proves the server holds the target's service key (the SSPI equivalent of a
    /// valid certificate); NTLM authenticates us to the server but not vice-versa.
    pub fn security(&self) -> (bool, bool, Option<String>) {
        let encrypted = self.sspi.confidentiality();
        let package = self.sspi.package_name();
        let verified = package
            .as_deref()
            .map_or(false, |p| p.eq_ignore_ascii_case("Kerberos"));
        (encrypted, verified, package)
    }

    /// (sealed frames sent, unsealed frames received) — for desync diagnostics.
    pub fn seal_stats(&self) -> (u64, u64) {
        (self.data_sent, self.data_recvd)
    }

    /// Total unsealed (plaintext RDP) bytes received this session.
    pub fn recvd_bytes(&self) -> u64 {
        self.data_recvd_bytes
    }

    /// Gracefully tear down the session so the SCCM server releases the shadow /
    /// host immediately instead of holding it until a timeout (which leaves the
    /// host stuck in `HostInUse` for the next connection). Best-effort:
    ///   1. send an MCS Disconnect-Provider-Ultimatum (TPKT+X.224+MCS), sealed;
    ///   2. close the TCP write half cleanly (FIN).
    pub async fn disconnect(&mut self) {
        // TPKT(len=9) + X.224 Data(02 f0 80) + MCS DisconnectProviderUltimatum(21 80).
        const MCS_DPUM: &[u8] = &[0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80];
        if let Err(e) = self.send_rdp(MCS_DPUM).await {
            debug!(error = %e, "disconnect: MCS ultimatum send failed (already closing?)");
        } else {
            info!("sent MCS Disconnect-Provider-Ultimatum (graceful release)");
        }
        self.conn.shutdown().await;
    }

    /// Seal and send a chunk of RDP bytes as one data frame.
    pub async fn send_rdp(&mut self, rdp_bytes: &[u8]) -> Result<()> {
        let sealed = self.sspi.seal(rdp_bytes)?;
        let header = (sealed.len() as u32) | ((MSG_TYPE_DATA as u32) << 24);
        let mut wire = Vec::with_capacity(4 + sealed.len());
        wire.extend_from_slice(&header.to_le_bytes());
        wire.extend_from_slice(&sealed);
        self.conn.send_raw(&wire).await?;
        self.data_sent += 1;
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
            debug!(
                msg_type = format_args!("{:#04x}", frame.msg_type),
                body_len = frame.body.len(),
                "recv_rdp: frame from server"
            );
            if frame.msg_type != MSG_TYPE_DATA {
                // Unencrypted control frame — unusual mid-session; skip.
                debug!(msg_type = format_args!("{:#04x}", frame.msg_type), "skipped non-data frame");
                continue;
            }
            let plain = match self.sspi.unseal(&frame.body) {
                Ok(p) => {
                    self.data_recvd += 1;
                    self.data_recvd_bytes += p.len() as u64;
                    p
                }
                Err(e) => {
                    let head: Vec<String> =
                        frame.body.iter().take(24).map(|b| format!("{b:02x}")).collect();
                    warn!(
                        error = %e,
                        body_len = frame.body.len(),
                        data_recvd = self.data_recvd,
                        data_sent = self.data_sent,
                        head = %head.join(" "),
                        "unseal FAILED — sealed-stream desync"
                    );
                    return Err(e.into());
                }
            };
            // Skip only KNOWN SCCM data-phase control strings (status updates).
            // Anything else — including all RDP graphics — is returned as-is.
            // (The previous heuristic "looks like ASCII" risked dropping RDP
            // PDUs whose bytes happened to be printable.)
            if let Some(s) = decode_control_utf16(&plain) {
                if is_sccm_control_keyword(&s) {
                    debug!(control = %s, "skipped sealed control message");
                    continue;
                }
            }
            return Ok(Some(plain));
        }
    }
}

/// Is this string one of the known SCCM data-phase control keywords?
fn is_sccm_control_keyword(s: &str) -> bool {
    s.starts_with("SUCCESS_")
        || s.starts_with("ERROR_")
        || s.starts_with("START_")
        || s == "STOP_HANDSHAKE"
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
