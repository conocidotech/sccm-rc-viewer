//! Low-level TCP/2701 transport — used both raw (before SSPI handshake)
//! and as the carrier for SecurityFilter-wrapped messages once authenticated.

use crate::framing::{self, MsgHeader};
use crate::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

/// A complete SCCM RC message: its type byte + body bytes (header stripped).
#[derive(Debug, Clone)]
pub struct Frame {
    pub msg_type: u8,
    pub body: Vec<u8>,
}

/// Standard SCCM Remote Control listening port on the target's CcmExec service.
pub const SCCM_RC_PORT: u16 = 2701;

/// A raw TCP connection to an SCCM RC target.
///
/// During the handshake phase, callers use `send_blob` / `recv_blob` to
/// exchange opaque SSPI-token byte runs. After handshake the same
/// `TcpStream` is wrapped in a `SecFilter` for per-message encryption.
#[derive(Debug)]
pub struct RawConnection {
    stream: TcpStream,
    /// Persistent receive buffer. `recv_frame` parses whole frames out of this and
    /// tops it up with a SINGLE cancel-safe read. This makes `recv_frame`
    /// cancel-safe: if its future is dropped (e.g. it loses a `tokio::select!`
    /// race against an input event in the active session), no partially-read bytes
    /// are lost — they stay buffered here. (`read_exact` into a local buffer would
    /// discard them on cancel, desyncing the sealed TPKT framing → session crash.)
    rxbuf: Vec<u8>,
}

impl RawConnection {
    pub async fn connect(host: &str) -> Result<Self> {
        let addr = format!("{host}:{SCCM_RC_PORT}");
        debug!(%addr, "TCP connect");
        let stream = TcpStream::connect(&addr).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                Error::Refused
            } else {
                Error::Io(e)
            }
        })?;
        // Disable Nagle: this is an interactive remote-control stream, so small
        // input/ack frames must go out immediately rather than being batched
        // (Nagle adds up to ~40 ms of latency to every keystroke/mouse move).
        let _ = stream.set_nodelay(true);
        // Enable TCP keepalive so a silently-dropped connection (VPN drop, peer
        // gone, a long-idle screen) is detected by the OS instead of blocking
        // recv_rdp forever. Probes start after 10 s idle, every 3 s; once the OS
        // gives up it errors the socket, which surfaces as a read error → the
        // active session ends → the viewer's reconnect loop takes over and shows
        // "reconnecting" status (rather than freezing on a dead link). Best-effort.
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(10))
            .with_interval(std::time::Duration::from_secs(3));
        let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive);
        Ok(Self { stream, rxbuf: Vec::new() })
    }

    /// Write a length-prefixed blob. Used during SSPI handshake to send each
    /// token: 4-byte big-endian length + payload. (Framing format TBD — pcap
    /// will confirm. For now we use a simple length-prefix to make
    /// peer-side test stubs easy.)
    pub async fn send_blob(&mut self, payload: &[u8]) -> Result<()> {
        let len = payload.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(payload).await?;
        self.stream.flush().await?;
        debug!(bytes = payload.len(), "sent blob");
        Ok(())
    }

    /// Read a length-prefixed blob, matching `send_blob`. Returns `Ok(None)`
    /// on clean EOF, `Err(Io)` on read errors, `Ok(Some(bytes))` on success.
    pub async fn recv_blob(&mut self) -> Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            return Err(Error::Protocol(format!(
                "implausibly-large blob length: {len} bytes"
            )));
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        debug!(bytes = len, "recv blob");
        Ok(Some(buf))
    }

    /// Diagnostic: read up to `max` bytes with a deadline, ignoring all
    /// framing assumptions. Used during protocol discovery to hex-dump
    /// whatever the server sends without imposing structure.
    pub async fn recv_raw_until_idle(&mut self, max: usize, idle: std::time::Duration) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; max];
        let mut filled = 0;
        loop {
            let remaining = &mut buf[filled..];
            if remaining.is_empty() {
                break;
            }
            let read = tokio::time::timeout(idle, self.stream.read(remaining)).await;
            match read {
                Ok(Ok(0)) => break,                       // EOF
                Ok(Ok(n)) => filled += n,
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_) => break,                          // idle timeout — peer paused
            }
        }
        buf.truncate(filled);
        Ok(buf)
    }

    /// Write raw bytes without any framing. Counterpart to `recv_raw_until_idle`.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    // ---- SCCM-framed I/O (the real wire format) ---------------------------

    /// Send an SSPI handshake token, framed as the real viewer does:
    /// `[u32 LE header (type=0x00)][u16 LE token_len][token]`.
    pub async fn send_handshake_token(&mut self, token: &[u8]) -> Result<()> {
        let wire = framing::encode_handshake_token(token);
        self.stream.write_all(&wire).await?;
        self.stream.flush().await?;
        debug!(token_bytes = token.len(), wire_bytes = wire.len(), "sent handshake token");
        Ok(())
    }

    /// Read one complete SCCM frame: parse the 4-byte header, then `body_len`
    /// bytes. Cancel-safe — frames are parsed out of a persistent buffer that is
    /// topped up with a single cancel-safe `read`, so dropping this future (e.g.
    /// losing a `tokio::select!` race) never loses partially-read bytes. Returns
    /// `Ok(None)` on clean EOF at a frame boundary.
    pub async fn recv_frame(&mut self) -> Result<Option<Frame>> {
        loop {
            // Parse a complete frame out of the buffer if one is fully present.
            if self.rxbuf.len() >= 4 {
                let MsgHeader { msg_type, body_len } =
                    framing::parse_header(&self.rxbuf[..4]).expect("4 bytes is always parseable");
                if body_len > 8 * 1024 * 1024 {
                    return Err(Error::Protocol(format!(
                        "implausibly-large frame body: {body_len} bytes"
                    )));
                }
                let total = 4 + body_len;
                if self.rxbuf.len() >= total {
                    let body = self.rxbuf[4..total].to_vec();
                    self.rxbuf.drain(..total);
                    debug!(msg_type = format!("0x{msg_type:02x}"), body_len, "recv frame");
                    return Ok(Some(Frame { msg_type, body }));
                }
            }
            // Need more bytes. A SINGLE `read` is cancel-safe: if this future is
            // dropped mid-await no bytes are consumed, and bytes already buffered
            // from earlier reads are retained.
            self.rxbuf.reserve(16 * 1024);
            let n = self.stream.read_buf(&mut self.rxbuf).await?;
            if n == 0 {
                return if self.rxbuf.is_empty() {
                    Ok(None) // clean EOF on a frame boundary
                } else {
                    Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed mid-frame",
                    )))
                };
            }
        }
    }

    /// Gracefully shut down the write half (TCP FIN) so the peer sees a clean
    /// close rather than a reset. Best-effort.
    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}
