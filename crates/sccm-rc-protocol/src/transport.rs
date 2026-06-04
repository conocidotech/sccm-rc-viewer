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
        Ok(Self { stream })
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

    /// Read one complete SCCM frame: parse the 4-byte header, then read
    /// exactly `body_len` bytes (handling TCP segmentation). Returns
    /// `Ok(None)` on clean EOF before any header.
    pub async fn recv_frame(&mut self) -> Result<Option<Frame>> {
        let mut hdr_buf = [0u8; 4];
        match self.stream.read_exact(&mut hdr_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }
        let MsgHeader { msg_type, body_len } =
            framing::parse_header(&hdr_buf).expect("4 bytes is always parseable");
        if body_len > 8 * 1024 * 1024 {
            return Err(Error::Protocol(format!(
                "implausibly-large frame body: {body_len} bytes"
            )));
        }
        let mut body = vec![0u8; body_len];
        self.stream.read_exact(&mut body).await?;
        debug!(msg_type = format!("0x{msg_type:02x}"), body_len, "recv frame");
        Ok(Some(Frame { msg_type, body }))
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
