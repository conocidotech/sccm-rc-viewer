//! Phase-3 validation: after a full handshake, exercise the SecurityFilter
//! data phase (seal/unseal) against a real SCCM RC target.
//!
//! Verifies:
//!   1. seal() produces a GSS wrap token starting `05 04 06 ff` (Kerberos
//!      initiator flags) — byte-identical token format to the real viewer.
//!   2. Sends a minimal RDP X.224 Connection Request, sealed, and reports
//!      whatever the server replies (sealed frame = our seal is wire-correct;
//!      we then unseal it and check for an X.224 Connection Confirm).

use clap::Parser;
use sccm_rc_protocol::framing::{self, MSG_TYPE_CONTROL, MSG_TYPE_DATA};
use sccm_rc_protocol::handshake::SspiSession;
use sccm_rc_protocol::transport::RawConnection;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "data-phase-test",
    about = "Test SecurityFilter seal/unseal against an SCCM RC target",
    version
)]
struct Cli {
    target: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_protocol=debug")),
        )
        .init();
    let cli = Cli::parse();

    let mut conn = RawConnection::connect(&cli.target).await?;
    info!("TCP connected");

    // greeting
    let g = conn
        .recv_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no greeting"))?;
    info!(greeting = %framing::decode_control_string(&g.body).unwrap_or_default(), "greeting");

    // handshake
    let mut sspi = SspiSession::new_for_target(&cli.target)?;
    let mut peer = Vec::new();
    let mut round = 0;
    loop {
        round += 1;
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
            .ok_or_else(|| anyhow::anyhow!("closed mid-handshake"))?;
        if f.msg_type == MSG_TYPE_CONTROL {
            anyhow::bail!(
                "server rejected: {}",
                framing::decode_control_string(&f.body).unwrap_or_default()
            );
        }
        peer = framing::decode_handshake_body(&f.body)
            .ok_or_else(|| anyhow::anyhow!("bad token"))?
            .to_vec();
        if round >= 10 {
            anyhow::bail!("no convergence");
        }
    }
    info!("handshake complete");
    let sizes = sspi.message_sizes()?;
    info!(?sizes, "context sizes");

    // --- 1. seal a probe and verify token format ---------------------------
    let probe_plain = b"sccm-rc data-phase probe";
    let sealed = sspi.seal(probe_plain)?;
    // body = [u16 dataLen][data][u16 tokenLen][token]
    let data_len = u16::from_le_bytes([sealed[0], sealed[1]]) as usize;
    let tok_off = 2 + data_len + 2;
    let token_head = &sealed[tok_off..(tok_off + 4).min(sealed.len())];
    info!(
        sealed_len = sealed.len(),
        data_len,
        token_head = format!("{token_head:02x?}"),
        "sealed probe"
    );
    if token_head.starts_with(&[0x05, 0x04, 0x06, 0xff]) {
        info!("✓ token format matches real viewer (Kerberos wrap, initiator flags 05 04 06 ff)");
    } else {
        warn!("token head differs from expected 05 04 06 ff — investigate");
    }

    // roundtrip self-check is not possible (encrypt uses local→remote key,
    // decrypt uses remote→local), so we verify structure only here.

    // --- 2. send a minimal RDP X.224 Connection Request, observe reply -----
    let x224_cr: &[u8] = &[
        0x03, 0x00, 0x00, 0x13, // TPKT header, total len 19
        0x0e, // X.224 LI = 14
        0xe0, // CR
        0x00, 0x00, // dst-ref
        0x00, 0x00, // src-ref
        0x00, // class 0
        0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ: type=1, flags=0, len=8
        0x00, 0x00, 0x00, 0x00, // requestedProtocols = PROTOCOL_RDP (standard)
    ];
    let sealed_cr = sspi.seal(x224_cr)?;
    let frame = make_data_frame(&sealed_cr);
    info!(
        plain = x224_cr.len(),
        wire = frame.len(),
        "sending sealed X.224 Connection Request"
    );
    conn.send_raw(&frame).await?;

    match conn.recv_frame().await? {
        Some(f) if f.msg_type == MSG_TYPE_CONTROL => {
            let s = framing::decode_control_string(&f.body).unwrap_or_default();
            warn!(control = %s, "server replied with control message (not a sealed data frame)");
        }
        Some(f) if f.msg_type == MSG_TYPE_DATA => {
            info!(
                body_len = f.body.len(),
                "server replied with a DATA frame — attempting unseal"
            );
            match sspi.unseal(&f.body) {
                Ok(plain) => {
                    info!(plain_len = plain.len(), "✓ UNSEAL SUCCEEDED");
                    // Try decoding as a SCCM control string (UTF-16LE, possibly
                    // with a leading u16 length like the unencrypted control msgs).
                    let as_str = decode_maybe_control(&plain);
                    if let Some(s) = &as_str {
                        info!(decrypted_string = %s, "✓✓ server data-phase control message");
                    }
                    if plain.starts_with(&[0x03, 0x00]) {
                        info!("plaintext is a TPKT/X.224 PDU — RDP handshake engaged!");
                    } else if as_str.is_none() {
                        info!(
                            head = format!("{:02x?}", &plain[..plain.len().min(24)]),
                            "plaintext (not string/TPKT)"
                        );
                    }
                }
                Err(e) => error!(error = %e, "unseal failed — our codec or key direction is off"),
            }
        }
        Some(f) => warn!(
            msg_type = format!("0x{:02x}", f.msg_type),
            "unexpected frame type"
        ),
        None => warn!("server closed connection without replying"),
    }

    Ok(())
}

/// Decode a decrypted SCCM control payload. The data-phase control strings
/// are raw UTF-16LE (no length prefix, unlike the unencrypted greeting).
fn decode_maybe_control(plain: &[u8]) -> Option<String> {
    // Try raw UTF-16LE first, then a u16-length-prefixed variant.
    for start in [0usize, 2usize] {
        if start > plain.len() {
            continue;
        }
        let utf16: Vec<u16> = plain[start..]
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16_lossy(&utf16);
        let s = s.trim_end_matches('\u{0}');
        if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == '_') {
            return Some(s.to_string());
        }
    }
    None
}

/// Wrap a sealed body in a type-0x00 outer frame.
fn make_data_frame(sealed_body: &[u8]) -> Vec<u8> {
    let header = (sealed_body.len() as u32) | ((MSG_TYPE_DATA as u32) << 24);
    let mut v = Vec::with_capacity(4 + sealed_body.len());
    v.extend_from_slice(&header.to_le_bytes());
    v.extend_from_slice(sealed_body);
    v
}
