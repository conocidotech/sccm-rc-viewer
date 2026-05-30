//! Explore the SCCM data-phase → RDP handoff.
//!
//! Flow under test (from RE + capture):
//!   1. TCP + greeting + SSPI handshake
//!   2. server sends sealed grant: SUCCESS_FULL_CONTROL / SUCCESS_VIEW_ONLY
//!      / ERROR_ACCESS_DENIED
//!   3. on a SUCCESS_* grant, the RDP stream begins — client sends a sealed
//!      X.224 Connection Request, server replies with X.224 Connection Confirm
//!
//! We log every decrypted frame and classify it (control string vs RDP TPKT).

use clap::Parser;
use sccm_rc_protocol::framing::{self, MSG_TYPE_CONTROL, MSG_TYPE_DATA};
use sccm_rc_protocol::handshake::SspiSession;
use sccm_rc_protocol::transport::RawConnection;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rdp-explore", about = "Drive SCCM data phase to the RDP X.224 exchange", version)]
struct Cli {
    target: String,
    /// How many post-grant frames to read while exploring.
    #[arg(long, default_value_t = 6)]
    rounds: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let cli = Cli::parse();

    let mut conn = RawConnection::connect(&cli.target).await?;
    info!("TCP connected");

    // greeting
    let g = conn.recv_frame().await?.ok_or_else(|| anyhow::anyhow!("no greeting"))?;
    info!(greeting = %framing::decode_control_string(&g.body).unwrap_or_default(), "greeting");

    // handshake
    let mut sspi = SspiSession::new_for_target(&cli.target)?;
    let mut peer = Vec::new();
    loop {
        let step = sspi.step(&peer)?;
        if !step.output.is_empty() {
            conn.send_handshake_token(&step.output).await?;
        }
        if step.done {
            break;
        }
        let f = conn.recv_frame().await?.ok_or_else(|| anyhow::anyhow!("closed mid-handshake"))?;
        if f.msg_type == MSG_TYPE_CONTROL {
            anyhow::bail!("rejected: {}", framing::decode_control_string(&f.body).unwrap_or_default());
        }
        peer = framing::decode_handshake_body(&f.body).ok_or_else(|| anyhow::anyhow!("bad token"))?.to_vec();
    }
    sspi.message_sizes()?;
    info!("handshake complete — entering data phase");

    let mut sent_x224 = false;
    for round in 1..=cli.rounds {
        let frame = match conn.recv_frame().await? {
            Some(f) => f,
            None => {
                warn!("server closed");
                break;
            }
        };
        if frame.msg_type != MSG_TYPE_DATA {
            info!(round, msg_type = format!("0x{:02x}", frame.msg_type), "non-data frame");
            continue;
        }
        let plain = match sspi.unseal(&frame.body) {
            Ok(p) => p,
            Err(e) => {
                warn!(round, error = %e, "unseal failed");
                continue;
            }
        };

        // Classify the decrypted payload.
        if let Some(s) = as_utf16_string(&plain) {
            info!(round, control = %s, plain_len = plain.len(), "← control message");
            if (s.starts_with("SUCCESS_")) && !sent_x224 {
                // RDP begins — send X.224 Connection Request.
                let cr = x224_connection_request();
                let sealed = sspi.seal(&cr)?;
                conn.send_raw(&data_frame(&sealed)).await?;
                sent_x224 = true;
                info!("→ sent sealed X.224 Connection Request ({} bytes plain)", cr.len());
            } else if s.starts_with("ERROR_") {
                warn!("server denied: {s}");
                break;
            }
        } else if plain.starts_with(&[0x03, 0x00]) {
            // TPKT — RDP!
            let tpkt_len = u16::from_be_bytes([plain[2], plain[3]]) as usize;
            let x224_type = plain.get(5).copied().unwrap_or(0);
            let kind = match x224_type & 0xf0 {
                0xd0 => "X.224 Connection Confirm",
                0xe0 => "X.224 Connection Request",
                0xf0 => "X.224 Data (RDP PDU)",
                _ => "X.224 ?",
            };
            info!(round, tpkt_len, x224 = kind, "← ✓✓ RDP TPKT PDU — RDP stream is live!");
            hexdump(&plain);
        } else {
            info!(round, plain_len = plain.len(), head = format!("{:02x?}", &plain[..plain.len().min(16)]), "← binary (non-TPKT)");
        }
    }

    Ok(())
}

fn as_utf16_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return None;
    }
    let u: Vec<u16> = bytes.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let s = String::from_utf16_lossy(&u);
    let s = s.trim_end_matches('\u{0}');
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == '_') {
        Some(s.to_string())
    } else {
        None
    }
}

/// Minimal RDP X.224 Connection Request with RDP Negotiation Request.
fn x224_connection_request() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x13, // TPKT, total 19
        0x0e,                   // X.224 LI=14
        0xe0,                   // CR
        0x00, 0x00,             // dst-ref
        0x00, 0x00,             // src-ref
        0x00,                   // class 0
        0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ type=1 flags=0 len=8
        0x00, 0x00, 0x00, 0x00, // requestedProtocols = PROTOCOL_RDP
    ]
}

fn data_frame(sealed: &[u8]) -> Vec<u8> {
    let header = (sealed.len() as u32) | ((MSG_TYPE_DATA as u32) << 24);
    let mut v = Vec::with_capacity(4 + sealed.len());
    v.extend_from_slice(&header.to_le_bytes());
    v.extend_from_slice(sealed);
    v
}

fn hexdump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).take(8).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
        println!("   {:04x}  {:<48}  {ascii}", i * 16, hex.join(" "));
    }
}
