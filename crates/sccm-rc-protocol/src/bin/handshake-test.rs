//! Full SSPI Negotiate handshake against a real SCCM RC target.
//!
//! Flow (confirmed via pcap, see docs/SPEC.md):
//!   1. connect TCP/2701
//!   2. recv server greeting (control "START_HANDSHAKE")
//!   3. loop:
//!        - SSPI step → get our token
//!        - send token framed as [u32 hdr][u16 token_len][token]
//!        - if SSPI says done, break
//!        - recv server frame, extract inner token, feed back into SSPI
//!   4. query stream sizes — proves the context is fully established

use clap::Parser;
use sccm_rc_protocol::framing::{self, MSG_TYPE_CONTROL, MSG_TYPE_DATA};
use sccm_rc_protocol::handshake::SspiSession;
use sccm_rc_protocol::transport::RawConnection;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "handshake-test",
    about = "Full SSPI handshake against an SCCM RC target on TCP/2701",
    version
)]
struct Cli {
    /// Target hostname or IP
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
    info!(target = %cli.target, "starting full handshake-test");

    let mut conn = RawConnection::connect(&cli.target).await?;
    info!("TCP connected");

    // --- 1. server greeting -------------------------------------------------
    match conn.recv_frame().await? {
        Some(frame) if frame.msg_type == MSG_TYPE_CONTROL => {
            let s = framing::decode_control_string(&frame.body).unwrap_or_default();
            info!(greeting = %s, "server greeting");
            if s != "START_HANDSHAKE" {
                warn!("unexpected greeting (continuing anyway)");
            }
        }
        Some(frame) => anyhow::bail!("expected control greeting, got type 0x{:02x}", frame.msg_type),
        None => anyhow::bail!("server closed before greeting"),
    }

    // --- 2. SSPI session + handshake loop ----------------------------------
    let mut sspi = SspiSession::new_for_target(&cli.target)?;
    info!("SSPI credentials acquired (current user)");

    let mut peer_token: Vec<u8> = Vec::new();
    let mut round = 0;
    loop {
        round += 1;
        let step = sspi.step(&peer_token)?;
        info!(round, our_token = step.output.len(), done = step.done, "ISC step");

        if !step.output.is_empty() {
            conn.send_handshake_token(&step.output).await?;
        }

        if step.done {
            info!("SSPI handshake complete");
            break;
        }

        // Need another leg — read the server's reply.
        let frame = match conn.recv_frame().await? {
            Some(f) => f,
            None => anyhow::bail!("server closed mid-handshake after round {round}"),
        };

        if frame.msg_type == MSG_TYPE_CONTROL {
            let s = framing::decode_control_string(&frame.body).unwrap_or_default();
            error!(control = %s, "server sent control message instead of token — handshake rejected");
            anyhow::bail!("server rejected handshake: {s}");
        }
        if frame.msg_type != MSG_TYPE_DATA {
            anyhow::bail!("unexpected frame type 0x{:02x}", frame.msg_type);
        }

        let token = framing::decode_handshake_body(&frame.body)
            .ok_or_else(|| anyhow::anyhow!("malformed handshake body"))?;
        info!(server_token = token.len(), "server token received");
        peer_token = token.to_vec();

        if round >= 10 {
            anyhow::bail!("handshake did not converge after 10 rounds");
        }
    }

    // --- 3. query message sizes (proves context is live) ------------------
    match sspi.message_sizes() {
        Ok(sz) => info!(
            cb_max_token = sz.cb_max_token,
            cb_max_signature = sz.cb_max_signature,
            cb_block_size = sz.cb_block_size,
            cb_security_trailer = sz.cb_security_trailer,
            "message sizes — context established ✓"
        ),
        Err(e) => warn!(error = %e, "message-sizes query failed"),
    }

    info!("✅ full handshake succeeded — authenticated pure-Rust session");
    Ok(())
}
