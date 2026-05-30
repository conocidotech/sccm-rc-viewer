//! Standalone Phase-2 validation harness.
//!
//! Connects to a target's TCP/2701, runs the SSPI Negotiate handshake using
//! the current user's credentials, and prints the result. Validates that
//! our handshake code is wire-compatible with the real CcmExec server-side.
//!
//! Note on framing: this tool uses a simple 4-byte BE length prefix between
//! the viewer and target to delimit SSPI tokens. The real SCCM RC server may
//! use a different framing — pcap will tell us. If the handshake fails with
//! "0 bytes received" or "connection reset" right after our first SEND, the
//! framing is the prime suspect.

use clap::Parser;
use sccm_rc_protocol::handshake::SspiSession;
use sccm_rc_protocol::transport::RawConnection;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "handshake-test",
    about = "Test SSPI Negotiate handshake against an SCCM RC target on TCP/2701",
    version
)]
struct Cli {
    /// Target hostname or IP
    target: String,

    /// Send a few extra handshake rounds even after SSPI says done,
    /// to see how the server reacts to over-driving the handshake.
    #[arg(long)]
    overdrive: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_protocol=debug")))
        .init();

    let cli = Cli::parse();
    info!(target = %cli.target, "starting handshake-test");

    // --- TCP connect --------------------------------------------------------
    let mut conn = RawConnection::connect(&cli.target).await?;
    info!("TCP connected");

    // --- SSPI session -------------------------------------------------------
    let mut sspi = SspiSession::new_for_target(&cli.target)?;
    info!("SSPI credentials acquired (current user)");

    // --- Handshake loop -----------------------------------------------------
    let mut round = 0;
    let mut peer_bytes: Vec<u8> = Vec::new();
    loop {
        round += 1;
        let step = sspi.step(&peer_bytes)?;
        info!(round, our_bytes = step.output.len(), done = step.done, "ISC step");

        if !step.output.is_empty() {
            conn.send_blob(&step.output).await?;
        }

        if step.done {
            info!("handshake reported done by SSPI");
            break;
        }

        match conn.recv_blob().await? {
            Some(bytes) => {
                info!(bytes = bytes.len(), "peer responded");
                peer_bytes = bytes;
            }
            None => {
                warn!("peer closed connection mid-handshake");
                anyhow::bail!("peer closed after round {round}");
            }
        }

        if round >= 10 {
            error!("handshake didn't complete after 10 rounds — bailing");
            anyhow::bail!("handshake stuck");
        }
    }

    // --- Query stream-sizes (matches what SecurityFilter does post-handshake)
    match sspi.stream_sizes() {
        Ok(sz) => info!(
            cb_header = sz.cb_header,
            cb_trailer = sz.cb_trailer,
            cb_maximum_message = sz.cb_maximum_message,
            c_buffers = sz.c_buffers,
            cb_block_size = sz.cb_block_size,
            "stream sizes"
        ),
        Err(e) => warn!(error = %e, "stream-sizes query failed (peer may not support streaming-mode Negotiate)"),
    }

    if cli.overdrive {
        info!("--overdrive: trying one more ISC step for diagnostics");
        let step = sspi.step(&[])?;
        info!(extra_bytes = step.output.len(), done = step.done, "overdrive ISC");
    }

    info!("handshake-test completed successfully");
    Ok(())
}
