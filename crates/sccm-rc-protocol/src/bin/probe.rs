//! Diagnostic probe: connect to TCP/2701, optionally send the first SSPI
//! NEGOTIATE token, and hexdump everything the server sends back.
//!
//! Used during Phase 2 framing discovery — no assumptions about wire
//! format other than "TCP, send some bytes, read some bytes".

use clap::Parser;
use sccm_rc_protocol::handshake::SspiSession;
use sccm_rc_protocol::transport::RawConnection;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "probe", about = "Connect to TCP/2701 and hexdump the server's reply", version)]
struct Cli {
    /// Target hostname or IP
    target: String,

    /// Skip the SSPI step — just connect, send nothing, see if server speaks first.
    #[arg(long)]
    connect_only: bool,

    /// Send only the raw SSPI token bytes, with no framing/wrapper at all.
    #[arg(long, conflicts_with_all = ["connect_only", "framed_be32"])]
    raw: bool,

    /// Send with a 4-byte big-endian length prefix.
    #[arg(long, conflicts_with_all = ["connect_only", "raw"])]
    framed_be32: bool,

    /// Send with a 4-byte little-endian length prefix.
    #[arg(long, conflicts_with_all = ["connect_only", "raw", "framed_be32"])]
    framed_le32: bool,

    /// Idle timeout per read (ms) — controls when we declare "server is done sending".
    #[arg(long, default_value_t = 2000)]
    idle_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_protocol=debug")))
        .init();
    let cli = Cli::parse();

    let mut conn = RawConnection::connect(&cli.target).await?;
    info!("TCP connected");

    if !cli.connect_only {
        let mut sspi = SspiSession::new_for_target(&cli.target)?;
        let step = sspi.step(&[])?;
        info!(token_bytes = step.output.len(), "got initial NEGOTIATE token from SSPI");

        hexdump("→ NEGOTIATE token", &step.output);

        let to_send: Vec<u8> = if cli.raw {
            step.output.clone()
        } else if cli.framed_be32 {
            let mut v = Vec::with_capacity(4 + step.output.len());
            v.extend_from_slice(&(step.output.len() as u32).to_be_bytes());
            v.extend_from_slice(&step.output);
            v
        } else if cli.framed_le32 {
            let mut v = Vec::with_capacity(4 + step.output.len());
            v.extend_from_slice(&(step.output.len() as u32).to_le_bytes());
            v.extend_from_slice(&step.output);
            v
        } else {
            anyhow::bail!("pick one of --raw, --framed-be32, --framed-le32, --connect-only");
        };

        info!(send_bytes = to_send.len(), "sending");
        conn.send_raw(&to_send).await?;
    }

    let idle = Duration::from_millis(cli.idle_ms);
    info!("reading until {}ms idle (or 65536 bytes)…", cli.idle_ms);
    let buf = conn.recv_raw_until_idle(65536, idle).await?;
    info!(received = buf.len(), "server response");
    hexdump("← server reply", &buf);
    Ok(())
}

fn hexdump(label: &str, bytes: &[u8]) {
    println!("\n== {label} ({} bytes) ==", bytes.len());
    if bytes.is_empty() {
        println!("  (empty)");
        return;
    }
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        let hex_str = hex.join(" ");
        println!("  {:04x}  {:<48}  {ascii}", i * 16, hex_str);
        if i >= 31 {
            println!("  …  (truncated)");
            break;
        }
    }
}
