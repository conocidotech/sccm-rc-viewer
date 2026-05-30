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

    /// Send using the discovered SCCM framing: u32 LE where high byte is
    /// the message-type flag and low 24 bits are the body length.
    /// Specify the type byte (0 = data, 0x80 = control string).
    #[arg(long, value_parser = parse_hex_u8)]
    sccm: Option<u8>,

    /// Like --sccm but also prepend a u16 LE length prefix INSIDE the body,
    /// before the SSPI token (the inner framing we found in the real capture:
    /// handshake body = [u16 token_len][token]).
    #[arg(long, value_parser = parse_hex_u8)]
    sccm_innerlen: Option<u8>,

    /// First read the server's greeting, then send our reply using --sccm framing.
    #[arg(long)]
    after_greeting: bool,

    /// Idle timeout per read (ms) — controls when we declare "server is done sending".
    #[arg(long, default_value_t = 2000)]
    idle_ms: u64,
}

fn parse_hex_u8(s: &str) -> Result<u8, String> {
    let s = s.trim_start_matches("0x");
    u8::from_str_radix(s, 16).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_protocol=debug")))
        .init();
    let cli = Cli::parse();

    let mut conn = RawConnection::connect(&cli.target).await?;
    info!("TCP connected");

    let idle = Duration::from_millis(cli.idle_ms);

    if cli.after_greeting {
        info!("waiting for server greeting…");
        let greeting = conn.recv_raw_until_idle(65536, idle).await?;
        info!(received = greeting.len(), "got greeting");
        hexdump("← server greeting", &greeting);
    }

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
        } else if let Some(type_byte) = cli.sccm {
            let mut v = Vec::with_capacity(4 + step.output.len());
            // u32 LE: low 24 bits = body len, high byte = type
            let header = (step.output.len() as u32) | ((type_byte as u32) << 24);
            v.extend_from_slice(&header.to_le_bytes());
            v.extend_from_slice(&step.output);
            v
        } else if let Some(type_byte) = cli.sccm_innerlen {
            // body = [u16 LE token_len][token]; outer body_len = 2 + token_len
            let token_len = step.output.len();
            let body_len = 2 + token_len;
            let mut v = Vec::with_capacity(4 + body_len);
            let header = (body_len as u32) | ((type_byte as u32) << 24);
            v.extend_from_slice(&header.to_le_bytes());
            v.extend_from_slice(&(token_len as u16).to_le_bytes());
            v.extend_from_slice(&step.output);
            v
        } else {
            anyhow::bail!("pick one of --raw, --framed-be32, --framed-le32, --sccm <type>, --sccm-innerlen <type>, --connect-only");
        };

        info!(send_bytes = to_send.len(), "sending");
        hexdump("→ raw bytes on wire", &to_send[..to_send.len().min(64)]);
        conn.send_raw(&to_send).await?;
    }

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
