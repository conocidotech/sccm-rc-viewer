//! End-to-end test: SCCM session + full RDP connection sequence via IronRDP.

use clap::Parser;
use sccm_rc_core::{rdp, SccmSession};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rdp-connect-test", about = "Connect + authenticate + drive the RDP connection sequence", version)]
struct Cli {
    target: String,
    #[arg(long, default_value_t = 1280)]
    width: u16,
    #[arg(long, default_value_t = 720)]
    height: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_core=debug")))
        .init();
    let cli = Cli::parse();

    info!(target = %cli.target, "connecting + authenticating");
    let mut session = SccmSession::connect(&cli.target).await?;
    info!(grant = ?session.grant(), "session established");

    match rdp::connect_rdp(&mut session, cli.width, cli.height).await {
        Ok(result) => {
            info!(
                desktop = format!("{}x{}", result.desktop_size.width, result.desktop_size.height),
                "✅✅ RDP ACTIVE SESSION — full connection sequence completed over SCCM transport"
            );
        }
        Err(e) => {
            error!(error = %e, "RDP connection sequence failed");
            return Err(e.into());
        }
    }
    Ok(())
}
