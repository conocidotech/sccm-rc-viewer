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

    let (result, initial_buf, share_id) = match rdp::connect_rdp(&mut session, cli.width, cli.height).await {
        Ok(r) => {
            info!(
                desktop = format!("{}x{}", r.0.desktop_size.width, r.0.desktop_size.height),
                "✅✅ RDP ACTIVE SESSION — full connection sequence completed over SCCM transport"
            );
            r
        }
        Err(e) => {
            error!(error = %e, "RDP connection sequence failed");
            return Err(e.into());
        }
    };

    // Process the live graphics stream headless to prove decoding works.
    info!("entering active session — processing graphics updates (Ctrl+C to stop)");
    let mut sink = rdp::PngDumpSink::new(format!("{}\\sccm-frame.png", std::env::temp_dir().display()));
    let (tx, mut input_rx) = tokio::sync::mpsc::channel(32);
    // Wiggle the mouse to wake a static/secure remote desktop.
    tokio::spawn(async move {
        use rdp::{FastPathInputEvent, MousePdu, PointerFlags};
        let mut t = tokio::time::interval(std::time::Duration::from_millis(800));
        let mut x = 100u16;
        loop {
            t.tick().await;
            x = if x > 800 { 100 } else { x + 60 };
            let ev = FastPathInputEvent::MouseEvent(MousePdu {
                flags: PointerFlags::MOVE,
                number_of_wheel_rotation_units: 0,
                x_position: x,
                y_position: 400,
            });
            if tx.send(vec![ev]).await.is_err() {
                break;
            }
        }
    });
    let curtain = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let file_offer = std::sync::Arc::new(std::sync::Mutex::new(None));
    if let Err(e) = rdp::run_active_session(&mut session, result, initial_buf, share_id, &mut sink, &mut input_rx, curtain, file_offer).await {
        error!(error = %e, updates = sink.updates, "active session ended with error");
    }
    info!(updates = sink.updates, nonblack = sink.nonblack_pixels, "active session ended");
    Ok(())
}
