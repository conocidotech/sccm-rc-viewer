//! Headless benchmark / self-test for the SCCM RC pipeline. Runs a bounded
//! session, measures rendering timing/throughput, shuts down cleanly (so the
//! server releases its session), and reports stats + any error. Lets us test and
//! optimize without the GUI.
//!
//! Usage: rc-bench <target> [--seconds N] [--width W --height H] [--input]
//! Env: same SCCM_RC_* flags as the viewer.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use sccm_rc_core::rdp::{self, FrameView, SessionSink, UpdateRegion};
use sccm_rc_core::SccmSession;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rc-bench", about = "Headless SCCM RC benchmark/self-test")]
struct Cli {
    target: String,
    #[arg(long, default_value_t = 1920)]
    width: u16,
    #[arg(long, default_value_t = 1080)]
    height: u16,
    #[arg(long, default_value_t = 30)]
    seconds: u64,
    /// Send synthetic mouse-move input (to test the send path / input desync).
    #[arg(long, default_value_t = false)]
    input: bool,
}

#[derive(Default)]
struct Stats {
    updates: u64,
    first_paint_ms: Option<u128>,
    last_update_ms: u128,
    nonblack: u64,
    total_px: u64,
    png_path: String,
}

struct BenchSink {
    start: Instant,
    last_png: Instant,
    stats: Arc<Mutex<Stats>>,
}

impl SessionSink for BenchSink {
    fn on_graphics_update(&mut self, image: &dyn FrameView, _region: UpdateRegion) {
        let now_ms = self.start.elapsed().as_millis();
        let data = image.data();
        let mut nonblack = 0u64;
        for px in data.chunks_exact(4) {
            if px[0] as u32 + px[1] as u32 + px[2] as u32 > 12 {
                nonblack += 1;
            }
        }
        {
            let mut s = self.stats.lock().unwrap();
            s.updates += 1;
            s.first_paint_ms.get_or_insert(now_ms);
            s.last_update_ms = now_ms;
            s.nonblack = nonblack;
            s.total_px = (image.width() as u64) * (image.height() as u64);
        }
        // Atomic PNG dump at most ~1/sec.
        if self.last_png.elapsed() >= Duration::from_millis(1000) {
            self.last_png = Instant::now();
            let (w, h) = (image.width() as u32, image.height() as u32);
            if let Some(buf) = image::RgbaImage::from_raw(w, h, data.to_vec()) {
                let path = self.stats.lock().unwrap().png_path.clone();
                let tmp = format!("{path}.tmp");
                if buf.save_with_format(&tmp, image::ImageFormat::Png).is_ok() {
                    let _ = std::fs::rename(&tmp, &path);
                }
            }
        }
    }
    fn on_terminate(&mut self, reason: String) {
        info!(%reason, "session terminated by server");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,sccm_rc_core=info")),
        )
        .init();
    let cli = Cli::parse();
    let png_path = format!("{}\\rc-bench.png", std::env::temp_dir().display());

    let t0 = Instant::now();
    let mut session = SccmSession::connect(&cli.target).await?;
    let t_connect = t0.elapsed();
    let (result, initial_buf, share_id) =
        rdp::connect_rdp(&mut session, cli.width, cli.height, &[]).await?;
    let t_active = t0.elapsed();
    info!(grant = ?session.grant(), connect_ms = t_connect.as_millis(), active_ms = t_active.as_millis(), "connected + RDP active");

    let stats = Arc::new(Mutex::new(Stats {
        png_path: png_path.clone(),
        ..Default::default()
    }));
    let mut sink = BenchSink {
        start: t0,
        last_png: Instant::now(),
        stats: stats.clone(),
    };
    let (tx, mut input_rx) = tokio::sync::mpsc::channel(64);

    if cli.input {
        tokio::spawn(async move {
            use rdp::{FastPathInputEvent, MousePdu, PointerFlags};
            let mut t = tokio::time::interval(Duration::from_millis(200));
            let mut x = 100u16;
            loop {
                t.tick().await;
                x = if x > 1600 { 100 } else { x + 80 };
                let ev = FastPathInputEvent::MouseEvent(MousePdu {
                    flags: PointerFlags::MOVE,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: 500,
                });
                if tx.send(vec![ev]).await.is_err() {
                    break;
                }
            }
        });
    }

    let curtain = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Curtain self-test: toggle the privacy screen on at ~6s, off at ~11s, so we
    // can observe the server's reaction (response / reactivation / no disconnect).
    if std::env::var("SCCM_RC_CURTAIN_TEST").as_deref() == Ok("1") {
        let c = curtain.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(6)).await;
            tracing::warn!("CURTAIN TEST: enabling");
            c.store(true, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(5)).await;
            tracing::warn!("CURTAIN TEST: disabling");
            c.store(false, std::sync::atomic::Ordering::Relaxed);
        });
    }
    let file_offer = std::sync::Arc::new(std::sync::Mutex::new(None));
    let run = rdp::run_active_session(
        &mut session,
        result,
        initial_buf,
        share_id,
        &mut sink,
        &mut input_rx,
        curtain,
        file_offer,
    );
    let outcome = tokio::time::timeout(Duration::from_secs(cli.seconds), run).await;

    // Graceful teardown so the server releases the host (avoids lingering HostInUse).
    session.disconnect().await;

    let elapsed = t0.elapsed().as_secs_f64();
    let s = stats.lock().unwrap();
    let (sent, recvd) = session.seal_stats();
    let recvd_mb = session.recvd_bytes() as f64 / (1024.0 * 1024.0);
    let status = match &outcome {
        Ok(Ok(())) => "session ended cleanly".to_string(),
        Ok(Err(e)) => format!("CRASH/ERROR: {e}"),
        Err(_) => "ran full duration (timed out -> clean shutdown)".to_string(),
    };

    println!("\n===== rc-bench result =====");
    println!(
        "target            : {} ({}x{})",
        cli.target, cli.width, cli.height
    );
    println!("input enabled     : {}", cli.input);
    println!("time to RDP active: {} ms", t_active.as_millis());
    println!(
        "first paint       : {}",
        s.first_paint_ms
            .map(|m| format!("{m} ms"))
            .unwrap_or("NEVER".into())
    );
    println!("graphics updates  : {}", s.updates);
    println!(
        "update rate       : {:.1}/s",
        s.updates as f64 / elapsed.max(0.001)
    );
    println!("last update at    : {} ms", s.last_update_ms);
    println!(
        "non-black px       : {}/{} ({:.1}%)",
        s.nonblack,
        s.total_px,
        100.0 * s.nonblack as f64 / (s.total_px.max(1)) as f64
    );
    println!("sealed sent/recvd : {sent} / {recvd}");
    println!("total recvd       : {recvd_mb:.2} MB");
    println!("ran for           : {elapsed:.1} s");
    println!("status            : {status}");
    println!("png               : {png_path}");
    println!("===========================");
    Ok(())
}
