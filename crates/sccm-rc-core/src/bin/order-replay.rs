//! Offline renderer debug: feed captured Fast-Path Orders streams
//! (sccm-orders-NNN.bin) through the OrderProcessor and dump the canvas to PNG.
//! Decouples renderer debugging from the (flaky) live SCCM server.
//!
//! Usage: order-replay [width height] [file1.bin file2.bin ...]
//! Default: 1920x1080, %TEMP%\sccm-orders-001..005.bin
//! Tracing: set SCCM_RC_ORDER_TRACE=1 and RUST_LOG=info,sccm_rc_orders=info.

use sccm_rc_orders::{ColorDepth, OrderProcessor};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut idx = 0;
    let (mut width, mut height) = (1920u16, 1080u16);
    if args.len() >= 2 {
        if let (Ok(w), Ok(h)) = (args[0].parse(), args[1].parse()) {
            width = w;
            height = h;
            idx = 2;
        }
    }
    let files: Vec<String> = if args.len() > idx {
        args[idx..].to_vec()
    } else {
        // All sccm-orders-*.bin in TEMP, sorted by name (capture order).
        let tmp = std::env::temp_dir();
        let mut v: Vec<String> = std::fs::read_dir(&tmp)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("sccm-orders-") && n.ends_with(".bin"))
                    .unwrap_or(false)
            })
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };

    let mut proc = OrderProcessor::new(width, height, ColorDepth::Bpp16);
    let mut total_orders = 0usize;
    let mut total_dirty = 0usize;
    for f in &files {
        let data = match std::fs::read(f) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("skip {f}: {e}");
                continue;
            }
        };
        match proc.process_orders(&data) {
            Ok(o) => {
                if o.dirty.is_some() {
                    total_dirty += 1;
                }
                total_orders += o.orders;
                println!(
                    "{}: orders={} skipped={} dirty={:?}",
                    std::path::Path::new(f)
                        .file_name()
                        .unwrap()
                        .to_string_lossy(),
                    o.orders,
                    o.skipped,
                    o.dirty
                );
            }
            Err(e) => eprintln!("{f}: process error: {e}"),
        }
    }

    // Analyze the canvas (RgbA32: 4 bytes/pixel).
    let canvas = proc.canvas();
    let buf = canvas.data();
    let (w, h) = (canvas.width() as u32, canvas.height() as u32);
    let mut nonblack = 0usize;
    for px in buf.chunks_exact(4) {
        if px[0] as u32 + px[1] as u32 + px[2] as u32 > 12 {
            nonblack += 1;
        }
    }
    let total_px = (w * h) as usize;
    println!(
        "\nTOTAL orders={total_orders}, streams-with-dirty={total_dirty}, canvas={w}x{h}, \
         non-black pixels={nonblack}/{total_px} ({:.2}%)",
        100.0 * nonblack as f64 / total_px as f64
    );

    // Write PNG (canvas is RGBA already).
    let out = std::env::temp_dir().join("order-replay.png");
    let img = image::RgbaImage::from_raw(w, h, buf.to_vec())
        .ok_or_else(|| anyhow::anyhow!("buffer size mismatch"))?;
    img.save(&out)?;
    println!("wrote {}", out.display());
    Ok(())
}
