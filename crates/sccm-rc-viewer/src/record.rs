//! Session recording: dump the live desktop to a PNG frame series (throttled,
//! ~3 fps) on a background thread so encoding never stalls the UI. Frames land in
//! `%USERPROFILE%\Videos\sccm-rc-rec\session-<epoch>\frame-NNNNNN.png`.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Frame {
    idx: u64,
    w: u32,
    h: u32,
    rgba: Vec<u8>,
}

pub struct Recorder {
    tx: Option<mpsc::Sender<Frame>>,
    join: Option<std::thread::JoinHandle<()>>,
    dir: PathBuf,
    idx: u64,
    last: Instant,
}

impl Recorder {
    /// Begin a recording session. Returns None if the output dir can't be made.
    pub fn start() -> Option<Self> {
        let base = std::env::var("USERPROFILE")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir = base
            .join("Videos")
            .join("sccm-rc-rec")
            .join(format!("session-{secs}"));
        std::fs::create_dir_all(&dir).ok()?;

        let (tx, rx) = mpsc::channel::<Frame>();
        let writer_dir = dir.clone();
        let join = std::thread::spawn(move || {
            for f in rx {
                // Drop alpha → RGB PNG (composite alpha is unreliable).
                let mut rgb = Vec::with_capacity((f.w as usize) * (f.h as usize) * 3);
                for px in f.rgba.chunks_exact(4) {
                    rgb.push(px[0]);
                    rgb.push(px[1]);
                    rgb.push(px[2]);
                }
                if let Some(img) = image::RgbImage::from_raw(f.w, f.h, rgb) {
                    let path = writer_dir.join(format!("frame-{:06}.png", f.idx));
                    let _ = img.save(&path);
                }
            }
        });
        Some(Self {
            tx: Some(tx),
            join: Some(join),
            dir,
            idx: 0,
            last: Instant::now(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn frame_count(&self) -> u64 {
        self.idx
    }

    /// Queue the current desktop for recording if the throttle interval elapsed.
    pub fn maybe_capture(&mut self, w: u32, h: u32, rgba: &[u8]) {
        if w == 0 || h == 0 || rgba.len() < (w as usize) * (h as usize) * 4 {
            return;
        }
        if self.last.elapsed() < Duration::from_millis(333) {
            return;
        }
        self.last = Instant::now();
        if let Some(tx) = &self.tx {
            let _ = tx.send(Frame {
                idx: self.idx,
                w,
                h,
                rgba: rgba.to_vec(),
            });
            self.idx += 1;
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.tx.take(); // close the channel so the writer thread drains + exits
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}
