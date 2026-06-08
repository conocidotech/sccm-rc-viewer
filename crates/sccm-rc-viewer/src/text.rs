//! Anti-aliased proportional text via `ab_glyph`, using a Windows system font
//! (Segoe UI) loaded at runtime. Falls back to the 8x8 bitmap font elsewhere if
//! no system TTF is available.

use ab_glyph::{point, Font, FontVec, Glyph, PxScale, ScaleFont};

pub struct TextRenderer {
    font: FontVec,
}

impl TextRenderer {
    /// Load a clean UI font from the Windows fonts directory.
    pub fn load() -> Option<Self> {
        let dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
        for name in ["segoeui.ttf", "tahoma.ttf", "arial.ttf", "verdana.ttf"] {
            if let Ok(bytes) = std::fs::read(format!("{dir}\\Fonts\\{name}")) {
                if let Ok(font) = FontVec::try_from_vec(bytes) {
                    return Some(Self { font });
                }
            }
        }
        None
    }

    /// Advance width (px) of `s` at pixel size `px`.
    pub fn width(&self, s: &str, px: f32) -> f32 {
        let sf = self.font.as_scaled(PxScale::from(px));
        let mut w = 0.0;
        let mut prev = None;
        for c in s.chars() {
            let g = sf.glyph_id(c);
            if let Some(p) = prev {
                w += sf.kern(p, g);
            }
            w += sf.h_advance(g);
            prev = Some(g);
        }
        w
    }

    /// Draw `s` left-aligned at `x`, vertically centered in the band
    /// `[band_top, band_top+band_h)`, alpha-blended over the existing pixels.
    pub fn draw_vcenter(
        &self,
        buf: &mut [u32],
        win_w: u32,
        win_h: u32,
        x: f32,
        band_top: f32,
        band_h: f32,
        s: &str,
        color: u32,
        px: f32,
    ) {
        let sf = self.font.as_scaled(PxScale::from(px));
        let baseline = band_top + (band_h - (sf.ascent() - sf.descent())) / 2.0 + sf.ascent();
        self.draw_baseline(buf, win_w, win_h, x, baseline, s, color, px);
    }

    /// Draw `s` horizontally centered in the window, baseline at `baseline_y`.
    pub fn draw_centered(
        &self,
        buf: &mut [u32],
        win_w: u32,
        win_h: u32,
        baseline_y: f32,
        s: &str,
        color: u32,
        px: f32,
    ) {
        let x = (win_w as f32 - self.width(s, px)).max(0.0) / 2.0;
        self.draw_baseline(buf, win_w, win_h, x, baseline_y, s, color, px);
    }

    fn draw_baseline(
        &self,
        buf: &mut [u32],
        win_w: u32,
        win_h: u32,
        x: f32,
        baseline_y: f32,
        s: &str,
        color: u32,
        px: f32,
    ) {
        let sf = self.font.as_scaled(PxScale::from(px));
        let (cr, cg, cb) = ((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff);
        let mut caret = x;
        let mut prev = None;
        for c in s.chars() {
            let gid = sf.glyph_id(c);
            if let Some(p) = prev {
                caret += sf.kern(p, gid);
            }
            let glyph: Glyph = gid.with_scale_and_position(px, point(caret, baseline_y));
            if let Some(outlined) = self.font.outline_glyph(glyph) {
                let bb = outlined.px_bounds();
                outlined.draw(|gx, gy, cov| {
                    let xx = bb.min.x as i32 + gx as i32;
                    let yy = bb.min.y as i32 + gy as i32;
                    if xx < 0 || yy < 0 || xx as u32 >= win_w || yy as u32 >= win_h {
                        return;
                    }
                    let idx = (yy as u32 * win_w + xx as u32) as usize;
                    let dst = buf[idx];
                    let (dr, dg, db) = ((dst >> 16) & 0xff, (dst >> 8) & 0xff, dst & 0xff);
                    let a = (cov * 255.0) as u32;
                    let r = (cr * a + dr * (255 - a)) / 255;
                    let g = (cg * a + dg * (255 - a)) / 255;
                    let b = (cb * a + db * (255 - a)) / 255;
                    buf[idx] = (r << 16) | (g << 8) | b;
                });
            }
            caret += sf.h_advance(gid);
            prev = Some(gid);
        }
    }
}
