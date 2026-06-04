//! Primary drawing orders. Each order keeps persistent field state (the RDP
//! encoding omits unchanged fields), decodes only the present fields, then
//! renders into the canvas. Field order / bit assignment mirrors FreeRDP's
//! `update_read_*_order`.

use crate::canvas::{OrderCanvas, Rect};
use crate::cache::{BitmapCache, Glyph, GlyphCache};
use crate::color::colorref;
use crate::cursor::Cursor;
use crate::header::{coord, field};
use crate::rop::Rop3;
use crate::OrderError;

/// Read a 3-byte color field (Red, Green, Blue byte order) -> RGBA.
fn read_color3(c: &mut Cursor) -> Result<[u8; 4], OrderError> {
    let r = c.u8()?;
    let g = c.u8()?;
    let b = c.u8()?;
    Ok(colorref(r, g, b))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DstBlt {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub rop: u8,
}

impl DstBlt {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        coord(ff, 0, c, delta, &mut self.x)?;
        coord(ff, 1, c, delta, &mut self.y)?;
        coord(ff, 2, c, delta, &mut self.w)?;
        coord(ff, 3, c, delta, &mut self.h)?;
        field(ff, 4, &mut self.rop, || c.u8())?;
        Ok(())
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>) -> Rect {
        canvas.dst_rop(Rect::from_ltwh(self.x, self.y, self.w, self.h), clip, Rop3(self.rop))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpaqueRect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub color: [u8; 4],
}

impl OpaqueRect {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        coord(ff, 0, c, delta, &mut self.x)?;
        coord(ff, 1, c, delta, &mut self.y)?;
        coord(ff, 2, c, delta, &mut self.w)?;
        coord(ff, 3, c, delta, &mut self.h)?;
        // Color is three independent 1-byte fields.
        field(ff, 4, &mut self.color[0], || c.u8())?; // RedOrPaletteIndex
        field(ff, 5, &mut self.color[1], || c.u8())?; // Green
        field(ff, 6, &mut self.color[2], || c.u8())?; // Blue
        self.color[3] = 0xff;
        Ok(())
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>) -> Rect {
        canvas.fill_rect(Rect::from_ltwh(self.x, self.y, self.w, self.h), clip, self.color)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScrBlt {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub rop: u8,
    pub x_src: i32,
    pub y_src: i32,
}

impl ScrBlt {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        coord(ff, 0, c, delta, &mut self.x)?;
        coord(ff, 1, c, delta, &mut self.y)?;
        coord(ff, 2, c, delta, &mut self.w)?;
        coord(ff, 3, c, delta, &mut self.h)?;
        field(ff, 4, &mut self.rop, || c.u8())?;
        coord(ff, 5, c, delta, &mut self.x_src)?;
        coord(ff, 6, c, delta, &mut self.y_src)?;
        Ok(())
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>) -> Rect {
        canvas.copy_rect(
            Rect::from_ltwh(self.x, self.y, self.w, self.h),
            clip,
            self.x_src,
            self.y_src,
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MemBlt {
    pub cache_id: u16,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub rop: u8,
    pub x_src: i32,
    pub y_src: i32,
    pub cache_index: u16,
}

impl MemBlt {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        field(ff, 0, &mut self.cache_id, || c.u16())?;
        coord(ff, 1, c, delta, &mut self.x)?;
        coord(ff, 2, c, delta, &mut self.y)?;
        coord(ff, 3, c, delta, &mut self.w)?;
        coord(ff, 4, c, delta, &mut self.h)?;
        field(ff, 5, &mut self.rop, || c.u8())?;
        coord(ff, 6, c, delta, &mut self.x_src)?;
        coord(ff, 7, c, delta, &mut self.y_src)?;
        field(ff, 8, &mut self.cache_index, || c.u16())?;
        Ok(())
    }

    /// The bitmap cache this MemBlt reads from (low byte of cacheId).
    pub fn cache(&self) -> usize {
        (self.cache_id & 0xff) as usize
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>, cache: &BitmapCache) -> Rect {
        let Some(bitmap) = cache.get(self.cache(), self.cache_index as usize) else {
            return Rect::new(0, 0, 0, 0);
        };
        canvas.blit_bitmap(
            Rect::from_ltwh(self.x, self.y, self.w, self.h),
            clip,
            bitmap,
            self.x_src,
            self.y_src,
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PatBlt {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub rop: u8,
    pub back_color: [u8; 4],
    pub fore_color: [u8; 4],
    pub brush_org_x: i32,
    pub brush_org_y: i32,
    pub brush_style: u8,
    pub brush_hatch: u8,
}

impl PatBlt {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        coord(ff, 0, c, delta, &mut self.x)?;
        coord(ff, 1, c, delta, &mut self.y)?;
        coord(ff, 2, c, delta, &mut self.w)?;
        coord(ff, 3, c, delta, &mut self.h)?;
        field(ff, 4, &mut self.rop, || c.u8())?;
        field(ff, 5, &mut self.back_color, || read_color3(c))?;
        field(ff, 6, &mut self.fore_color, || read_color3(c))?;
        field(ff, 7, &mut self.brush_org_x, || Ok(c.i8()? as i32))?;
        field(ff, 8, &mut self.brush_org_y, || Ok(c.i8()? as i32))?;
        field(ff, 9, &mut self.brush_style, || c.u8())?;
        field(ff, 10, &mut self.brush_hatch, || c.u8())?;
        // brushExtra (bit 11): 7 bytes, present for non-solid cached brushes.
        if ff & (1 << 11) != 0 {
            c.skip(7)?;
        }
        Ok(())
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>) -> Rect {
        // Solid brush (style 0) — the overwhelmingly common case for desktop
        // chrome. PATCOPY/PATPAINT fill with the foreground color; other ROPs
        // approximate with a fill so something is drawn.
        let rect = Rect::from_ltwh(self.x, self.y, self.w, self.h);
        match self.rop {
            0x00 => canvas.fill_rect(rect, clip, [0, 0, 0, 0xff]),       // BLACKNESS
            0xFF => canvas.fill_rect(rect, clip, [0xff, 0xff, 0xff, 0xff]), // WHITENESS
            _ => canvas.fill_rect(rect, clip, self.fore_color),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LineTo {
    pub back_mode: u16,
    pub x_start: i32,
    pub y_start: i32,
    pub x_end: i32,
    pub y_end: i32,
    pub back_color: [u8; 4],
    pub rop2: u8,
    pub pen_style: u8,
    pub pen_width: u8,
    pub pen_color: [u8; 4],
}

impl LineTo {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        field(ff, 0, &mut self.back_mode, || c.u16())?;
        coord(ff, 1, c, delta, &mut self.x_start)?;
        coord(ff, 2, c, delta, &mut self.y_start)?;
        coord(ff, 3, c, delta, &mut self.x_end)?;
        coord(ff, 4, c, delta, &mut self.y_end)?;
        field(ff, 5, &mut self.back_color, || read_color3(c))?;
        field(ff, 6, &mut self.rop2, || c.u8())?;
        field(ff, 7, &mut self.pen_style, || c.u8())?;
        field(ff, 8, &mut self.pen_width, || c.u8())?;
        field(ff, 9, &mut self.pen_color, || read_color3(c))?;
        Ok(())
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>) -> Rect {
        draw_line(
            canvas,
            clip,
            self.x_start,
            self.y_start,
            self.x_end,
            self.y_end,
            self.pen_color,
        )
    }
}

// ---------------------------------------------------------------------------
// Glyph / text orders (MS-RDPEGDI 2.2.2.2.1.1.2.13–15). Cached glyphs (1-bpp
// bitmaps from Cache Glyph secondary orders) are blitted in the foreground color
// along an advancing pen. Fragment-cache escapes (0xFE/0xFF) are consumed but not
// yet rendered. NOTE: implemented from the spec; not yet validated against a real
// glyph-emitting session (the SCCM login screen paints text via bitmap tiles).

/// Read a glyph-run advance/delta byte (0x80 escape → 2-byte LE value).
fn read_glyph_delta(data: &[u8], i: &mut usize) -> i32 {
    if *i >= data.len() {
        return 0;
    }
    let b = data[*i];
    *i += 1;
    if b == 0x80 {
        if *i + 1 < data.len() {
            let v = u16::from_le_bytes([data[*i], data[*i + 1]]) as i32;
            *i += 2;
            v
        } else {
            0
        }
    } else {
        b as i32
    }
}

/// Render a glyph-fragment byte stream: each index draws a cached glyph and
/// advances the pen (by `ul_char_inc`, or a trailing delta when it is 0). The
/// `0xFF` escape caches the preceding bytes as a fragment; `0xFE` replays a
/// cached fragment. Recursion is depth-limited as a safety guard.
#[allow(clippy::too_many_arguments)]
fn process_glyph_bytes(
    canvas: &mut OrderCanvas,
    clip: Option<Rect>,
    cache: &mut GlyphCache,
    cache_id: usize,
    ul_char_inc: u8,
    fore: [u8; 4],
    data: &[u8],
    gx: &mut i32,
    y: i32,
    dirty: &mut Rect,
    depth: u8,
) {
    if depth > 8 {
        return;
    }
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        i += 1;
        match b {
            0xFF => {
                // ADD: id(u8), size(u8) — cache the `size` bytes immediately
                // preceding this escape under fragment id.
                if i + 1 < data.len() {
                    let id = data[i] as usize;
                    let size = data[i + 1] as usize;
                    let frag_end = i - 1; // index of the 0xFF byte
                    let frag_start = frag_end.saturating_sub(size);
                    let frag = data[frag_start..frag_end].to_vec();
                    cache.put_fragment(id, &frag);
                    i += 2;
                } else {
                    break;
                }
            }
            0xFE => {
                // USE: id(u8) [+ delta]; replay the cached fragment's glyphs.
                if i >= data.len() {
                    break;
                }
                let id = data[i] as usize;
                i += 1;
                let delta = if ul_char_inc == 0 {
                    read_glyph_delta(data, &mut i)
                } else {
                    0
                };
                if let Some(frag) = cache.fragment(id).map(|f| f.to_vec()) {
                    process_glyph_bytes(canvas, clip, cache, cache_id, ul_char_inc, fore, &frag, gx, y, dirty, depth + 1);
                }
                *gx += delta;
            }
            idx => {
                let mut adv = 0;
                if let Some(g) = cache.get(cache_id, idx as usize) {
                    let r = canvas.blit_glyph(*gx + g.x as i32, y + g.y as i32, g.cx, g.cy, &g.aj, clip, fore);
                    if !r.is_empty() {
                        *dirty = if dirty.is_empty() { r } else { dirty.union(&r) };
                    }
                    adv = if ul_char_inc != 0 { ul_char_inc as i32 } else { read_glyph_delta(data, &mut i) };
                } else if ul_char_inc == 0 {
                    let _ = read_glyph_delta(data, &mut i);
                }
                *gx += adv;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_glyph_run(
    canvas: &mut OrderCanvas,
    clip: Option<Rect>,
    cache: &mut GlyphCache,
    cache_id: usize,
    ul_char_inc: u8,
    data: &[u8],
    x: i32,
    y: i32,
    fore: [u8; 4],
) -> Rect {
    let mut gx = x;
    let mut dirty = Rect::new(0, 0, 0, 0);
    process_glyph_bytes(canvas, clip, cache, cache_id, ul_char_inc, fore, data, &mut gx, y, &mut dirty, 0);
    dirty
}

/// Fill the text background box with `back_color` (inclusive coords), then return
/// it as a dirty seed. A zero/empty box is ignored.
fn fill_text_bg(canvas: &mut OrderCanvas, clip: Option<Rect>, l: i32, t: i32, r: i32, b: i32, color: [u8; 4]) -> Rect {
    if r > l && b > t {
        canvas.fill_rect(Rect::from_inclusive(l, t, r, b), clip, color)
    } else {
        Rect::new(0, 0, 0, 0)
    }
}

/// GlyphIndex order (0x1B) — the full text order.
#[derive(Debug, Clone, Default)]
pub struct GlyphIndex {
    pub cache_id: u8,
    pub fl_accel: u8,
    pub ul_char_inc: u8,
    pub fop_redundant: u8,
    pub back_color: [u8; 4],
    pub fore_color: [u8; 4],
    pub bk: [i32; 4], // left, top, right, bottom (inclusive)
    pub op: [i32; 4],
    pub brush_org_x: u8,
    pub brush_org_y: u8,
    pub brush_style: u8,
    pub brush_hatch: u8,
    pub x: i32,
    pub y: i32,
    pub data: Vec<u8>,
}

impl GlyphIndex {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        field(ff, 0, &mut self.cache_id, || c.u8())?;
        field(ff, 1, &mut self.fl_accel, || c.u8())?;
        field(ff, 2, &mut self.ul_char_inc, || c.u8())?;
        field(ff, 3, &mut self.fop_redundant, || c.u8())?;
        field(ff, 4, &mut self.back_color, || read_color3(c))?;
        field(ff, 5, &mut self.fore_color, || read_color3(c))?;
        for (bit, slot) in self.bk.iter_mut().enumerate() {
            coord(ff, 6 + bit as u32, c, delta, slot)?;
        }
        for (bit, slot) in self.op.iter_mut().enumerate() {
            coord(ff, 10 + bit as u32, c, delta, slot)?;
        }
        field(ff, 14, &mut self.brush_org_x, || c.u8())?;
        field(ff, 15, &mut self.brush_org_y, || c.u8())?;
        field(ff, 16, &mut self.brush_style, || c.u8())?;
        field(ff, 17, &mut self.brush_hatch, || c.u8())?;
        if ff & (1 << 18) != 0 {
            c.skip(7)?; // brushExtra
        }
        coord(ff, 19, c, delta, &mut self.x)?;
        coord(ff, 20, c, delta, &mut self.y)?;
        if ff & (1 << 21) != 0 {
            let n = c.u8()? as usize;
            self.data = c.bytes(n.min(c.remaining()))?.to_vec();
        }
        Ok(())
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>, glyphs: &mut GlyphCache) -> Rect {
        let bg = fill_text_bg(canvas, clip, self.bk[0], self.bk[1], self.bk[2], self.bk[3], self.back_color);
        let fg = draw_glyph_run(canvas, clip, glyphs, self.cache_id as usize, self.ul_char_inc, &self.data, self.x, self.y, self.fore_color);
        if bg.is_empty() { fg } else if fg.is_empty() { bg } else { bg.union(&fg) }
    }
}

/// FastIndex order (0x13) — compact text order (no brush / fOpRedundant).
#[derive(Debug, Clone, Default)]
pub struct FastIndex {
    pub cache_id: u8,
    pub ul_char_inc: u8,
    pub fl_accel: u8,
    pub back_color: [u8; 4],
    pub fore_color: [u8; 4],
    pub bk: [i32; 4],
    pub op: [i32; 4],
    pub x: i32,
    pub y: i32,
    pub data: Vec<u8>,
}

impl FastIndex {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        field(ff, 0, &mut self.cache_id, || c.u8())?;
        // bit 1: two bytes — ulCharInc then flAccel.
        if ff & (1 << 1) != 0 {
            self.ul_char_inc = c.u8()?;
            self.fl_accel = c.u8()?;
        }
        field(ff, 2, &mut self.back_color, || read_color3(c))?;
        field(ff, 3, &mut self.fore_color, || read_color3(c))?;
        for (bit, slot) in self.bk.iter_mut().enumerate() {
            coord(ff, 4 + bit as u32, c, delta, slot)?;
        }
        for (bit, slot) in self.op.iter_mut().enumerate() {
            coord(ff, 8 + bit as u32, c, delta, slot)?;
        }
        coord(ff, 12, c, delta, &mut self.x)?;
        coord(ff, 13, c, delta, &mut self.y)?;
        if ff & (1 << 14) != 0 {
            let n = c.u8()? as usize;
            self.data = c.bytes(n.min(c.remaining()))?.to_vec();
        }
        Ok(())
    }

    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>, glyphs: &mut GlyphCache) -> Rect {
        let bg = fill_text_bg(canvas, clip, self.bk[0], self.bk[1], self.bk[2], self.bk[3], self.back_color);
        let fg = draw_glyph_run(canvas, clip, glyphs, self.cache_id as usize, self.ul_char_inc, &self.data, self.x, self.y, self.fore_color);
        if bg.is_empty() { fg } else if fg.is_empty() { bg } else { bg.union(&fg) }
    }
}

/// FastGlyph order (0x18) — like FastIndex but the data carries one inline glyph
/// (cached under `cacheId`/index and drawn once).
#[derive(Debug, Clone, Default)]
pub struct FastGlyph {
    pub cache_id: u8,
    pub ul_char_inc: u8,
    pub fl_accel: u8,
    pub back_color: [u8; 4],
    pub fore_color: [u8; 4],
    pub bk: [i32; 4],
    pub op: [i32; 4],
    pub x: i32,
    pub y: i32,
    pub data: Vec<u8>,
}

impl FastGlyph {
    pub fn decode(&mut self, c: &mut Cursor, ff: u32, delta: bool) -> Result<(), OrderError> {
        field(ff, 0, &mut self.cache_id, || c.u8())?;
        if ff & (1 << 1) != 0 {
            self.ul_char_inc = c.u8()?;
            self.fl_accel = c.u8()?;
        }
        field(ff, 2, &mut self.back_color, || read_color3(c))?;
        field(ff, 3, &mut self.fore_color, || read_color3(c))?;
        for (bit, slot) in self.bk.iter_mut().enumerate() {
            coord(ff, 4 + bit as u32, c, delta, slot)?;
        }
        for (bit, slot) in self.op.iter_mut().enumerate() {
            coord(ff, 8 + bit as u32, c, delta, slot)?;
        }
        coord(ff, 12, c, delta, &mut self.x)?;
        coord(ff, 13, c, delta, &mut self.y)?;
        if ff & (1 << 14) != 0 {
            let n = c.u8()? as usize;
            self.data = c.bytes(n.min(c.remaining()))?.to_vec();
        }
        Ok(())
    }

    /// Draws (and caches) the inline glyph. `data` = cacheIndex(u8) then, if more
    /// bytes follow, a TS_CACHE_GLYPH_DATA (x,y,cx,cy,aj) to cache + draw.
    pub fn draw(&self, canvas: &mut OrderCanvas, clip: Option<Rect>, glyphs: &mut GlyphCache) -> Rect {
        let bg = fill_text_bg(canvas, clip, self.bk[0], self.bk[1], self.bk[2], self.bk[3], self.back_color);
        let mut dirty = bg;
        if self.data.len() >= 1 {
            let cache_index = self.data[0] as usize;
            if self.data.len() >= 9 {
                // inline TS_CACHE_GLYPH_DATA
                let gx = i16::from_le_bytes([self.data[1], self.data[2]]);
                let gy = i16::from_le_bytes([self.data[3], self.data[4]]);
                let cx = u16::from_le_bytes([self.data[5], self.data[6]]);
                let cy = u16::from_le_bytes([self.data[7], self.data[8]]);
                let aj = self.data.get(9..).unwrap_or(&[]).to_vec();
                let glyph = Glyph { x: gx, y: gy, cx, cy, aj };
                let r = canvas.blit_glyph(self.x + gx as i32, self.y + gy as i32, cx, cy, &glyph.aj, clip, self.fore_color);
                glyphs.insert(self.cache_id as usize, cache_index, glyph);
                if !r.is_empty() {
                    dirty = if dirty.is_empty() { r } else { dirty.union(&r) };
                }
            } else if let Some(g) = glyphs.get(self.cache_id as usize, cache_index) {
                let r = canvas.blit_glyph(self.x + g.x as i32, self.y + g.y as i32, g.cx, g.cy, &g.aj, clip, self.fore_color);
                if !r.is_empty() {
                    dirty = if dirty.is_empty() { r } else { dirty.union(&r) };
                }
            }
        }
        dirty
    }
}

/// Bresenham line, clipped per-pixel to the canvas and bounds.
fn draw_line(
    canvas: &mut OrderCanvas,
    clip: Option<Rect>,
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    color: [u8; 4],
) -> Rect {
    let dirty = Rect::from_inclusive(x0.min(x1), y0.min(y1), x0.max(x1), y0.max(y1));
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    let (mut x, mut y) = (x0, y0);
    loop {
        canvas.fill_rect(Rect::new(x, y, 1, 1), clip, color);
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            err += dx;
            y += sy;
        }
    }
    dirty
}

