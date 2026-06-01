//! Primary drawing orders. Each order keeps persistent field state (the RDP
//! encoding omits unchanged fields), decodes only the present fields, then
//! renders into the canvas. Field order / bit assignment mirrors FreeRDP's
//! `update_read_*_order`.

use crate::canvas::{OrderCanvas, Rect};
use crate::cache::BitmapCache;
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

