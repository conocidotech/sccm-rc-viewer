//! `OrderCanvas` — a plain RGBA32 framebuffer with the blit primitives the
//! RDP primary drawing orders need. Byte order is `[R, G, B, A]` to match
//! IronRDP's `DecodedImage` (`PixelFormat::RgbA32`), so the existing viewer
//! can render our buffer unchanged.

use crate::rop::Rop3;

/// An inclusive-exclusive rectangle in pixel space (x..x+w, y..y+h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    /// Build from RDP left/top + width/height.
    pub fn from_ltwh(left: i32, top: i32, width: i32, height: i32) -> Self {
        Self {
            x: left,
            y: top,
            w: width,
            h: height,
        }
    }

    /// Build from inclusive left/top/right/bottom (RDP bounds use inclusive
    /// right/bottom).
    pub fn from_inclusive(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        // Saturating: bounds edges are independent wire deltas with no ordering
        // guarantee; a `right < left` or extreme value must not overflow-panic.
        Self {
            x: left,
            y: top,
            w: right.saturating_sub(left).saturating_add(1),
            h: bottom.saturating_sub(top).saturating_add(1),
        }
    }

    pub fn right(&self) -> i32 {
        self.x.saturating_add(self.w)
    }

    pub fn bottom(&self) -> i32 {
        self.y.saturating_add(self.h)
    }

    pub fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }

    /// Intersection of two rects (empty if disjoint).
    pub fn intersect(&self, other: &Rect) -> Rect {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());
        Rect {
            x,
            y,
            w: right.saturating_sub(x),
            h: bottom.saturating_sub(y),
        }
    }

    /// Union (bounding box) of two non-empty rects.
    pub fn union(&self, other: &Rect) -> Rect {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = self.right().max(other.right());
        let bottom = self.bottom().max(other.bottom());
        Rect {
            x,
            y,
            w: right.saturating_sub(x),
            h: bottom.saturating_sub(y),
        }
    }
}

/// A decoded bitmap (RGBA32, top-down) — e.g. an entry in the bitmap cache,
/// used as the source for MemBlt.
#[derive(Debug, Clone)]
pub struct Bitmap {
    pub width: u16,
    pub height: u16,
    /// RGBA32, top-down, `width * height * 4` bytes.
    pub data: Vec<u8>,
}

impl Bitmap {
    pub fn new(width: u16, height: u16, data: Vec<u8>) -> Self {
        debug_assert_eq!(data.len(), width as usize * height as usize * 4);
        Self {
            width,
            height,
            data,
        }
    }

    #[inline]
    pub fn pixel(&self, x: i32, y: i32) -> Option<[u8; 4]> {
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return None;
        }
        let idx = (y as usize * self.width as usize + x as usize) * 4;
        Some([
            self.data[idx],
            self.data[idx + 1],
            self.data[idx + 2],
            self.data[idx + 3],
        ])
    }
}

pub struct OrderCanvas {
    width: u16,
    height: u16,
    data: Vec<u8>,
}

impl OrderCanvas {
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            data: vec![0u8; width as usize * height as usize * 4],
        }
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Resize (used on reactivation with a new desktop size). Contents are
    /// cleared to black.
    pub fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.data = vec![0u8; width as usize * height as usize * 4];
    }

    #[inline]
    fn idx(&self, x: i32, y: i32) -> usize {
        (y as usize * self.width as usize + x as usize) * 4
    }

    /// In-bounds guard for `get`/`put`. Defense-in-depth: callers go through
    /// `clip()`, but if a rect-arithmetic overflow ever broke that invariant,
    /// `idx()`'s `as usize` cast on a negative/oversized coord would wrap to a
    /// huge index and write out of bounds. This keeps such a bug a no-op.
    #[inline]
    fn in_bounds(&self, x: i32, y: i32) -> bool {
        x >= 0
            && y >= 0
            && (x as usize) < self.width as usize
            && (y as usize) < self.height as usize
    }

    #[inline]
    fn get(&self, x: i32, y: i32) -> [u8; 4] {
        if !self.in_bounds(x, y) {
            return [0, 0, 0, 0xff];
        }
        let i = self.idx(x, y);
        [
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
        ]
    }

    #[inline]
    fn put(&mut self, x: i32, y: i32, c: [u8; 4]) {
        if !self.in_bounds(x, y) {
            return;
        }
        let i = self.idx(x, y);
        self.data[i] = c[0];
        self.data[i + 1] = c[1];
        self.data[i + 2] = c[2];
        self.data[i + 3] = 0xff;
    }

    /// Clip a destination rect to the canvas and (optionally) a bounds rect.
    fn clip(&self, dst: Rect, bounds: Option<Rect>) -> Rect {
        let canvas = Rect::new(0, 0, self.width as i32, self.height as i32);
        let mut r = dst.intersect(&canvas);
        if let Some(b) = bounds {
            r = r.intersect(&b);
        }
        r
    }

    /// Solid fill (OpaqueRect, PatBlt with solid brush, DstBlt BLACKNESS/WHITENESS).
    pub fn fill_rect(&mut self, dst: Rect, bounds: Option<Rect>, color: [u8; 4]) -> Rect {
        let r = self.clip(dst, bounds);
        if r.is_empty() {
            return r;
        }
        for y in r.y..r.bottom() {
            for x in r.x..r.right() {
                self.put(x, y, color);
            }
        }
        r
    }

    /// Blit a 1-bit-per-pixel glyph at `(x, y)`. `aj` is the glyph bitmap,
    /// `ceil(cx/8)` bytes per row, MSB-first (bit 7 = leftmost pixel); set bits
    /// are painted `color`, clear bits are left unchanged. Clipped to the canvas
    /// and the optional bounds rect. Returns the touched (clipped) rect.
    #[allow(clippy::too_many_arguments)]
    pub fn blit_glyph(
        &mut self,
        x: i32,
        y: i32,
        cx: u16,
        cy: u16,
        aj: &[u8],
        bounds: Option<Rect>,
        color: [u8; 4],
    ) -> Rect {
        let dst = Rect::from_ltwh(x, y, cx as i32, cy as i32);
        let r = self.clip(dst, bounds);
        if r.is_empty() {
            return r;
        }
        let row_bytes = (cx as usize).div_ceil(8);
        for py in r.y..r.bottom() {
            let gy = (py - y) as usize;
            let row = gy * row_bytes;
            for px in r.x..r.right() {
                let gx = (px - x) as usize;
                let byte = aj.get(row + gx / 8).copied().unwrap_or(0);
                if (byte >> (7 - (gx % 8))) & 1 != 0 {
                    self.put(px, py, color);
                }
            }
        }
        r
    }

    /// Apply a destination-only ROP3 (no source/pattern): BLACKNESS (0x00),
    /// WHITENESS (0xFF), DSTINVERT (0x55). Other dest-only codes fall back to
    /// a no-op.
    pub fn dst_rop(&mut self, dst: Rect, bounds: Option<Rect>, rop: Rop3) -> Rect {
        let r = self.clip(dst, bounds);
        if r.is_empty() {
            return r;
        }
        match rop.0 {
            0x00 => {
                self.fill_rect(dst, bounds, [0, 0, 0, 0xff]);
            }
            0xFF => {
                self.fill_rect(dst, bounds, [0xff, 0xff, 0xff, 0xff]);
            }
            0x55 => {
                for y in r.y..r.bottom() {
                    for x in r.x..r.right() {
                        let c = self.get(x, y);
                        self.put(x, y, [!c[0], !c[1], !c[2], 0xff]);
                    }
                }
            }
            _ => {}
        }
        r
    }

    /// Screen-to-screen copy (ScrBlt). Handles overlapping source/destination
    /// by choosing scan order. Only SRCCOPY semantics are implemented; other
    /// ROPs are treated as SRCCOPY.
    pub fn copy_rect(&mut self, dst: Rect, bounds: Option<Rect>, src_x: i32, src_y: i32) -> Rect {
        let clipped = self.clip(dst, bounds);
        if clipped.is_empty() {
            return clipped;
        }
        // Offset between dst and src so we can map clipped dst pixels back to src.
        let dx = src_x - dst.x;
        let dy = src_y - dst.y;

        // Choose iteration order to be safe under overlap.
        let reverse_x = dx > 0;
        let reverse_y = dy > 0;

        let xs: Vec<i32> = if reverse_x {
            (clipped.x..clipped.right()).rev().collect()
        } else {
            (clipped.x..clipped.right()).collect()
        };
        let ys: Vec<i32> = if reverse_y {
            (clipped.y..clipped.bottom()).rev().collect()
        } else {
            (clipped.y..clipped.bottom()).collect()
        };

        for &y in &ys {
            for &x in &xs {
                let sx = x + dx;
                let sy = y + dy;
                if sx < 0 || sy < 0 || sx >= self.width as i32 || sy >= self.height as i32 {
                    continue;
                }
                let c = self.get(sx, sy);
                self.put(x, y, c);
            }
        }
        clipped
    }

    /// Blit a source bitmap (MemBlt). `src_x`/`src_y` is the top-left within
    /// the source bitmap. Only SRCCOPY is implemented; other ROPs SRCCOPY.
    pub fn blit_bitmap(
        &mut self,
        dst: Rect,
        bounds: Option<Rect>,
        src: &Bitmap,
        src_x: i32,
        src_y: i32,
    ) -> Rect {
        let clipped = self.clip(dst, bounds);
        if clipped.is_empty() {
            return clipped;
        }
        for y in clipped.y..clipped.bottom() {
            for x in clipped.x..clipped.right() {
                let sx = src_x + (x - dst.x);
                let sy = src_y + (y - dst.y);
                if let Some(c) = src.pixel(sx, sy) {
                    self.put(x, y, c);
                }
            }
        }
        clipped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_arithmetic_is_overflow_safe() {
        // Extreme / inverted edges must saturate, not panic (RRCV-9).
        let r = Rect::from_inclusive(i32::MIN, i32::MIN, i32::MAX, i32::MAX);
        let _ = (r.right(), r.bottom());
        let a = Rect::from_ltwh(0, 0, i32::MAX, i32::MAX);
        let b = Rect::from_ltwh(i32::MIN, i32::MIN, i32::MAX, i32::MAX);
        let _ = a.intersect(&b); // must not panic
        let _ = a.union(&b); // must not panic
                             // A normal intersection is still computed correctly.
        let i = Rect::from_ltwh(0, 0, 100, 100).intersect(&Rect::from_ltwh(50, 50, 100, 100));
        assert_eq!((i.x, i.y, i.w, i.h), (50, 50, 50, 50));
    }

    #[test]
    fn canvas_put_get_out_of_bounds_is_noop() {
        // The in_bounds guard must turn an out-of-range write into a no-op rather
        // than an out-of-bounds index (RRCV-9 defense-in-depth).
        let mut c = OrderCanvas::new(4, 4);
        c.put(1_000_000, 1_000_000, [1, 2, 3, 4]);
        c.put(-5, -5, [1, 2, 3, 4]);
        assert!(
            c.data().iter().all(|&b| b == 0),
            "OOB put must not modify the buffer"
        );
        assert_eq!(
            c.get(-1, -1),
            [0, 0, 0, 0xff],
            "OOB get returns the opaque fallback"
        );
        assert_eq!(c.get(4, 4), [0, 0, 0, 0xff]);
        // In-bounds round-trip still works (alpha forced opaque).
        c.put(2, 2, [10, 20, 30, 0]);
        assert_eq!(c.get(2, 2), [10, 20, 30, 0xff]);
    }
}
