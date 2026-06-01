//! Primary drawing-order header machinery (MS-RDPEGDI 2.2.2.2.1.1.2):
//! control flags, the variable-length field-flags bitmask, the persistent
//! bounds (clip) rectangle, and coordinate (delta/absolute) decoding.
//!
//! The field-flags and bounds decoding deliberately mirror FreeRDP's
//! `update_read_field_flags` / `update_read_bounds` byte-for-byte.

use crate::canvas::Rect;
use crate::cursor::Cursor;
use crate::OrderError;

// Primary order control flags.
pub const TS_STANDARD: u8 = 0x01;
pub const TS_SECONDARY: u8 = 0x02;
pub const TS_BOUNDS: u8 = 0x04;
pub const TS_TYPE_CHANGE: u8 = 0x08;
pub const TS_DELTA_COORDINATES: u8 = 0x10;
pub const TS_ZERO_BOUNDS_DELTAS: u8 = 0x20;
pub const TS_ZERO_FIELD_BYTE_BIT0: u8 = 0x40;
pub const TS_ZERO_FIELD_BYTE_BIT1: u8 = 0x80;

// Order type encodings (the `orderType` byte, present only on TS_TYPE_CHANGE).
pub const ORD_DSTBLT: u8 = 0x00;
pub const ORD_PATBLT: u8 = 0x01;
pub const ORD_SCRBLT: u8 = 0x02;
pub const ORD_DRAW_NINE_GRID: u8 = 0x07;
pub const ORD_MULTI_DRAW_NINE_GRID: u8 = 0x08;
pub const ORD_LINE_TO: u8 = 0x09;
pub const ORD_OPAQUE_RECT: u8 = 0x0A;
pub const ORD_SAVE_BITMAP: u8 = 0x0B;
pub const ORD_MEMBLT: u8 = 0x0D;
pub const ORD_MEM3BLT: u8 = 0x0E;
pub const ORD_MULTI_DSTBLT: u8 = 0x0F;
pub const ORD_MULTI_PATBLT: u8 = 0x10;
pub const ORD_MULTI_SCRBLT: u8 = 0x11;
pub const ORD_MULTI_OPAQUE_RECT: u8 = 0x12;
pub const ORD_FAST_INDEX: u8 = 0x13;
pub const ORD_POLYGON_SC: u8 = 0x14;
pub const ORD_POLYGON_CB: u8 = 0x15;
pub const ORD_POLYLINE: u8 = 0x16;
pub const ORD_FAST_GLYPH: u8 = 0x18;
pub const ORD_ELLIPSE_SC: u8 = 0x19;
pub const ORD_ELLIPSE_CB: u8 = 0x1A;
pub const ORD_GLYPH_INDEX: u8 = 0x1B;

/// Number of field-flag bytes for each order type (indexed by order type byte).
/// Mirrors FreeRDP's `PRIMARY_DRAWING_ORDER_FIELD_BYTES`.
pub fn field_bytes(order_type: u8) -> Option<u8> {
    Some(match order_type {
        ORD_DSTBLT => 1,
        ORD_PATBLT => 2,
        ORD_SCRBLT => 1,
        ORD_DRAW_NINE_GRID => 1,
        ORD_MULTI_DRAW_NINE_GRID => 2,
        ORD_LINE_TO => 2,
        ORD_OPAQUE_RECT => 1,
        ORD_SAVE_BITMAP => 1,
        ORD_MEMBLT => 2,
        ORD_MEM3BLT => 3,
        ORD_MULTI_DSTBLT => 2,
        ORD_MULTI_PATBLT => 2,
        ORD_MULTI_SCRBLT => 2,
        ORD_MULTI_OPAQUE_RECT => 1,
        ORD_FAST_INDEX => 3,
        ORD_POLYGON_SC => 2,
        ORD_POLYGON_CB => 3,
        ORD_POLYLINE => 2,
        ORD_FAST_GLYPH => 2,
        ORD_ELLIPSE_SC => 2,
        ORD_ELLIPSE_CB => 3,
        ORD_GLYPH_INDEX => 3,
        _ => return None,
    })
}

/// Decode the variable-length field-flags bitmask. `field_bytes` is the order
/// type's constant; the two TS_ZERO_FIELD_BYTE control bits drop trailing
/// (zero) bytes. Mirrors FreeRDP `update_read_field_flags`.
pub fn read_field_flags(c: &mut Cursor, control: u8, field_bytes: u8) -> Result<u32, OrderError> {
    let mut fb = field_bytes;
    if control & TS_ZERO_FIELD_BYTE_BIT0 != 0 {
        fb = fb.saturating_sub(1);
    }
    if control & TS_ZERO_FIELD_BYTE_BIT1 != 0 {
        if fb > 1 {
            fb -= 2;
        } else {
            fb = 0;
        }
    }
    let mut flags: u32 = 0;
    for i in 0..fb {
        let b = c.u8()?;
        flags |= (b as u32) << (i * 8);
    }
    Ok(flags)
}

/// Read a non-coordinate field only when its `flag` bit is present (byte, u16,
/// color); otherwise keep `*slot` unchanged.
#[inline]
pub fn field<T>(
    field_flags: u32,
    bit: u32,
    slot: &mut T,
    f: impl FnOnce() -> Result<T, OrderError>,
) -> Result<(), OrderError> {
    if field_flags & (1 << bit) != 0 {
        *slot = f()?;
    }
    Ok(())
}

/// Read a coordinate field (delta or absolute) in place when present.
#[inline]
pub fn coord(
    field_flags: u32,
    bit: u32,
    c: &mut Cursor,
    delta: bool,
    slot: &mut i32,
) -> Result<(), OrderError> {
    if field_flags & (1 << bit) != 0 {
        if delta {
            *slot += c.i8()? as i32;
        } else {
            *slot = c.i16()? as i32;
        }
    }
    Ok(())
}

// Bounds (clip rect) description flags.
const BOUND_LEFT: u8 = 0x01;
const BOUND_TOP: u8 = 0x02;
const BOUND_RIGHT: u8 = 0x04;
const BOUND_BOTTOM: u8 = 0x08;
const BOUND_DELTA_LEFT: u8 = 0x10;
const BOUND_DELTA_TOP: u8 = 0x20;
const BOUND_DELTA_RIGHT: u8 = 0x40;
const BOUND_DELTA_BOTTOM: u8 = 0x80;

/// The persistent clip rectangle. Bounds are sticky across orders: a TS_BOUNDS
/// order updates only the edges whose flag is present (absolute or delta);
/// TS_ZERO_BOUNDS_DELTAS reuses the previous bounds unchanged. Right/bottom are
/// inclusive in the wire format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bounds {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Bounds {
    /// Read a bounds description (when control has TS_BOUNDS and not
    /// TS_ZERO_BOUNDS_DELTAS), updating self in place. Mirrors FreeRDP
    /// `update_read_bounds`.
    pub fn read(&mut self, c: &mut Cursor) -> Result<(), OrderError> {
        let flags = c.u8()?;
        if flags & BOUND_LEFT != 0 {
            self.left = c.i16()? as i32;
        } else if flags & BOUND_DELTA_LEFT != 0 {
            self.left += c.i8()? as i32;
        }
        if flags & BOUND_TOP != 0 {
            self.top = c.i16()? as i32;
        } else if flags & BOUND_DELTA_TOP != 0 {
            self.top += c.i8()? as i32;
        }
        if flags & BOUND_RIGHT != 0 {
            self.right = c.i16()? as i32;
        } else if flags & BOUND_DELTA_RIGHT != 0 {
            self.right += c.i8()? as i32;
        }
        if flags & BOUND_BOTTOM != 0 {
            self.bottom = c.i16()? as i32;
        } else if flags & BOUND_DELTA_BOTTOM != 0 {
            self.bottom += c.i8()? as i32;
        }
        Ok(())
    }

    /// As a clip rect (inclusive right/bottom -> exclusive width/height).
    pub fn to_rect(self) -> Rect {
        Rect::from_inclusive(self.left, self.top, self.right, self.bottom)
    }
}
