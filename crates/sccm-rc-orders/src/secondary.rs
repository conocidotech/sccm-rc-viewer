//! Secondary drawing orders: caches the server populates (Cache Bitmap,
//! Cache Color Table). The stream stays in sync via the header-declared order
//! length, so unimplemented secondary orders (glyph/brush/rev2/rev3) are
//! skipped without corrupting the parse.

use crate::bitmap;
use crate::cache::{BitmapCache, PaletteCache};
use crate::color::ColorDepth;
use crate::cursor::Cursor;
use crate::OrderError;

// Secondary order types.
pub const CACHE_BITMAP_UNCOMPRESSED: u8 = 0x00;
pub const CACHE_COLOR_TABLE: u8 = 0x01;
pub const CACHE_BITMAP_COMPRESSED: u8 = 0x02;
pub const CACHE_GLYPH: u8 = 0x03;
pub const CACHE_BITMAP_UNCOMPRESSED_REV2: u8 = 0x04;
pub const CACHE_BITMAP_COMPRESSED_REV2: u8 = 0x05;
pub const CACHE_BRUSH: u8 = 0x07;
pub const CACHE_BITMAP_COMPRESSED_REV3: u8 = 0x08;

const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

/// Apply one secondary order (already sliced to its payload).
pub fn apply(
    order_type: u8,
    extra_flags: u16,
    payload: &[u8],
    bitmaps: &mut BitmapCache,
    palettes: &mut PaletteCache,
) -> Result<(), OrderError> {
    match order_type {
        CACHE_BITMAP_UNCOMPRESSED => cache_bitmap_rev1(extra_flags, payload, false, bitmaps),
        CACHE_BITMAP_COMPRESSED => cache_bitmap_rev1(extra_flags, payload, true, bitmaps),
        CACHE_COLOR_TABLE => cache_color_table(payload, palettes),
        CACHE_BITMAP_UNCOMPRESSED_REV2
        | CACHE_BITMAP_COMPRESSED_REV2
        | CACHE_BITMAP_COMPRESSED_REV3
        | CACHE_GLYPH
        | CACHE_BRUSH => {
            // Not yet implemented — stream stays in sync via the order length.
            tracing::debug!(order_type, "skipping unimplemented secondary order");
            Ok(())
        }
        other => Err(OrderError::UnsupportedSecondaryOrder(other)),
    }
}

/// TS_CACHE_BITMAP_DATA (revision 1), MS-RDPEGDI 2.2.2.2.1.2.2.
fn cache_bitmap_rev1(
    extra_flags: u16,
    payload: &[u8],
    compressed: bool,
    bitmaps: &mut BitmapCache,
) -> Result<(), OrderError> {
    let mut c = Cursor::new(payload);
    let cache_id = c.u8()?;
    let _pad = c.u8()?;
    let width = c.u8()? as u16;
    let height = c.u8()? as u16;
    let bpp = c.u8()? as u16;
    let mut bitmap_length = c.u16()? as usize;
    let cache_index = c.u16()?;

    let depth = ColorDepth::from_bpp(bpp).ok_or(OrderError::Malformed("bad cache bitmap bpp"))?;

    if compressed && (extra_flags & NO_BITMAP_COMPRESSION_HDR) == 0 {
        // TS_CD_HEADER (8 bytes): cbCompFirstRowSize(2,=0), cbCompMainBodySize(2),
        // cbScanWidth(2), cbUncompressedSize(2). The real compressed length is
        // cbCompMainBodySize.
        let _first_row = c.u16()?;
        let main_body = c.u16()? as usize;
        let _scan_width = c.u16()?;
        let _uncompressed = c.u16()?;
        bitmap_length = main_body;
    }

    let data = c.bytes(bitmap_length)?;
    let bmp = bitmap::decode(data, width, height, depth, compressed, None)?;
    bitmaps.insert(cache_id as usize, cache_index as usize, bmp);
    Ok(())
}

/// TS_CACHE_COLOR_TABLE_ORDER, MS-RDPEGDI 2.2.2.2.1.2.4. Populates a palette
/// for 8 bpp sessions.
fn cache_color_table(payload: &[u8], palettes: &mut PaletteCache) -> Result<(), OrderError> {
    let mut c = Cursor::new(payload);
    let cache_index = c.u8()?;
    let number_colors = c.u16()?;
    if number_colors != 256 {
        // Spec mandates 256; be lenient but bail if absurd.
        return Err(OrderError::Malformed("color table not 256 entries"));
    }
    let mut table = Box::new([[0u8; 4]; 256]);
    for entry in table.iter_mut() {
        // TS_PALETTE_ENTRY: blue, green, red, pad (4 bytes).
        let b = c.u8()?;
        let g = c.u8()?;
        let r = c.u8()?;
        let _pad = c.u8()?;
        *entry = [r, g, b, 0xff];
    }
    palettes.insert(cache_index as usize, table);
    Ok(())
}
