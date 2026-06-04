//! Secondary drawing orders: caches the server populates (Cache Bitmap,
//! Cache Color Table). The stream stays in sync via the header-declared order
//! length, so unimplemented secondary orders (glyph/brush/rev2/rev3) are
//! skipped without corrupting the parse.

use crate::bitmap;
use crate::cache::{BitmapCache, Glyph, GlyphCache, PaletteCache};
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
    glyphs: &mut GlyphCache,
) -> Result<(), OrderError> {
    match order_type {
        CACHE_BITMAP_UNCOMPRESSED => cache_bitmap_rev1(extra_flags, payload, false, bitmaps),
        CACHE_BITMAP_COMPRESSED => cache_bitmap_rev1(extra_flags, payload, true, bitmaps),
        CACHE_COLOR_TABLE => cache_color_table(payload, palettes),
        CACHE_BITMAP_UNCOMPRESSED_REV2 => {
            cache_bitmap_rev2(extra_flags, payload, false, bitmaps)
        }
        CACHE_BITMAP_COMPRESSED_REV2 => cache_bitmap_rev2(extra_flags, payload, true, bitmaps),
        // CACHE_GLYPH carries Rev1 (extraFlags bit 8, CG_GLYPH_UNICODE_PRESENT aside)
        // or Rev2; we parse the common Rev1 TS_CACHE_GLYPH_DATA layout.
        CACHE_GLYPH => cache_glyph_rev1(payload, glyphs),
        CACHE_BITMAP_COMPRESSED_REV3 | CACHE_BRUSH => {
            // Not yet implemented — stream stays in sync via the order length.
            tracing::debug!(order_type, "skipping unimplemented secondary order");
            Ok(())
        }
        other => Err(OrderError::UnsupportedSecondaryOrder(other)),
    }
}

/// TS_CACHE_GLYPH_ORDER (revision 1), MS-RDPEGDI 2.2.2.2.1.2.5: a run of
/// `cGlyphs` glyph bitmaps cached under `cacheId`. Each glyph's 1-bpp data is
/// `ceil(cx/8)` bytes per row × `cy` rows, the whole padded up to a 4-byte
/// multiple (mirrors FreeRDP `update_read_glyph_data`).
fn cache_glyph_rev1(payload: &[u8], glyphs: &mut GlyphCache) -> Result<(), OrderError> {
    let mut c = Cursor::new(payload);
    let cache_id = c.u8()? as usize;
    let c_glyphs = c.u8()?;
    for _ in 0..c_glyphs {
        let cache_index = c.u16()? as usize;
        let x = c.i16()?;
        let y = c.i16()?;
        let cx = c.u16()?;
        let cy = c.u16()?;
        let row_bytes = (cx as usize + 7) / 8;
        let mut cb = row_bytes * cy as usize;
        if cb % 4 != 0 {
            cb += 4 - (cb % 4);
        }
        let aj = c.bytes(cb.min(c.remaining()))?.to_vec();
        glyphs.insert(cache_id, cache_index, Glyph { x, y, cx, cy, aj });
    }
    Ok(())
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

// CBR2 header flags (already shifted right by 7 from the secondary extraFlags).
const CBR2_HEIGHT_SAME_AS_WIDTH: u16 = 0x01;
const CBR2_PERSISTENT_KEY_PRESENT: u16 = 0x02;
const CBR2_NO_BITMAP_COMPRESSION_HDR: u16 = 0x08;

/// MS-RDPEGDI variable-length unsigned (1 or 2 bytes): high bit of the first
/// byte signals a 2-byte value.
fn read_2byte(c: &mut Cursor) -> Result<usize, OrderError> {
    let b0 = c.u8()?;
    if b0 & 0x80 != 0 {
        Ok((((b0 & 0x7f) as usize) << 8) | c.u8()? as usize)
    } else {
        Ok(b0 as usize)
    }
}

/// MS-RDPEGDI variable-length unsigned (1–4 bytes): top 2 bits of the first byte
/// are the count of additional bytes.
fn read_4byte(c: &mut Cursor) -> Result<usize, OrderError> {
    let b0 = c.u8()?;
    let count = (b0 & 0xc0) >> 6;
    let mut val = (b0 & 0x3f) as usize;
    for _ in 0..count {
        val = (val << 8) | c.u8()? as usize;
    }
    Ok(val)
}

/// TS_CACHE_BITMAP_REV2_ORDER, MS-RDPEGDI 2.2.2.2.1.2.3. The SCCM RC server
/// paints the desktop as 64x64 tiles cached with this order (waiting-list index
/// 0x7FFF) and blitted by MemBlt. `extra_flags` is the secondary header's
/// extraFlags: cacheId in bits 0-2, bppId in bits 3-6, the CBR2 flags in bits 7+.
fn cache_bitmap_rev2(
    extra_flags: u16,
    payload: &[u8],
    compressed: bool,
    bitmaps: &mut BitmapCache,
) -> Result<(), OrderError> {
    let cache_id = (extra_flags & 0x0007) as usize;
    let bpp_id = (extra_flags >> 3) & 0x07;
    let flags = extra_flags >> 7;

    let mut c = Cursor::new(payload);
    if flags & CBR2_PERSISTENT_KEY_PRESENT != 0 {
        c.skip(8)?; // key1 (UINT32) + key2 (UINT32)
    }
    let width = read_2byte(&mut c)? as u16;
    let height = if flags & CBR2_HEIGHT_SAME_AS_WIDTH != 0 {
        width
    } else {
        read_2byte(&mut c)? as u16
    };
    let mut bitmap_length = read_4byte(&mut c)?;
    let cache_index = read_2byte(&mut c)?;

    if compressed && (flags & CBR2_NO_BITMAP_COMPRESSION_HDR) == 0 {
        // TS_CD_HEADER (8 bytes); the real compressed length is cbCompMainBodySize.
        let _first_row = c.u16()?;
        let main_body = c.u16()? as usize;
        let _scan_width = c.u16()?;
        let _uncompressed = c.u16()?;
        bitmap_length = main_body;
    }

    // bppId 3/4/5/6 => 8/16/24/32. The SCCM server often sends bppId 0; derive
    // the depth from the uncompressed byte count instead.
    let bpp = match bpp_id {
        3 => 8,
        4 => 16,
        5 => 24,
        6 => 32,
        _ if !compressed && width as usize * height as usize > 0 => {
            (bitmap_length * 8 / (width as usize * height as usize)) as u16
        }
        _ => 16,
    };
    let depth = ColorDepth::from_bpp(bpp).ok_or(OrderError::Malformed("bad CBR2 bpp"))?;

    let data = c.bytes(bitmap_length.min(c.remaining()))?;
    let bmp = bitmap::decode(data, width, height, depth, compressed, None)?;

    if cache_index == crate::cache::WAITING_LIST_INDEX {
        bitmaps.insert_waiting(cache_id, bmp);
    } else {
        bitmaps.insert(cache_id, cache_index, bmp);
    }
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
