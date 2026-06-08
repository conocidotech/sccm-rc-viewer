//! Decoding cache-bitmap data into an RGBA [`Bitmap`]. RDP bitmaps are stored
//! bottom-up in the session color depth, optionally interleaved-RLE compressed.
//! Compression is handled by `ironrdp-graphics` (well-tested); raw decoding and
//! the bottom-up -> top-down flip + color conversion are done here.

use crate::canvas::Bitmap;
use crate::color::ColorDepth;
use crate::OrderError;

/// Decode bitmap pixel data into a top-down RGBA [`Bitmap`].
///
/// * `data` — the bitmap bits (raw or RLE-compressed), bottom-up.
/// * `compressed` — whether `data` is interleaved-RLE compressed.
/// * `depth` — the source color depth.
/// * `palette` — required for 8 bpp (else grayscale fallback).
pub fn decode(
    data: &[u8],
    width: u16,
    height: u16,
    depth: ColorDepth,
    compressed: bool,
    palette: Option<&[[u8; 4]; 256]>,
) -> Result<Bitmap, OrderError> {
    let bpp = depth.bytes_per_pixel();
    let w = width as usize;
    let h = height as usize;

    // DoS guard: cache-bitmap tiles are small. A malformed Cache Bitmap Rev2 can
    // declare dimensions up to 0x7FFF each → `w*h*4` ≈ 4 GB allocated before any
    // data is even read. Reject absurd dimensions before allocating.
    const MAX_DIM: usize = 4096;
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
        return Err(OrderError::Malformed("bitmap dimensions out of range"));
    }

    // Source pixels, bottom-up, in the session bpp.
    let raw: std::borrow::Cow<'_, [u8]> = if compressed {
        let mut out = Vec::with_capacity(w * h * bpp);
        let bits = match depth {
            ColorDepth::Bpp8 => 8,
            ColorDepth::Bpp15 => 15,
            ColorDepth::Bpp16 => 16,
            ColorDepth::Bpp24 => 24,
            // 32 bpp interleaved RLE is not used; fall back to treating as raw.
            ColorDepth::Bpp32 => 32,
        };
        if bits == 32 {
            std::borrow::Cow::Borrowed(data)
        } else {
            ironrdp_graphics::rle::decompress(data, &mut out, w, h, bits)
                .map_err(|_| OrderError::Malformed("RLE decompression failed"))?;
            std::borrow::Cow::Owned(out)
        }
    } else {
        std::borrow::Cow::Borrowed(data)
    };

    let stride = w * bpp;
    if raw.len() < stride * h {
        return Err(OrderError::UnexpectedEof {
            needed: stride * h,
            have: raw.len(),
        });
    }

    // Convert bottom-up source -> top-down RGBA.
    let mut rgba = vec![0u8; w * h * 4];
    for dst_row in 0..h {
        let src_row = h - 1 - dst_row; // flip vertical
        let src_off = src_row * stride;
        let dst_off = dst_row * w * 4;
        for x in 0..w {
            let sp = &raw[src_off + x * bpp..src_off + x * bpp + bpp];
            let c = depth.to_rgba(sp, palette);
            let d = dst_off + x * 4;
            rgba[d] = c[0];
            rgba[d + 1] = c[1];
            rgba[d + 2] = c[2];
            rgba[d + 3] = 0xff;
        }
    }

    Ok(Bitmap::new(width, height, rgba))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absurd_dimensions() {
        // Dimensions past MAX_DIM must be rejected BEFORE any allocation (RRCV-8):
        // a 5000x5000 RGBA buffer would be ~100 MB, 0x7FFF² would be ~4 GB.
        let data = [0u8; 16];
        assert!(decode(&data, 5000, 10, ColorDepth::Bpp16, false, None).is_err());
        assert!(decode(&data, 10, 5000, ColorDepth::Bpp16, false, None).is_err());
        // Zero-area tiles are rejected too.
        assert!(decode(&data, 0, 10, ColorDepth::Bpp16, false, None).is_err());
        assert!(decode(&data, 10, 0, ColorDepth::Bpp16, false, None).is_err());
    }

    #[test]
    fn accepts_normal_tile() {
        // A normal small uncompressed 2x2 16bpp tile (8 source bytes) decodes.
        let data = [0u8; 2 * 2 * 2];
        assert!(decode(&data, 2, 2, ColorDepth::Bpp16, false, None).is_ok());
    }
}
