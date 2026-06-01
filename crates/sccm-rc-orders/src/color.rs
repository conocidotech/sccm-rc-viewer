//! Pixel-format conversions for the inner RDP color depth. Drawing orders and
//! cached bitmaps carry colors in the session's bpp; the canvas is RGBA32.

/// Expand a 5-bit channel to 8-bit.
#[inline]
fn x5(v: u16) -> u8 {
    ((v << 3) | (v >> 2)) as u8
}

/// Expand a 6-bit channel to 8-bit.
#[inline]
fn x6(v: u16) -> u8 {
    ((v << 2) | (v >> 4)) as u8
}

/// RGB565 (16 bpp) little-endian u16 -> RGBA.
#[inline]
pub fn rgb565(p: u16) -> [u8; 4] {
    let r = x5((p >> 11) & 0x1f);
    let g = x6((p >> 5) & 0x3f);
    let b = x5(p & 0x1f);
    [r, g, b, 0xff]
}

/// RGB555 (15 bpp) little-endian u16 -> RGBA.
#[inline]
pub fn rgb555(p: u16) -> [u8; 4] {
    let r = x5((p >> 10) & 0x1f);
    let g = x5((p >> 5) & 0x1f);
    let b = x5(p & 0x1f);
    [r, g, b, 0xff]
}

/// An OpaqueRect / brush color field: three 1-byte components as carried in
/// the order stream (RedOrPaletteIndex, Green, Blue). For >8 bpp these are the
/// red/green/blue intensities directly.
#[inline]
pub fn colorref(red_or_idx: u8, green: u8, blue: u8) -> [u8; 4] {
    [red_or_idx, green, blue, 0xff]
}

/// Bits per pixel of the inner RDP session / a cached bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorDepth {
    Bpp8,
    Bpp15,
    Bpp16,
    Bpp24,
    Bpp32,
}

impl ColorDepth {
    pub fn from_bpp(bpp: u16) -> Option<ColorDepth> {
        Some(match bpp {
            8 => ColorDepth::Bpp8,
            15 => ColorDepth::Bpp15,
            16 => ColorDepth::Bpp16,
            24 => ColorDepth::Bpp24,
            32 => ColorDepth::Bpp32,
            _ => return None,
        })
    }

    pub fn bytes_per_pixel(self) -> usize {
        match self {
            ColorDepth::Bpp8 => 1,
            ColorDepth::Bpp15 | ColorDepth::Bpp16 => 2,
            ColorDepth::Bpp24 => 3,
            ColorDepth::Bpp32 => 4,
        }
    }

    /// Convert one source pixel (little-endian, RDP byte order) to RGBA.
    /// `palette` is required for 8 bpp; without it, 8 bpp maps to grayscale.
    #[inline]
    pub fn to_rgba(self, src: &[u8], palette: Option<&[[u8; 4]; 256]>) -> [u8; 4] {
        match self {
            ColorDepth::Bpp8 => {
                let idx = src[0] as usize;
                match palette {
                    Some(pal) => pal[idx],
                    None => [src[0], src[0], src[0], 0xff],
                }
            }
            ColorDepth::Bpp15 => rgb555(u16::from_le_bytes([src[0], src[1]])),
            ColorDepth::Bpp16 => rgb565(u16::from_le_bytes([src[0], src[1]])),
            // RDP 24/32 bpp raw bitmaps are stored B, G, R(, X), bottom-up.
            ColorDepth::Bpp24 => [src[2], src[1], src[0], 0xff],
            ColorDepth::Bpp32 => [src[2], src[1], src[0], 0xff],
        }
    }
}
