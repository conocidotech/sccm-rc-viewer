//! Ternary raster operation (ROP3) index. We carry the raw code so orders can
//! pass it through; the canvas only special-cases the handful that matter
//! (SRCCOPY, BLACKNESS, WHITENESS, DSTINVERT). Full ROP3 support is not needed
//! for a usable desktop image.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rop3(pub u8);

impl Rop3 {
    pub const BLACKNESS: Rop3 = Rop3(0x00);
    pub const DSTINVERT: Rop3 = Rop3(0x55);
    pub const SRCCOPY: Rop3 = Rop3(0xCC);
    pub const WHITENESS: Rop3 = Rop3(0xFF);

    pub fn is_srccopy(self) -> bool {
        self.0 == Self::SRCCOPY.0
    }
}
