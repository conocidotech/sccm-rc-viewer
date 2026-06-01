//! Minimal little-endian read cursor with the signed/coordinate reads the
//! RDP order encoding needs. Kept tiny and dependency-free.

use crate::OrderError;

pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    #[inline]
    #[allow(dead_code)] // used by upcoming rev2 cache-bitmap decoding
    pub fn position(&self) -> usize {
        self.pos
    }

    fn need(&self, n: usize) -> Result<(), OrderError> {
        if self.remaining() < n {
            Err(OrderError::UnexpectedEof {
                needed: n,
                have: self.remaining(),
            })
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn u8(&mut self) -> Result<u8, OrderError> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline]
    pub fn i8(&mut self) -> Result<i8, OrderError> {
        Ok(self.u8()? as i8)
    }

    #[inline]
    pub fn u16(&mut self) -> Result<u16, OrderError> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    #[inline]
    pub fn i16(&mut self) -> Result<i16, OrderError> {
        Ok(self.u16()? as i16)
    }

    #[inline]
    #[allow(dead_code)] // used by upcoming rev2/rev3 cache-bitmap decoding
    pub fn u32(&mut self) -> Result<u32, OrderError> {
        self.need(4)?;
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read `n` raw bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], OrderError> {
        self.need(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<(), OrderError> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }
}
