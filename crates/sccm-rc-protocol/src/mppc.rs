//! RDP bulk decompression — MPPC (Microsoft Point-to-Point Compression),
//! RDP 5.0 / 64K variant (MS-RDPBCGR 3.1.8.4.2). The SCCM RC server compresses
//! its fast-path graphics with this when the client advertises bulk compression
//! in the Client Info PDU — which cuts the wire data ~5x (the reason CmRcViewer
//! is fast). IronRDP ships no bulk decompressor, so we implement it here.
//!
//! Wire format: a bit stream (MSB-first) of literal bytes and copy-tuples
//! (offset + length) referencing a sliding history window. The decompressor is
//! STATEFUL — the 64K history persists across updates, so every compressed
//! fast-path update must be fed through it in order.

const HISTORY_SIZE: usize = 65536;
/// The 64K history plus over-read headroom. MS/FreeRDP use a 64K history buffer
/// followed by a zeroed field; a copy whose source starts near the end and runs
/// past it reads those zeros — it does NOT wrap to the front. We replicate that by
/// keeping the write region in `[0, HISTORY_SIZE)` and a zeroed tail for reads.
const HISTORY_CAP: usize = HISTORY_SIZE * 2;

/// Stateful MPPC (RDP5/64K) decompressor. Models FreeRDP's `mppc_decompress`
/// (libfreerdp/codec/mppc.c) exactly: a LINEAR history pointer (reset to 0 on
/// PACKET_AT_FRONT / PACKET_FLUSHED, bounds-checked, never wrapped mid-copy) and
/// a copy whose source index is masked to the 64K window only at its START. An
/// earlier circular variant (wrapping every byte) diverged from the server's
/// compressor deep into long sessions, corrupting the order stream.
pub struct MppcDecompressor {
    history: Vec<u8>,
    /// HistoryPtr index: grows linearly, reset to 0 on AT_FRONT/FLUSHED.
    offset: usize,
}

impl Default for MppcDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl MppcDecompressor {
    pub fn new() -> Self {
        Self {
            history: vec![0u8; HISTORY_CAP],
            offset: 0,
        }
    }

    /// Decompress one update's payload. `compressed`/`at_front`/`flushed` come
    /// from the fast-path compression flags. Returns the plaintext bytes.
    pub fn decompress(&mut self, data: &[u8], compressed: bool, at_front: bool, flushed: bool) -> Vec<u8> {
        if flushed {
            for b in self.history[..HISTORY_SIZE].iter_mut() {
                *b = 0;
            }
            self.offset = 0;
        }
        if at_front {
            self.offset = 0;
        }

        if !compressed {
            // Uncompressed: returned verbatim and does NOT update the history
            // (FreeRDP: `*ppDstData = pSrcData; return`). The server's compressor
            // likewise excludes uncompressed packets from its history.
            return data.to_vec();
        }

        let mut out = Vec::new();
        let mut br = BitReader::new(data);
        // Loop while a whole token could still begin. The smallest token is an
        // 8-bit literal, so once fewer than 8 bits remain we are in the final
        // byte's zero padding (RDP pads to a byte boundary) — stop.
        while br.bits_left() >= 8 {
            // FreeRDP bails ("history buffer index out of range") if the write
            // pointer reaches the end without an AT_FRONT reset; mirror that.
            if self.offset >= HISTORY_SIZE {
                break;
            }
            if br.read_bit() == 0 {
                // 0xxxxxxx -> literal 0x00..0x7F
                let lit = br.read(7) as u8;
                self.history[self.offset] = lit;
                out.push(lit);
                self.offset += 1;
            } else if br.read_bit() == 0 {
                // 10xxxxxx x -> literal 0x80..0xFF
                let lit = 0x80 | (br.read(7) as u8);
                self.history[self.offset] = lit;
                out.push(lit);
                self.offset += 1;
            } else {
                // 11... -> copy tuple. The source index is masked to the 64K
                // window only at its START (so a back-reference right after
                // AT_FRONT reaches the retained tail); the copy then runs LINEARLY
                // — if it crosses the 64K end it reads the zeroed headroom, it does
                // NOT wrap to the front.
                let copy_offset = decode_offset(&mut br) as usize;
                let length = decode_length(&mut br) as usize;
                if copy_offset == 0 {
                    break; // malformed
                }
                // FreeRDP errors ("history buffer overflow") if the write would
                // cross the 64K end; the server avoids this via AT_FRONT.
                if self.offset + length > HISTORY_SIZE {
                    break;
                }
                let mut src = self.offset.wrapping_sub(copy_offset) & (HISTORY_SIZE - 1);
                for _ in 0..length {
                    let b = self.history[src];
                    self.history[self.offset] = b;
                    out.push(b);
                    self.offset += 1;
                    src += 1; // linear; may read into the zeroed headroom, no wrap
                }
            }
        }
        out
    }
}

/// Decode the CopyOffset (RDP5/64K offset table). The `11` copy indicator has
/// already been consumed.
fn decode_offset(br: &mut BitReader) -> u32 {
    if br.read_bit() == 0 {
        // 110 -> 16 bits, +2368 (range 2368..65535)
        br.read(16) + 2368
    } else if br.read_bit() == 0 {
        // 1110 -> 11 bits, +320 (range 320..2367)
        br.read(11) + 320
    } else if br.read_bit() == 0 {
        // 11110 -> 8 bits, +64  (range 64..319)
        br.read(8) + 64
    } else {
        // 11111 -> 6 bits, +0   (range 0..63)
        br.read(6)
    }
}

/// Decode the Length-of-Match (RFC 2118): `0` => 3; else with `n` leading
/// ones followed by a `0`, read `n+1` value bits => 2^(n+1) + value.
/// e.g. `10`+2bits => 4..7, `110`+3bits => 8..15, `11110`+5bits => 32..63.
fn decode_length(br: &mut BitReader) -> u32 {
    let mut n = 0u32;
    while br.read_bit() == 1 {
        n += 1;
        if n > 30 {
            break; // guard against a runaway / malformed stream
        }
    }
    if n == 0 {
        3
    } else {
        let bits = (n + 1) as u8;
        (1u32 << bits) + br.read(bits)
    }
}

/// MSB-first bit reader over a byte slice. Reads past the end return 0 bits.
struct BitReader<'a> {
    data: &'a [u8],
    byte: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, byte: 0, bit: 0 }
    }

    #[inline]
    fn read_bit(&mut self) -> u32 {
        let v = if self.byte < self.data.len() {
            ((self.data[self.byte] >> (7 - self.bit)) & 1) as u32
        } else {
            0
        };
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.byte += 1;
        }
        v
    }

    /// Number of unread bits remaining in the source.
    #[inline]
    fn bits_left(&self) -> usize {
        self.data.len() * 8 - (self.byte * 8 + self.bit as usize)
    }

    #[inline]
    fn read(&mut self, n: u8) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.read_bit();
        }
        v
    }
}

#[cfg(test)]
#[path = "mppc_vectors.rs"]
mod mppc_vectors;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freerdp_rdp5_large_vector() {
        // The big FreeRDP RDP5/64K vector (2835 compressed -> 6496 bytes), which
        // exercises large copies and long token runs — flags PACKET_AT_FRONT |
        // PACKET_COMPRESSED.
        let mut d = MppcDecompressor::new();
        let out = d.decompress(mppc_vectors::RDP5_COMPRESSED, true, true, false);
        assert_eq!(out.len(), mppc_vectors::RDP5_UNCOMPRESSED.len(), "size mismatch");
        // Find the first differing byte for a useful failure message.
        if let Some((i, (a, b))) = out
            .iter()
            .zip(mppc_vectors::RDP5_UNCOMPRESSED.iter())
            .enumerate()
            .find(|(_, (a, b))| a != b)
        {
            panic!("first diff at byte {i}: got {a:#04x}, want {b:#04x}");
        }
    }

    /// Dump our decompressor's per-record output for a capture, to diff against
    /// the FreeRDP reference (experiments/mppc_ref.c). Inert unless
    /// SCCM_RC_MPPC_CAP=<capture> + SCCM_RC_MPPC_OUT=<out> are set.
    #[test]
    fn dump_decompressed_for_diff() {
        let cap = match std::env::var("SCCM_RC_MPPC_CAP") {
            Ok(p) => p,
            Err(_) => return,
        };
        let outp = std::env::var("SCCM_RC_MPPC_OUT").expect("SCCM_RC_MPPC_OUT");
        let raw = std::fs::read(&cap).expect("read capture");
        let mut dec = MppcDecompressor::new();
        let mut out = Vec::new();
        let mut i = 0usize;
        let mut recs = 0u32;
        while i + 4 <= raw.len() {
            let cflags = raw[i + 1];
            let size = u16::from_le_bytes([raw[i + 2], raw[i + 3]]) as usize;
            if i + 4 + size > raw.len() {
                break;
            }
            let data = &raw[i + 4..i + 4 + size];
            i += 4 + size;
            let d = dec.decompress(data, cflags & 0x20 != 0, cflags & 0x40 != 0, cflags & 0x80 != 0);
            out.extend_from_slice(&d);
            recs += 1;
        }
        std::fs::write(&outp, &out).expect("write out");
        eprintln!("rust: {recs} records -> {} bytes", out.len());
    }

    #[test]
    fn uncompressed_passthrough() {
        let mut d = MppcDecompressor::new();
        let out = d.decompress(b"hello", false, false, false);
        assert_eq!(out, b"hello");
    }

    #[test]
    fn literal_roundtrip_lowascii() {
        // Encode "AB" (0x41 0x42) as two `0`+7bit literals = 0100_0001 0100_0010.
        let mut d = MppcDecompressor::new();
        let out = d.decompress(&[0b0100_0001, 0b0100_0010], true, false, false);
        assert_eq!(out, b"AB");
    }

    #[test]
    fn freerdp_rdp5_bells_vector() {
        // Authoritative ground-truth vector from FreeRDP's TestFreeRDPCodecMppc.c
        // (RDP5/64K, flags PACKET_AT_FRONT | PACKET_COMPRESSED). Not circular.
        let compressed = [
            0x66, 0x6f, 0x72, 0x2e, 0x77, 0x68, 0x6f, 0x6d, 0x2e, 0x74, 0x68, 0x65, 0x2e, 0x62,
            0x65, 0x6c, 0x6c, 0x2e, 0x74, 0x6f, 0x6c, 0x6c, 0x73, 0x2c, 0xfa, 0x1b, 0x97, 0x33,
            0x7e, 0x87, 0xe3, 0x32, 0x90, 0x80,
        ];
        // NB: the genuine decode (periods as separators) — a back-reference can
        // only reproduce bytes already in the 64K history, and there is no space
        // anywhere in it, so the plaintext is the dotted form below. (The summary
        // model that first surfaced this vector "normalised" it to English with a
        // space; that is wrong — this is what FreeRDP's exact algorithm yields.)
        let expected: &[u8] = b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!";
        let mut d = MppcDecompressor::new();
        let out = d.decompress(&compressed, true, true, false);
        assert_eq!(
            out,
            expected,
            "\n got: {:02x?}\nwant: {:02x?}",
            out,
            expected
        );
    }

    #[test]
    fn copy_tuple_roundtrip() {
        // "ABCABC": literals A,B,C (each `0`+7bits) then a copy CopyOffset=3
        // (`11111`+6bits=3), LengthOfMatch=3 (`0`). Bits laid out and byte-packed:
        //   0100_0001 0100_0010 0100_0011 1111_1000 0110_0000
        // The trailing 4 zero bits are padding and must NOT yield a NUL.
        let mut d = MppcDecompressor::new();
        let out = d.decompress(&[0x41, 0x42, 0x43, 0xF8, 0x60], true, false, false);
        assert_eq!(out, b"ABCABC");
    }
}
