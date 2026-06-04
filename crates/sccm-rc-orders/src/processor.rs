//! The order-stream processor: decodes a Fast-Path "Orders" update into the
//! [`OrderCanvas`], maintaining persistent per-order field state, the clip
//! bounds, and the caches across orders.

use crate::cache::{BitmapCache, GlyphCache, PaletteCache};
use crate::canvas::{OrderCanvas, Rect};
use crate::color::ColorDepth;
use crate::cursor::Cursor;
use crate::header::{
    self, Bounds, ORD_DSTBLT, ORD_FAST_GLYPH, ORD_FAST_INDEX, ORD_GLYPH_INDEX, ORD_LINE_TO,
    ORD_MEMBLT, ORD_OPAQUE_RECT, ORD_PATBLT, ORD_SCRBLT, TS_BOUNDS, TS_DELTA_COORDINATES,
    TS_SECONDARY, TS_STANDARD, TS_TYPE_CHANGE, TS_ZERO_BOUNDS_DELTAS,
};
use crate::primary::{DstBlt, FastGlyph, FastIndex, GlyphIndex, LineTo, MemBlt, OpaqueRect, PatBlt, ScrBlt};
use crate::{secondary, OrderError};

// Alternate-secondary order types we can size (to keep the stream in sync).
const ALTSEC_SWITCH_SURFACE: u8 = 0x00;
const ALTSEC_FRAME_MARKER: u8 = 0x0D;

/// Result of processing one Orders update.
#[derive(Debug, Default)]
pub struct ProcessOutcome {
    /// Union of all pixels touched (None if nothing drew).
    pub dirty: Option<Rect>,
    /// Number of orders decoded.
    pub orders: usize,
    /// Orders skipped/aborted (unknown altsec, etc.).
    pub skipped: usize,
}

pub struct OrderProcessor {
    canvas: OrderCanvas,
    bitmaps: BitmapCache,
    palettes: PaletteCache,
    glyphs: GlyphCache,
    #[allow(dead_code)]
    depth: ColorDepth,
    bounds: Bounds,
    current_order_type: Option<u8>,
    trace_budget: u32,

    // Persistent per-order field state (RDP omits unchanged fields).
    dstblt: DstBlt,
    patblt: PatBlt,
    scrblt: ScrBlt,
    opaque: OpaqueRect,
    memblt: MemBlt,
    lineto: LineTo,
    glyph_index: GlyphIndex,
    fast_index: FastIndex,
    fast_glyph: FastGlyph,
}

impl OrderProcessor {
    pub fn new(width: u16, height: u16, depth: ColorDepth) -> Self {
        Self {
            canvas: OrderCanvas::new(width, height),
            bitmaps: BitmapCache::new(),
            palettes: PaletteCache::new(),
            glyphs: GlyphCache::new(),
            depth,
            bounds: Bounds::default(),
            current_order_type: None,
            trace_budget: match std::env::var("SCCM_RC_ORDER_TRACE").ok().as_deref() {
                Some("0") | None => 0,
                Some("1") => 120,
                Some(n) => n.parse().unwrap_or(120),
            },
            dstblt: DstBlt::default(),
            patblt: PatBlt::default(),
            scrblt: ScrBlt::default(),
            opaque: OpaqueRect::default(),
            memblt: MemBlt::default(),
            lineto: LineTo::default(),
            glyph_index: GlyphIndex::default(),
            fast_index: FastIndex::default(),
            fast_glyph: FastGlyph::default(),
        }
    }

    pub fn canvas(&self) -> &OrderCanvas {
        &self.canvas
    }

    /// Resize the framebuffer (reactivation with a new desktop size). The
    /// caches survive; only the canvas is cleared.
    pub fn resize(&mut self, width: u16, height: u16) {
        self.canvas.resize(width, height);
    }

    /// Process a Fast-Path Orders update. `data` is the update payload:
    /// `numberOrders` (2 bytes LE) followed by the order bytes.
    pub fn process_orders(&mut self, data: &[u8]) -> Result<ProcessOutcome, OrderError> {
        let mut c = Cursor::new(data);
        let number_orders = c.u16()? as usize;
        let mut out = ProcessOutcome::default();

        while out.orders + out.skipped < number_orders && !c.is_empty() {
            let control = c.u8()?;

            if control & TS_STANDARD == 0 {
                // Alternate secondary order — has no length field; we can only
                // continue if we know how to size it.
                if self.altsec(&mut c, control)? {
                    out.skipped += 1;
                } else {
                    out.skipped += 1;
                    break; // unknown altsec: stop parsing this update
                }
                continue;
            }

            if control & TS_SECONDARY != 0 {
                self.secondary(&mut c)?;
                out.orders += 1;
                continue;
            }

            let dirty = self.primary(&mut c, control)?;
            if self.trace_budget > 0 {
                self.trace_budget -= 1;
                let r = dirty.unwrap_or(Rect::new(0, 0, 0, 0));
                if self.current_order_type == Some(ORD_MEMBLT) {
                    let m = &self.memblt;
                    tracing::info!(
                        cache_id = m.cache_id, cache_index = m.cache_index,
                        dst = format!("{},{} {}x{}", m.x, m.y, m.w, m.h),
                        src = format!("{},{}", m.x_src, m.y_src),
                        empty = r.is_empty(),
                        "MEMBLT"
                    );
                } else {
                    tracing::info!(
                        order_type = self.current_order_type,
                        control = format!("{control:#04x}"),
                        rect = format!("{},{} {}x{}", r.x, r.y, r.w, r.h),
                        empty = r.is_empty(),
                        "primary order"
                    );
                }
            }
            if let Some(r) = dirty {
                if !r.is_empty() {
                    out.dirty = Some(out.dirty.map_or(r, |d| d.union(&r)));
                }
            }
            out.orders += 1;
        }

        Ok(out)
    }

    fn secondary(&mut self, c: &mut Cursor) -> Result<(), OrderError> {
        // Secondary header (controlFlags already consumed): orderLength(2),
        // extraFlags(2), orderType(1). Total order length = orderLength + 13
        // (MS-RDPEGDI 2.2.2.2.1.2.1.1), so the payload after this 6-byte header
        // is orderLength + 7 bytes.
        let order_length = c.u16()? as usize;
        let extra_flags = c.u16()?;
        let order_type = c.u8()?;
        let payload_len = order_length.saturating_add(7).min(c.remaining());
        if self.trace_budget > 0 {
            self.trace_budget -= 1;
            tracing::info!(order_type, extra_flags, order_length, payload_len, "secondary (cache) order");
        }
        let payload = c.bytes(payload_len)?;

        if let Err(e) = secondary::apply(
            order_type,
            extra_flags,
            payload,
            &mut self.bitmaps,
            &mut self.palettes,
            &mut self.glyphs,
        ) {
            tracing::debug!(order_type, error = %e, "secondary order failed");
        }
        Ok(())
    }

    fn primary(&mut self, c: &mut Cursor, control: u8) -> Result<Option<Rect>, OrderError> {
        if control & TS_TYPE_CHANGE != 0 {
            self.current_order_type = Some(c.u8()?);
        }
        let order_type = self
            .current_order_type
            .ok_or(OrderError::NoOrderType(control))?;

        let field_bytes =
            header::field_bytes(order_type).ok_or(OrderError::UnsupportedOrderType(order_type))?;
        let field_flags = header::read_field_flags(c, control, field_bytes)?;

        // Bounds (clip). TS_BOUNDS => bounds apply; only re-read when
        // TS_ZERO_BOUNDS_DELTAS is clear.
        let clip = if control & TS_BOUNDS != 0 {
            if control & TS_ZERO_BOUNDS_DELTAS == 0 {
                self.bounds.read(c)?;
            }
            Some(self.bounds.to_rect())
        } else {
            None
        };

        let delta = control & TS_DELTA_COORDINATES != 0;

        let dirty = match order_type {
            ORD_DSTBLT => {
                self.dstblt.decode(c, field_flags, delta)?;
                Some(self.dstblt.draw(&mut self.canvas, clip))
            }
            ORD_OPAQUE_RECT => {
                self.opaque.decode(c, field_flags, delta)?;
                Some(self.opaque.draw(&mut self.canvas, clip))
            }
            ORD_PATBLT => {
                self.patblt.decode(c, field_flags, delta)?;
                Some(self.patblt.draw(&mut self.canvas, clip))
            }
            ORD_SCRBLT => {
                self.scrblt.decode(c, field_flags, delta)?;
                Some(self.scrblt.draw(&mut self.canvas, clip))
            }
            ORD_MEMBLT => {
                self.memblt.decode(c, field_flags, delta)?;
                Some(self.memblt.draw(&mut self.canvas, clip, &self.bitmaps))
            }
            ORD_LINE_TO => {
                self.lineto.decode(c, field_flags, delta)?;
                Some(self.lineto.draw(&mut self.canvas, clip))
            }
            ORD_GLYPH_INDEX => {
                self.glyph_index.decode(c, field_flags, delta)?;
                Some(self.glyph_index.draw(&mut self.canvas, clip, &mut self.glyphs))
            }
            ORD_FAST_INDEX => {
                self.fast_index.decode(c, field_flags, delta)?;
                Some(self.fast_index.draw(&mut self.canvas, clip, &mut self.glyphs))
            }
            ORD_FAST_GLYPH => {
                self.fast_glyph.decode(c, field_flags, delta)?;
                Some(self.fast_glyph.draw(&mut self.canvas, clip, &mut self.glyphs))
            }
            other => return Err(OrderError::UnsupportedOrderType(other)),
        };

        Ok(dirty)
    }

    /// Returns Ok(true) if the altsec order was sized and skipped, Ok(false) if
    /// it is unknown (caller stops parsing this update).
    fn altsec(&mut self, c: &mut Cursor, control: u8) -> Result<bool, OrderError> {
        let order_type = control >> 2;
        match order_type {
            ALTSEC_FRAME_MARKER => {
                c.skip(4)?; // action (UINT32)
                Ok(true)
            }
            ALTSEC_SWITCH_SURFACE => {
                c.skip(2)?; // surfaceId (UINT16)
                Ok(true)
            }
            other => {
                tracing::debug!(altsec = other, "unknown alternate-secondary order; stopping");
                Ok(false)
            }
        }
    }
}
