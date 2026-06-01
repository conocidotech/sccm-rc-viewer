//! The order-stream processor: decodes a Fast-Path "Orders" update into the
//! [`OrderCanvas`], maintaining persistent per-order field state, the clip
//! bounds, and the caches across orders.

use crate::cache::{BitmapCache, PaletteCache};
use crate::canvas::{OrderCanvas, Rect};
use crate::color::ColorDepth;
use crate::cursor::Cursor;
use crate::header::{
    self, Bounds, ORD_DSTBLT, ORD_LINE_TO, ORD_MEMBLT, ORD_OPAQUE_RECT, ORD_PATBLT, ORD_SCRBLT,
    TS_BOUNDS, TS_DELTA_COORDINATES, TS_SECONDARY, TS_STANDARD, TS_TYPE_CHANGE,
    TS_ZERO_BOUNDS_DELTAS,
};
use crate::primary::{DstBlt, LineTo, MemBlt, OpaqueRect, PatBlt, ScrBlt};
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
    #[allow(dead_code)]
    depth: ColorDepth,
    bounds: Bounds,
    current_order_type: Option<u8>,

    // Persistent per-order field state (RDP omits unchanged fields).
    dstblt: DstBlt,
    patblt: PatBlt,
    scrblt: ScrBlt,
    opaque: OpaqueRect,
    memblt: MemBlt,
    lineto: LineTo,
}

impl OrderProcessor {
    pub fn new(width: u16, height: u16, depth: ColorDepth) -> Self {
        Self {
            canvas: OrderCanvas::new(width, height),
            bitmaps: BitmapCache::new(),
            palettes: PaletteCache::new(),
            depth,
            bounds: Bounds::default(),
            current_order_type: None,
            dstblt: DstBlt::default(),
            patblt: PatBlt::default(),
            scrblt: ScrBlt::default(),
            opaque: OpaqueRect::default(),
            memblt: MemBlt::default(),
            lineto: LineTo::default(),
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
        let payload = c.bytes(payload_len)?;

        if let Err(e) = secondary::apply(
            order_type,
            extra_flags,
            payload,
            &mut self.bitmaps,
            &mut self.palettes,
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
