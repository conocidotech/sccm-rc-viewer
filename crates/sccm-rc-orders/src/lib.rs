//! Pure-Rust RDP primary/secondary drawing-order decoder + software renderer.
//!
//! IronRDP does not implement RDP drawing orders (MS-RDPEGDI); it renders only
//! via bitmap/surface/RemoteFx updates. The 2014-era SCCM Remote Control RDP
//! server, however, paints the desktop using primary drawing orders. This crate
//! fills that gap: it decodes a Fast-Path "Orders" update stream and renders it
//! into an [`OrderCanvas`] (a plain RGBA32 framebuffer), entirely independent of
//! the IronRDP stack so it can be unit-tested offline against pinned bytes.

mod bitmap;
mod cache;
mod canvas;
mod color;
mod cursor;
mod header;
mod primary;
mod processor;
mod rop;
mod secondary;

pub use canvas::{Bitmap, OrderCanvas, Rect};
pub use color::ColorDepth;
pub use processor::{OrderProcessor, ProcessOutcome};
pub use rop::Rop3;

/// Errors from decoding/rendering an order stream. Decode errors are generally
/// recoverable: the caller logs and continues with the next update.
#[derive(Debug, thiserror::Error)]
pub enum OrderError {
    #[error("unexpected end of order stream: needed {needed} bytes, had {have}")]
    UnexpectedEof { needed: usize, have: usize },

    #[error("unsupported order type {0:#x}")]
    UnsupportedOrderType(u8),

    #[error("unsupported secondary order type {0:#x}")]
    UnsupportedSecondaryOrder(u8),

    #[error("order type {0:#x} arrived before any TS_TYPE_CHANGE set it")]
    NoOrderType(u8),

    #[error("malformed order: {0}")]
    Malformed(&'static str),
}
