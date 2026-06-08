//! SCCM Remote Control 2701-wire protocol.
//!
//! See `docs/SPEC.md` in the workspace root for the wire format.
//!
//! Layers (outer → inner) — confirmed from static RE 2026-05-30:
//! ```text
//!  TCP/2701  (SccmStream / customtransport)
//!    └── SecurityFilter
//!          ├── handshake phase: SSPI Negotiate token exchange
//!          └── data phase:      per-message EncryptMessage/DecryptMessage
//!                └── standard MS-RDPBCGR frames (hand off to IronRDP)
//! ```
//!
//! The session arbitration ("ask remote user permission") does NOT
//! require an RPC client on the viewer side; the outcome arrives on
//! the same TCP stream. See `docs/SPEC.md` § 3.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod transport;
pub mod handshake;
pub mod framing;
pub mod error;
pub mod mppc;
pub mod cliprdr;

pub use error::{Error, Result};

/// Possible outcomes of the target-side session arbitration. The viewer
/// learns the outcome by observing certain bytes/events on the stream
/// after the SSPI handshake; the exact wire signal is TBD via pcap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbitrationOutcome {
    Allowed,
    Denied,
    HostIdle,
    HostInUse,
}
