//! SCCM Remote Control 2701-wire protocol.
//!
//! See `docs/SPEC.md` in the workspace root for the wire format.
//!
//! Layers (outer → inner):
//! ```text
//!  TCP/2701
//!    └── SSPI Negotiate handshake (SecFilter wrap)
//!          └── Session arbitration (RequestHostArbitration RPC)
//!                └── Standard MS-RDPBCGR frames
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod transport;
pub mod handshake;
pub mod arbitration;
pub mod error;

pub use error::{Error, Result};
