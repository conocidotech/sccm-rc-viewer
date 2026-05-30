//! High-level SCCM RC session API. Glues the transport (`sccm-rc-protocol`)
//! into IronRDP for the actual RDP frame decode.
//!
//! STATUS: stub. Implementation hangs on Phase-1 protocol work.

#![forbid(unsafe_op_in_unsafe_fn)]

use sccm_rc_protocol::Result;

#[derive(Debug)]
pub struct Session {
    target: String,
}

impl Session {
    pub async fn connect(target: impl Into<String>) -> Result<Self> {
        Ok(Self { target: target.into() })
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}
