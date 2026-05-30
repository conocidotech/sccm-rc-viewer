//! Low-level TCP/2701 transport + SecFilter framing.
//!
//! STATUS: stub. Wire format TBD until first live capture.
//! See `docs/SPEC.md` § "SecFilter framing".

use crate::Result;
use tokio::net::TcpStream;

/// Standard SCCM Remote Control listening port on the target's CcmExec service.
pub const SCCM_RC_PORT: u16 = 2701;

/// A raw TCP connection to an SCCM RC target, before SSPI handshake.
#[derive(Debug)]
pub struct RawConnection {
    stream: TcpStream,
}

impl RawConnection {
    pub async fn connect(host: &str) -> Result<Self> {
        let addr = format!("{host}:{SCCM_RC_PORT}");
        let stream = TcpStream::connect(&addr).await?;
        Ok(Self { stream })
    }

    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}
