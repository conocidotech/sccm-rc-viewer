use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("sspi: {0}")]
    Sspi(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("connection refused — target may not have CcmExec running, or TCP/2701 is blocked")]
    Refused,

    #[error("session arbitration denied by remote user")]
    ArbitrationDenied,

    #[error("session arbitration timed out (no response from remote user)")]
    ArbitrationTimeout,

    #[error("a remote-control session is already active on the target (possibly a previous session of yours that was not released)")]
    ExistingSession,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
