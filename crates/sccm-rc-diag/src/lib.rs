//! Pre-flight diagnostics for SCCM Remote Control targets.
//!
//! Each `Check` runs independently and returns a `CheckResult`.
//! Designed so a viewer-UI can show "this is why connecting will fail
//! before you even try", and so support staff can run it standalone
//! without the viewer at all.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::time::Duration;

pub mod checks;
mod winutil;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warning,
    Blocker,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: &'static str,
    pub severity: Severity,
    pub message: String,
    pub remediation: Option<String>,
    pub duration: Duration,
}

impl CheckResult {
    pub fn ok(name: &'static str, msg: impl Into<String>, dur: Duration) -> Self {
        Self {
            name,
            severity: Severity::Ok,
            message: msg.into(),
            remediation: None,
            duration: dur,
        }
    }

    pub fn blocker(
        name: &'static str,
        msg: impl Into<String>,
        remediation: impl Into<String>,
        dur: Duration,
    ) -> Self {
        Self {
            name,
            severity: Severity::Blocker,
            message: msg.into(),
            remediation: Some(remediation.into()),
            duration: dur,
        }
    }

    pub fn warning(
        name: &'static str,
        msg: impl Into<String>,
        remediation: impl Into<String>,
        dur: Duration,
    ) -> Self {
        Self {
            name,
            severity: Severity::Warning,
            message: msg.into(),
            remediation: Some(remediation.into()),
            duration: dur,
        }
    }
}
