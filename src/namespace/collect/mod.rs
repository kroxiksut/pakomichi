// SPDX-License-Identifier: MIT OR Apache-2.0

//! Collecting the system namespace from the running system (P2-014,
//! `docs/en/specifications/system-namespace.md`).
//!
//! `parse` holds every format the collector reads and is portable; `system`
//! runs the native tools on Linux.

use std::fmt;
use std::io;

use super::SystemNamespace;
use crate::error::ReasonCode;

pub mod parse;
#[cfg(target_os = "linux")]
pub mod system;

/// A namespace and the distribution sources it was read from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Collected {
    pub namespace: SystemNamespace,
    /// APT base URIs or DNF repository IDs of the distribution sources.
    pub sources: Vec<String>,
}

/// Why the namespace could not be read.
#[derive(Debug)]
pub enum CollectError {
    /// Not one of the first targets of ADR-026.
    Unsupported,
    /// No enabled source is the distribution's own.
    NoDistributionSource,
    /// The native metadata of a distribution source is missing or
    /// unreadable (before `apt update` or `dnf makecache`, after
    /// `dnf clean all`).
    Unknown {
        source: String,
    },
    /// A native tool failed, timed out, or printed too much.
    ToolFailed {
        tool: String,
    },
    Io(io::Error),
}

impl CollectError {
    /// The reason an admission is held for while the namespace is not
    /// known. Every failure holds: unknown is never "no conflict".
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Unsupported => ReasonCode::EPlatformUnsupported,
            Self::NoDistributionSource
            | Self::Unknown { .. }
            | Self::ToolFailed { .. }
            | Self::Io(_) => ReasonCode::ESystemNamespaceUnknown,
        }
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("not a supported distribution build"),
            Self::NoDistributionSource => formatter.write_str("no enabled distribution source"),
            Self::Unknown { source } => write!(
                formatter,
                "no native metadata for distribution source {source}; refresh it with apt update or dnf makecache"
            ),
            Self::ToolFailed { tool } => write!(formatter, "native tool {tool} failed"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for CollectError {}
