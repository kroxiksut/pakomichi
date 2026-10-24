// SPDX-License-Identifier: MIT OR Apache-2.0

//! Collecting the system namespace from the running system (P2-014,
//! `docs/en/specifications/system-namespace.md`).
//!
//! `parse` holds every format the collector reads and is portable; `system`
//! runs the native tools on Linux.

use std::fmt;
use std::io;

use super::SystemNamespace;
use crate::compat::SystemPackages;
use crate::error::ReasonCode;

pub mod parse;
#[cfg(target_os = "linux")]
pub mod system;

/// A namespace, the system's packages with their versions, and the sources
/// they were read from.
#[derive(Clone, Debug)]
pub struct Collected {
    pub namespace: SystemNamespace,
    /// APT base URIs or DNF repository IDs of the distribution sources.
    pub sources: Vec<String>,
    /// Versions and `Provides` of the distribution's, the installed, and the
    /// other enabled sources' packages, for the compatibility check
    /// (P2-008b, `crate::compat`).
    pub packages: SystemPackages,
    /// Other enabled sources read into `packages`.
    pub other_sources: Vec<String>,
    /// Other enabled sources whose metadata could not be read: their
    /// packages are missing from `packages`, so a dependency only they
    /// offer is held, never admitted.
    pub other_unknown: Vec<String>,
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
