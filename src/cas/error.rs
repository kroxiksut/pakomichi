// SPDX-License-Identifier: MIT OR Apache-2.0

//! Store errors and their mapping to the stable reason contract.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::error::{ObjectReference, Reason, ReasonCode, SafeText};

use super::digest::{InvalidDigest, Sha256Digest};

#[derive(Debug)]
#[non_exhaustive]
pub enum CasError {
    /// A digest in a name or request is not canonical SHA-256 hex.
    InvalidDigest,
    /// The bytes hash to another digest than the accepted one.
    DigestMismatch {
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    /// The byte count differs from the accepted size. When the source was
    /// longer, `actual` is the count at which reading stopped.
    SizeMismatch { expected: u64, actual: u64 },
    /// The object exceeds the per-object limit of the store.
    ObjectTooLarge { size: u64, limit: u64 },
    /// Writing would exceed the store quota; nothing was written.
    QuotaExceeded { requested: u64, available: u64 },
    /// The filesystem reported `ENOSPC` or `EDQUOT`.
    StorageFull { source: io::Error },
    /// A stored object no longer matches its name; it was moved to
    /// quarantine (or left in place by a read-only check).
    CorruptObject { digest: Sha256Digest },
    /// A store path is a symlink, not a regular file or directory, or is
    /// writable by other users.
    UnsafeEntry {
        path: PathBuf,
        problem: &'static str,
    },
    /// No object with this digest is stored.
    NotFound { digest: Sha256Digest },
    /// Another process holds the store lock.
    StoreBusy,
    /// Reading the caller's source failed (for example, the network).
    Source { source: io::Error },
    /// Any other filesystem failure of the store itself.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl CasError {
    /// Classifies a store-side I/O failure; a full disk or quota is reported
    /// as [`CasError::StorageFull`] so that it maps to `E_DISK_EXHAUSTED`.
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        if is_storage_full(&source) {
            Self::StorageFull { source }
        } else {
            Self::Io {
                operation,
                path: path.into(),
                source,
            }
        }
    }

    /// The stable reason code for user-facing results, if this error has one.
    /// Errors without a code are internal faults or belong to the caller's
    /// domain (for example, a source read error is a forge or network
    /// problem that the caller classifies).
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::DigestMismatch { .. }
            | Self::SizeMismatch { .. }
            | Self::CorruptObject { .. }
            | Self::UnsafeEntry { .. } => Some(ReasonCode::ECacheDigestMismatch),
            Self::ObjectTooLarge { .. } | Self::QuotaExceeded { .. } | Self::StorageFull { .. } => {
                Some(ReasonCode::EDiskExhausted)
            }
            Self::InvalidDigest
            | Self::NotFound { .. }
            | Self::StoreBusy
            | Self::Source { .. }
            | Self::Io { .. } => None,
        }
    }

    /// A reason event for `object` with a fixed message; no path, URL, or
    /// source error text enters the message.
    pub fn reason(&self, object: ObjectReference) -> Option<Reason> {
        let code = self.reason_code()?;
        let message = match self {
            Self::DigestMismatch { .. } => "bytes do not match the accepted digest",
            Self::SizeMismatch { .. } => "byte count does not match the accepted size",
            Self::CorruptObject { .. } => "stored object is corrupt and was quarantined",
            Self::UnsafeEntry { .. } => "cache entry is not a safe regular file",
            Self::ObjectTooLarge { .. } => "object exceeds the cache size limit",
            Self::QuotaExceeded { .. } => "cache quota exhausted",
            _ => "no space left for the cache",
        };
        SafeText::new(message)
            .ok()
            .map(|message| Reason::new(code, object, message))
    }
}

pub(crate) fn is_storage_full(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded
    )
}

impl From<InvalidDigest> for CasError {
    fn from(_: InvalidDigest) -> Self {
        Self::InvalidDigest
    }
}

impl fmt::Display for CasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigest => formatter.write_str("invalid SHA-256 digest"),
            Self::DigestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "digest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::SizeMismatch { expected, actual } => {
                write!(
                    formatter,
                    "size mismatch: expected {expected} bytes, got {actual}"
                )
            }
            Self::ObjectTooLarge { size, limit } => {
                write!(
                    formatter,
                    "object of {size} bytes exceeds the {limit}-byte limit"
                )
            }
            Self::QuotaExceeded {
                requested,
                available,
            } => write!(
                formatter,
                "quota exceeded: {requested} bytes requested, {available} available"
            ),
            Self::StorageFull { source } => write!(formatter, "storage full: {source}"),
            Self::CorruptObject { digest } => write!(formatter, "object {digest} is corrupt"),
            Self::UnsafeEntry { path, problem } => {
                write!(
                    formatter,
                    "unsafe store entry {}: {problem}",
                    path.display()
                )
            }
            Self::NotFound { digest } => write!(formatter, "object {digest} not found"),
            Self::StoreBusy => formatter.write_str("the store is locked by another process"),
            Self::Source { source } => write!(formatter, "source read failed: {source}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for CasError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StorageFull { source } | Self::Source { source } | Self::Io { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_disk_and_quota_map_to_disk_exhausted() {
        for kind in [io::ErrorKind::StorageFull, io::ErrorKind::QuotaExceeded] {
            let error = CasError::io("write", "x", io::Error::from(kind));
            assert!(matches!(error, CasError::StorageFull { .. }));
            assert_eq!(error.reason_code(), Some(ReasonCode::EDiskExhausted));
        }
        let quota = CasError::QuotaExceeded {
            requested: 2,
            available: 1,
        };
        assert_eq!(quota.reason_code(), Some(ReasonCode::EDiskExhausted));
    }

    #[test]
    fn other_io_errors_have_no_reason_code() {
        let error = CasError::io(
            "open",
            "x",
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert!(matches!(error, CasError::Io { .. }));
        assert_eq!(error.reason_code(), None);
    }

    #[test]
    fn integrity_failures_map_to_cache_digest_mismatch() {
        let digest = Sha256Digest::of(b"x");
        for error in [
            CasError::DigestMismatch {
                expected: digest,
                actual: Sha256Digest::of(b"y"),
            },
            CasError::SizeMismatch {
                expected: 1,
                actual: 0,
            },
            CasError::CorruptObject { digest },
            CasError::UnsafeEntry {
                path: PathBuf::from("objects/x"),
                problem: "symlink",
            },
        ] {
            assert_eq!(error.reason_code(), Some(ReasonCode::ECacheDigestMismatch));
        }
    }

    #[test]
    fn reason_message_carries_no_path() -> Result<(), Box<dyn std::error::Error>> {
        let digest = Sha256Digest::of(b"x");
        let error = CasError::UnsafeEntry {
            path: PathBuf::from("/var/lib/pakomichi/objects/secret-looking-path"),
            problem: "symlink",
        };
        let reason = error
            .reason(digest.cache_reference()?)
            .ok_or("no reason for an unsafe entry")?;
        assert_eq!(reason.code(), ReasonCode::ECacheDigestMismatch);
        assert!(!reason.message().as_str().contains("/var/lib"));
        assert_eq!(reason.object().id().as_str(), digest.to_hex());
        Ok(())
    }
}
