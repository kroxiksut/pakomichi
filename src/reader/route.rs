// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the reader serves for a request target, independent of HTTP.

use std::path::Path;
use std::time::{Duration, SystemTime};

use super::target::parse_target;
use crate::cas::{CasError, ObjectReader, Verification, VerifiedObject};
use crate::publish::{GenerationId, PathClass, PublishError, PublishReader};

/// The default retention window for retired generations: the default
/// maximum freshness of seven days (`delivery-recovery.md`) plus one day of
/// margin (ADR-024 point 2).
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(8 * 24 * 60 * 60);

/// Read-only access to the published generations and their objects.
#[derive(Debug)]
pub struct Repositories {
    publish: PublishReader,
    objects: ObjectReader,
    retention: Duration,
}

/// The outcome of looking one target up.
#[derive(Debug)]
pub enum Lookup {
    /// The object, fully verified against the manifest, positioned at its
    /// first byte.
    Found {
        object: VerifiedObject,
        generation: GenerationId,
        class: PathClass,
    },
    /// No such repository or path, a refused target, a mutable path of a
    /// retired generation, or a retired generation past the window.
    NotFound,
    /// The object does not match its manifest entry, or is not a regular
    /// file; nothing of it is served (N-017).
    ObjectRefused(CasError),
    /// The store could not be read (an unsafe entry, a corrupt manifest, an
    /// I/O error).
    Unavailable(PublishError),
}

impl Repositories {
    /// Opens the publish root and the CAS root for reading. Neither is
    /// locked or changed.
    pub fn open(
        publish_root: &Path,
        cas_root: &Path,
        retention: Duration,
    ) -> Result<Self, OpenError> {
        Ok(Self {
            publish: PublishReader::open(publish_root).map_err(OpenError::Publish)?,
            objects: ObjectReader::open(cas_root).map_err(OpenError::Cas)?,
            retention,
        })
    }

    /// Looks `target` up as of `now`. Blocking: it reads manifests and
    /// hashes the whole object before returning it.
    pub fn lookup(&self, target: &str, now: SystemTime) -> Lookup {
        let Ok((repo, path)) = parse_target(target) else {
            return Lookup::NotFound;
        };
        let (generation, entry) = match self.publish.resolve(&repo, &path, now, self.retention) {
            Ok(Some(found)) => found,
            // A retired manifest collected between listing and reading.
            Ok(None) | Err(PublishError::UnknownGeneration) => return Lookup::NotFound,
            Err(error) => return Lookup::Unavailable(error),
        };
        match self.objects.open_object(entry.object, Verification::Full) {
            Ok(object) => Lookup::Found {
                object,
                generation,
                class: entry.class,
            },
            Err(error) => Lookup::ObjectRefused(error),
        }
    }
}

/// Why the stores could not be opened.
#[derive(Debug)]
pub enum OpenError {
    Publish(PublishError),
    Cas(CasError),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Publish(error) => write!(formatter, "publish store: {error}"),
            Self::Cas(error) => write!(formatter, "object store: {error}"),
        }
    }
}

impl std::error::Error for OpenError {}
