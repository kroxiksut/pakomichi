// SPDX-License-Identifier: MIT OR Apache-2.0

//! Publishing one APT generation (P3-001): build, store, sign, check, and
//! only then make it current (`architecture/delivery-recovery.md`,
//! "Immutable generations").
//!
//! 1. `Packages` and `Release` are built from the admitted packages
//!    ([`build_indexes`]).
//! 2. The indexes go into the CAS; the packages must already be there.
//! 3. The signer clear-signs `Release`; `gpgv` checks the result against
//!    the keyring APT uses, and the text the signature covers must be
//!    exactly the `Release` that was built.
//! 4. [`check_generation`] re-reads the signed text and every index and
//!    checks every reference against the bytes that will be served.
//! 5. The manifest lists `InRelease`, every index at its plain and its
//!    `by-hash` path, and every package at its pool path; the generation
//!    store writes it and replaces `current` (N-015, N-033).
//!
//! Any failure before step 5 leaves `current` as it was: APT clients keep
//! the previous generation until its `Valid-Until` (R-004 G9).

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use super::apt::{
    AptError, AptPackage, AptRepository, Freshness, GenerationFiles, build_indexes,
    check_generation, iso8601,
};
use super::manifest::{
    Backend, GenerationId, GenerationMeta, RepoName, RepoPath, SourceId, Timestamp,
};
use super::sign::{MetadataSigner, MetadataVerifier, SignError};
use super::store::{GenerationStore, PublishError};
use crate::cas::{CasError, ExpectedObject, Store as CasStore, StoredObject};
use crate::error::ReasonCode;

/// Why an APT generation was not published.
#[derive(Debug)]
pub enum AptPublishError {
    Index(AptError),
    Sign(SignError),
    /// The signature is valid, but over another text than the `Release`
    /// that was built.
    SignedTextDiffers,
    Cas(CasError),
    Publish(PublishError),
}

impl AptPublishError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            Self::Index(error) => error.reason(),
            Self::Cas(
                CasError::QuotaExceeded { .. }
                | CasError::ObjectTooLarge { .. }
                | CasError::StorageFull { .. },
            ) => ReasonCode::EDiskExhausted,
            Self::Sign(_) | Self::SignedTextDiffers | Self::Cas(_) | Self::Publish(_) => {
                ReasonCode::ESnapshotInconsistent
            }
        }
    }
}

impl fmt::Display for AptPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Index(error) => write!(formatter, "{error}"),
            Self::Sign(error) => write!(formatter, "{error}"),
            Self::SignedTextDiffers => {
                formatter.write_str("the signature covers another text than the built Release")
            }
            Self::Cas(error) => write!(formatter, "{error}"),
            Self::Publish(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AptPublishError {}

impl From<AptError> for AptPublishError {
    fn from(error: AptError) -> Self {
        Self::Index(error)
    }
}

impl From<SignError> for AptPublishError {
    fn from(error: SignError) -> Self {
        Self::Sign(error)
    }
}

impl From<CasError> for AptPublishError {
    fn from(error: CasError) -> Self {
        Self::Cas(error)
    }
}

impl From<PublishError> for AptPublishError {
    fn from(error: PublishError) -> Self {
        Self::Publish(error)
    }
}

/// One APT generation to publish.
#[derive(Clone, Debug)]
pub struct AptGeneration<'a> {
    /// The directory of the logical repository in the store.
    pub repo: RepoName,
    pub source: SourceId,
    pub apt: &'a AptRepository,
    /// The admitted packages; their bytes must already be in the CAS.
    pub packages: &'a [AptPackage],
    pub freshness: Freshness,
}

/// Builds, signs, checks, and publishes one generation; see the module
/// documentation for the order. Returns the new current generation.
pub fn publish_apt(
    store: &mut GenerationStore,
    cas: &CasStore,
    signer: &dyn MetadataSigner,
    verifier: &dyn MetadataVerifier,
    generation: AptGeneration<'_>,
    now: SystemTime,
) -> Result<GenerationId, AptPublishError> {
    let now_seconds = now
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let apt = generation.apt;
    let indexes = build_indexes(apt, generation.packages, generation.freshness, now_seconds)?;

    // Stored objects hold their CAS lease until the manifest refers to them.
    let mut held: Vec<StoredObject> = Vec::new();
    let mut objects: Vec<(RepoPath, ExpectedObject)> = Vec::new();
    for (path, bytes) in &indexes.indexes {
        let stored = cas.insert(bytes.as_slice())?;
        let object = ExpectedObject::new(stored.digest(), stored.size());
        let by_hash = by_hash_path(path, &object)?;
        objects.push((path.clone(), object));
        objects.push((by_hash, object));
        held.push(stored);
    }

    let in_release = signer.clearsign(&indexes.release)?;
    let signed = verifier.verify_clearsigned(&in_release)?;
    if signed != indexes.release {
        return Err(AptPublishError::SignedTextDiffers);
    }
    let files = GenerationFiles {
        indexes: indexes.indexes.iter().cloned().collect::<BTreeMap<_, _>>(),
        pool: indexes.pool.iter().cloned().collect::<BTreeMap<_, _>>(),
    };
    check_generation(apt, &signed, &files, indexes.valid_until, now_seconds)?;

    let stored = cas.insert(in_release.as_slice())?;
    objects.push((
        apt.in_release_path()?,
        ExpectedObject::new(stored.digest(), stored.size()),
    ));
    held.push(stored);
    objects.extend(indexes.pool.iter().cloned());

    let timestamp = |seconds| {
        Timestamp::new(&iso8601(seconds))
            .map_err(|error| AptPublishError::Publish(PublishError::Manifest(error)))
    };
    let meta = GenerationMeta {
        repo: generation.repo,
        source: generation.source,
        backend: Backend::Apt,
        valid_from: timestamp(indexes.date)?,
        valid_until: timestamp(indexes.valid_until)?,
    };
    let id = store.publish(meta, objects, cas, now)?;
    drop(held);
    Ok(id)
}

fn by_hash_path(plain: &RepoPath, object: &ExpectedObject) -> Result<RepoPath, AptError> {
    let text = plain.as_str();
    let parent = text.rsplit_once('/').map_or("", |(parent, _)| parent);
    let alias = format!("{parent}/by-hash/SHA256/{}", object.sha256.to_hex());
    RepoPath::new(&alias).map_err(|_| AptError::Check(format!("{alias} is not a path")))
}

#[cfg(test)]
#[path = "apt_store_tests.rs"]
mod tests;
