// SPDX-License-Identifier: MIT OR Apache-2.0

//! Release and asset pins, and the release-identity checks of a verified
//! attestation (R-003 steps 1–3, ADR-030 point 5).
//!
//! These are pure comparisons of values; nothing here verifies a signature.
//! R-003 showed what they must cover:
//!
//! - A mutable release keeps its release ID, tag, tag commit, and asset name
//!   when an asset is replaced; only the asset ID and the digest change. An
//!   admitted asset is therefore pinned as `(release ID, asset ID, SHA-256)`
//!   ([`AssetPin`]).
//! - An attestation outlives the asset it was made for: the removed file
//!   still verifies by digest. An attested digest must also be the API digest
//!   of the asset that is in the release now ([`current_asset`]).
//! - A release attestation found through the tag commit can belong to
//!   another release on the same commit. Its `databaseId` and `tag` must be
//!   the release being checked ([`ExpectedRelease::check_release_claims`]).
//! - The release attestation's `sha1` subject is the object the tag
//!   reference points to, as GitHub returns it: the commit for a lightweight
//!   tag, but the tag object for an annotated tag, whose peeled commit the
//!   attestation does not name (`research/r-003/results/annotated-tag-reference.tsv`).
//!
//! Every comparison is exact and case-sensitive.

use std::fmt;

use super::identity::{AssetId, OwnerId, PinnedRepository, ReleaseId, RepositoryId};
use super::wire::{Release, ReleaseAsset};
use crate::cas::Sha256Digest;
use crate::error::ReasonCode;

/// A Git object ID (SHA-1): a commit, or the tag object of an annotated tag.
/// Release attestations name the tag reference object in a `sha1` subject;
/// SLSA provenance names the commit the workflow ran on.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitObjectId([u8; 20]);

/// The text is not 40 lowercase hexadecimal digits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidObjectId;

impl fmt::Display for InvalidObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Git object ID must be 40 lowercase hexadecimal digits")
    }
}

impl std::error::Error for InvalidObjectId {}

impl GitObjectId {
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Parses exactly 40 lowercase hexadecimal digits. Upper case is refused
    /// so that one object has one spelling.
    pub fn from_hex(text: &str) -> Result<Self, InvalidObjectId> {
        let text = text.as_bytes();
        if text.len() != 40 {
            return Err(InvalidObjectId);
        }
        let mut bytes = [0_u8; 20];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
            let high = lower_hex_value(pair[0]).ok_or(InvalidObjectId)?;
            let low = lower_hex_value(pair[1]).ok_or(InvalidObjectId)?;
            *byte = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

const fn lower_hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GitObjectId({})", self.to_hex())
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// What was recorded when an asset was admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetPin {
    pub release_id: ReleaseId,
    pub asset_id: AssetId,
    pub name: String,
    pub sha256: Sha256Digest,
}

/// The pinned asset compared with its release as the API reports it now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssetCheck {
    /// The same asset ID with the pinned API digest.
    Unchanged,
    /// The same asset ID, but the API omits its digest (R-005); the bytes
    /// must be compared with the pin after download ([`AssetPin::check_bytes`]).
    DigestUnknown,
    /// No asset with the pinned name or ID is left. The admitted copy stays
    /// in the cache; nothing new is admitted under this pin.
    Removed,
    /// The pinned name now has another asset ID or another digest: the file
    /// was replaced (`E_ASSET_MUTATED`). The pin is never rebound.
    Mutated {
        observed_asset_id: AssetId,
        observed_sha256: Option<Sha256Digest>,
    },
    /// The release given is not the pinned release; a caller error.
    OtherRelease { observed: ReleaseId },
}

impl AssetCheck {
    /// The stable reason for a blocking outcome.
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::Mutated { .. } => Some(ReasonCode::EAssetMutated),
            Self::Unchanged | Self::DigestUnknown | Self::Removed | Self::OtherRelease { .. } => {
                None
            }
        }
    }
}

/// Downloaded bytes whose SHA-256 differs from the pin (`E_ASSET_MUTATED`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BytesMutated {
    pub expected: Sha256Digest,
    pub observed: Sha256Digest,
}

impl BytesMutated {
    pub const fn reason_code(&self) -> ReasonCode {
        ReasonCode::EAssetMutated
    }
}

impl fmt::Display for BytesMutated {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "downloaded SHA-256 {} differs from the pinned {}",
            self.observed.to_hex(),
            self.expected.to_hex()
        )
    }
}

impl std::error::Error for BytesMutated {}

impl AssetPin {
    /// Compares the pin with the release's current asset list. An asset is
    /// found by its pinned ID first and by its exact name otherwise, so a
    /// replacement under the same name is reported as [`AssetCheck::Mutated`]
    /// rather than as a removal.
    pub fn check(&self, release: &Release) -> AssetCheck {
        if release.id != self.release_id {
            return AssetCheck::OtherRelease {
                observed: release.id,
            };
        }
        let by_id = release
            .assets
            .iter()
            .find(|asset| asset.id == self.asset_id);
        let asset = match by_id {
            Some(asset) => asset,
            None => match release.assets.iter().find(|asset| asset.name == self.name) {
                Some(asset) => {
                    return AssetCheck::Mutated {
                        observed_asset_id: asset.id,
                        observed_sha256: asset.api_digest,
                    };
                }
                None => return AssetCheck::Removed,
            },
        };
        match asset.api_digest {
            Some(digest) if digest == self.sha256 && asset.name == self.name => {
                AssetCheck::Unchanged
            }
            None if asset.name == self.name => AssetCheck::DigestUnknown,
            observed => AssetCheck::Mutated {
                observed_asset_id: asset.id,
                observed_sha256: observed,
            },
        }
    }

    /// Checks the SHA-256 of downloaded bytes against the pin.
    pub fn check_bytes(&self, downloaded: &Sha256Digest) -> Result<(), BytesMutated> {
        if *downloaded == self.sha256 {
            Ok(())
        } else {
            Err(BytesMutated {
                expected: self.sha256,
                observed: *downloaded,
            })
        }
    }
}

/// Why an attested digest is not the current asset of the release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentAssetError {
    /// No uploaded asset has this exact name.
    NotInRelease,
    /// The API omits the asset's digest, so it cannot be tied to the
    /// attestation before download.
    DigestUnknown { asset_id: AssetId },
    /// The current asset has another digest: the attestation belongs to an
    /// earlier or a different file (R-003 step 3).
    DigestDiffers {
        asset_id: AssetId,
        current: Sha256Digest,
    },
}

impl fmt::Display for CurrentAssetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInRelease => formatter.write_str("no uploaded asset has this name"),
            Self::DigestUnknown { asset_id } => {
                write!(formatter, "the API gives no digest for asset {asset_id}")
            }
            Self::DigestDiffers { asset_id, current } => write!(
                formatter,
                "asset {asset_id} now has SHA-256 {}, not the attested one",
                current.to_hex()
            ),
        }
    }
}

impl std::error::Error for CurrentAssetError {}

/// Finds the uploaded asset with this exact name and requires that its API
/// digest equals the attested one. An attestation that verifies by digest
/// does not prove that the file is still in the release.
pub fn current_asset<'a>(
    release: &'a Release,
    name: &str,
    attested: &Sha256Digest,
) -> Result<&'a ReleaseAsset, CurrentAssetError> {
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.uploaded && asset.name == name)
        .ok_or(CurrentAssetError::NotInRelease)?;
    match asset.api_digest {
        Some(current) if current == *attested => Ok(asset),
        Some(current) => Err(CurrentAssetError::DigestDiffers {
            asset_id: asset.id,
            current,
        }),
        None => Err(CurrentAssetError::DigestUnknown { asset_id: asset.id }),
    }
}

/// A subject of a release attestation statement that carries a name and a
/// SHA-256 digest (an asset).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedSubject {
    pub name: String,
    pub sha256: Sha256Digest,
}

/// Fields read by the verifier from a release attestation (predicate
/// `https://in-toto.io/attestation/release/v0.2`) after its signature was
/// verified. IDs are kept as the raw numbers of the predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseClaims {
    pub repository_id: u64,
    pub package_id: u64,
    pub owner_id: u64,
    pub database_id: u64,
    pub tag: String,
    /// The `sha1` digests of the `pkg:github/` subjects (the tag reference
    /// object).
    pub tag_refs: Vec<GitObjectId>,
    /// The named `sha256` subjects (assets).
    pub assets: Vec<NamedSubject>,
}

/// The first field of a release attestation that does not match. Each
/// variant names the ADR-030 point 7 sub-reason it maps to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseMismatch {
    RepositoryId {
        observed: u64,
    },
    PackageId {
        observed: u64,
    },
    OwnerId {
        observed: u64,
    },
    ReleaseId {
        observed: u64,
    },
    Tag,
    TagRef,
    /// No subject has the asset's name, or it has another digest, or the
    /// name appears with more than one digest.
    AssetSubject,
}

impl ReleaseMismatch {
    /// The ADR-030 sub-reason under `E_ATTESTATION_INVALID`.
    pub const fn sub_reason(&self) -> &'static str {
        match self {
            Self::RepositoryId { .. } => "repository_id_mismatch",
            Self::OwnerId { .. } => "owner_id_mismatch",
            Self::PackageId { .. } | Self::ReleaseId { .. } | Self::Tag | Self::TagRef => {
                "release_mismatch"
            }
            Self::AssetSubject => "subject_mismatch",
        }
    }

    pub const fn reason_code(&self) -> ReasonCode {
        ReasonCode::EAttestationInvalid
    }
}

impl fmt::Display for ReleaseMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryId { observed } => {
                write!(
                    formatter,
                    "attested repository ID {observed} is not the pinned one"
                )
            }
            Self::PackageId { observed } => {
                write!(
                    formatter,
                    "attested package ID {observed} is not the pinned repository ID"
                )
            }
            Self::OwnerId { observed } => {
                write!(
                    formatter,
                    "attested owner ID {observed} is not a confirmed owner"
                )
            }
            Self::ReleaseId { observed } => {
                write!(
                    formatter,
                    "attestation is for release ID {observed}, not this release"
                )
            }
            Self::Tag => formatter.write_str("attested tag is not the release tag"),
            Self::TagRef => {
                formatter.write_str("attestation does not name the tag reference object")
            }
            Self::AssetSubject => {
                formatter.write_str("attestation does not name the asset with its digest")
            }
        }
    }
}

impl std::error::Error for ReleaseMismatch {}

/// What a release attestation must state for one asset of one release
/// (ADR-030 point 5, Strict). The tag reference object is `object.sha` of
/// `/repositories/{id}/git/ref/tags/{tag}` exactly as returned, never peeled
/// to a commit and never taken from `target_commitish`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedRelease {
    repository_id: RepositoryId,
    accepted_owner_ids: Vec<OwnerId>,
    release_id: ReleaseId,
    tag: String,
    tag_ref: GitObjectId,
    asset_name: String,
    asset_sha256: Sha256Digest,
}

impl ExpectedRelease {
    /// Built from the pinned repository (with every confirmed owner ID), the
    /// release from the API, the tag reference object, and the asset.
    pub fn new(
        repository: &PinnedRepository,
        release: &Release,
        tag_ref: GitObjectId,
        asset_name: impl Into<String>,
        asset_sha256: Sha256Digest,
    ) -> Self {
        Self {
            repository_id: repository.repository_id(),
            accepted_owner_ids: repository.accepted_owner_ids().collect(),
            release_id: release.id,
            tag: release.tag.clone(),
            tag_ref,
            asset_name: asset_name.into(),
            asset_sha256,
        }
    }

    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Owner IDs an attestation may carry, ascending.
    pub fn accepted_owner_ids(&self) -> &[OwnerId] {
        &self.accepted_owner_ids
    }

    pub const fn release_id(&self) -> ReleaseId {
        self.release_id
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub const fn tag_ref(&self) -> GitObjectId {
        self.tag_ref
    }

    pub fn asset_name(&self) -> &str {
        &self.asset_name
    }

    pub const fn asset_sha256(&self) -> Sha256Digest {
        self.asset_sha256
    }

    /// Checks the claims of a verified release attestation. The order is
    /// fixed (repository, package, owner, release, tag, tag reference,
    /// asset), so
    /// the same input always reports the same first mismatch.
    pub fn check_release_claims(&self, claims: &ReleaseClaims) -> Result<(), ReleaseMismatch> {
        if claims.repository_id != self.repository_id.get() {
            return Err(ReleaseMismatch::RepositoryId {
                observed: claims.repository_id,
            });
        }
        if claims.package_id != self.repository_id.get() {
            return Err(ReleaseMismatch::PackageId {
                observed: claims.package_id,
            });
        }
        if !self
            .accepted_owner_ids
            .iter()
            .any(|owner| owner.get() == claims.owner_id)
        {
            return Err(ReleaseMismatch::OwnerId {
                observed: claims.owner_id,
            });
        }
        if claims.database_id != self.release_id.get() {
            return Err(ReleaseMismatch::ReleaseId {
                observed: claims.database_id,
            });
        }
        if claims.tag != self.tag {
            return Err(ReleaseMismatch::Tag);
        }
        if !claims.tag_refs.contains(&self.tag_ref) {
            return Err(ReleaseMismatch::TagRef);
        }
        let mut named = claims
            .assets
            .iter()
            .filter(|subject| subject.name == self.asset_name);
        let all_match = named
            .clone()
            .all(|subject| subject.sha256 == self.asset_sha256);
        if named.next().is_none() || !all_match {
            return Err(ReleaseMismatch::AssetSubject);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "release_pin_tests.rs"]
mod tests;
