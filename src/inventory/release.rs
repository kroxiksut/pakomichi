// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inventory of one release (before download) and the admission of its
//! inspected packages (after download).

use std::collections::HashMap;
use std::fmt;

use crate::cas::Sha256Digest;
use crate::error::ReasonCode;
use crate::github::{AssetId, Release, ReleaseId};
use crate::inspect::{DebInspection, RpmInspection};

use super::asset::{AssetKind, asset_kind};
use super::channel::{ChannelPolicy, ChannelVerdict, marker_in_native_version, marker_in_text};
use super::platform::{ArchHint, Ecosystem, TargetPlatform, arch_hint};

/// Limits and choices that apply to every release of a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryPolicy {
    pub channel: ChannelPolicy,
    /// Largest asset worth downloading; the GitHub asset limit and the CAS
    /// per-object default are 2 GiB.
    pub max_package_bytes: u64,
}

impl Default for InventoryPolicy {
    fn default() -> Self {
        Self {
            channel: ChannelPolicy::Stable,
            max_package_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Why an asset is not downloaded. Recorded, never an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipReason {
    /// A package of the other ecosystem (an `.rpm` on a DEB system).
    OtherEcosystem,
    /// The name clearly names another CPU.
    OtherArchitecture(ArchHint),
    SourcePackage,
    DeltaPackage,
    DebugPackage,
    InstallerComponent,
    Archive,
    Checksum,
    Signature,
    Sbom,
    OtherPlatform,
    /// The provider reports the upload as incomplete.
    IncompleteUpload,
    /// Larger than [`InventoryPolicy::max_package_bytes`].
    TooLarge,
}

/// The decision about one asset before download.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetDecision {
    /// Download and inspect it. The hint is informational only.
    Candidate {
        hint: ArchHint,
    },
    Skipped(SkipReason),
    /// A package-like asset that is broken before download (an empty file).
    Rejected(ReasonCode),
    /// An unknown kind of file; shown to the user, never downloaded or
    /// published.
    NeedsReview,
}

/// One asset with the decision about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetEntry {
    pub asset_id: AssetId,
    pub name: String,
    pub size: u64,
    /// The provider's claim; reconciled with the downloaded bytes during
    /// admission and never a signature.
    pub api_digest: Option<Sha256Digest>,
    pub decision: AssetDecision,
}

/// Why a whole release is not offered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseExclusion {
    Draft,
    /// The channel verdict is not admitted by the policy.
    Channel(ChannelVerdict),
}

impl ReleaseExclusion {
    /// A draft or a flagged pre-release is simply not offered; an unclear
    /// channel is a hold the user can resolve (`E_CHANNEL_UNCLEAR`).
    pub const fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Self::Channel(ChannelVerdict::Unclear(_)) => Some(ReasonCode::EChannelUnclear),
            Self::Draft | Self::Channel(_) => None,
        }
    }
}

/// The inventory of one release for one target platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseInventory {
    pub release_id: ReleaseId,
    pub tag: String,
    /// From the provider flag and the tag; native versions may still make
    /// it unclear during admission.
    pub channel: ChannelVerdict,
    pub excluded: Option<ReleaseExclusion>,
    /// Every asset in provider order, including skipped ones.
    pub assets: Vec<AssetEntry>,
}

impl ReleaseInventory {
    /// Assets to download and inspect; none when the release is excluded.
    pub fn candidates(&self) -> impl Iterator<Item = &AssetEntry> {
        self.assets.iter().filter(|entry| {
            self.excluded.is_none() && matches!(entry.decision, AssetDecision::Candidate { .. })
        })
    }

    /// Assets of an unknown kind, for the user to review.
    pub fn needs_review(&self) -> impl Iterator<Item = &AssetEntry> {
        self.assets
            .iter()
            .filter(|entry| entry.decision == AssetDecision::NeedsReview)
    }
}

/// Builds the inventory of `release` for `target` from the provider's
/// asset list alone. Nothing is downloaded.
pub fn inventory_release(
    release: &Release,
    target: &TargetPlatform,
    policy: &InventoryPolicy,
) -> ReleaseInventory {
    let channel = ChannelVerdict::from_signals(release.prerelease, marker_in_text(&release.tag));
    let excluded = if release.draft {
        Some(ReleaseExclusion::Draft)
    } else if !channel.admitted_by(policy.channel) {
        Some(ReleaseExclusion::Channel(channel))
    } else {
        None
    };
    let assets = release
        .assets
        .iter()
        .map(|asset| AssetEntry {
            asset_id: asset.id,
            name: asset.name.clone(),
            size: asset.size,
            api_digest: asset.api_digest,
            decision: decide(&asset.name, asset.size, asset.uploaded, target, policy),
        })
        .collect();
    ReleaseInventory {
        release_id: release.id,
        tag: release.tag.clone(),
        channel,
        excluded,
        assets,
    }
}

fn decide(
    name: &str,
    size: u64,
    uploaded: bool,
    target: &TargetPlatform,
    policy: &InventoryPolicy,
) -> AssetDecision {
    let ecosystem = match asset_kind(name) {
        AssetKind::Deb => Ecosystem::Deb,
        AssetKind::Rpm => Ecosystem::Rpm,
        AssetKind::Unknown => return AssetDecision::NeedsReview,
        other => return AssetDecision::Skipped(skip_reason(other)),
    };
    if ecosystem != target.ecosystem() {
        return AssetDecision::Skipped(SkipReason::OtherEcosystem);
    }
    if !uploaded {
        return AssetDecision::Skipped(SkipReason::IncompleteUpload);
    }
    if size == 0 {
        return AssetDecision::Rejected(ReasonCode::EArtifactMalformed);
    }
    if size > policy.max_package_bytes {
        return AssetDecision::Skipped(SkipReason::TooLarge);
    }
    let hint = arch_hint(name);
    if hint.excludes(target.family()) {
        return AssetDecision::Skipped(SkipReason::OtherArchitecture(hint));
    }
    AssetDecision::Candidate { hint }
}

const fn skip_reason(kind: AssetKind) -> SkipReason {
    match kind {
        AssetKind::SourceRpm => SkipReason::SourcePackage,
        AssetKind::DeltaRpm => SkipReason::DeltaPackage,
        AssetKind::DebugPackage => SkipReason::DebugPackage,
        AssetKind::InstallerComponent => SkipReason::InstallerComponent,
        AssetKind::Archive => SkipReason::Archive,
        AssetKind::Checksum => SkipReason::Checksum,
        AssetKind::Signature => SkipReason::Signature,
        AssetKind::Sbom => SkipReason::Sbom,
        // Packages and unknown names are handled before this is called.
        AssetKind::OtherPlatform | AssetKind::Deb | AssetKind::Rpm | AssetKind::Unknown => {
            SkipReason::OtherPlatform
        }
    }
}

/// The native identity the inspector read from one package.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NativePackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// The full native version: the dpkg `Version`, or the RPM
    /// `[epoch:]version-release`. Never the Git tag.
    pub version: String,
    pub arch: String,
    /// An RPM source package; binary DEBs have no such form here.
    pub source: bool,
}

impl NativePackage {
    pub fn from_deb(inspection: &DebInspection) -> Self {
        let control = inspection.control();
        Self {
            ecosystem: Ecosystem::Deb,
            name: control.package().to_owned(),
            version: control.version().to_owned(),
            arch: control.architecture().to_owned(),
            source: false,
        }
    }

    pub fn from_rpm(inspection: &RpmInspection) -> Self {
        Self {
            ecosystem: Ecosystem::Rpm,
            name: inspection.name().to_owned(),
            version: inspection.evr(),
            arch: inspection.arch().to_owned(),
            source: inspection.is_source_package(),
        }
    }
}

/// A downloaded and inspected candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedAsset {
    pub asset_id: AssetId,
    /// The SHA-256 of the downloaded bytes, as the CAS computed it.
    pub sha256: Sha256Digest,
    pub package: NativePackage,
}

/// The admission of one inspected asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    /// May go on to provenance verification and the family policy.
    Eligible,
    /// The same bytes as another eligible asset of this release.
    Duplicate {
        of: AssetId,
    },
    Held(ReasonCode),
    Rejected(ReasonCode),
}

/// A programming error in the caller, not a property of the release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InventoryError {
    /// The asset is not a candidate of this inventory, or the release is
    /// excluded, so it should not have been downloaded.
    NotACandidate(AssetId),
    /// The same asset was passed twice.
    DuplicateInput(AssetId),
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACandidate(id) => write!(formatter, "asset {id} is not a candidate"),
            Self::DuplicateInput(id) => write!(formatter, "asset {id} was passed twice"),
        }
    }
}

impl std::error::Error for InventoryError {}

/// Admits the inspected candidates of one release, in input order.
///
/// Checks, per asset: the downloaded digest equals the provider's claim
/// when there is one; the native ecosystem and architecture fit the
/// target; the package is not a source package; and the native version
/// keeps the release on the source's channel. Then, across the release:
/// two different files with the same native name and architecture are
/// ambiguous and both are held, while the same bytes under two names keep
/// only the first.
pub fn admit_release(
    inventory: &ReleaseInventory,
    inspected: &[InspectedAsset],
    target: &TargetPlatform,
    policy: &InventoryPolicy,
) -> Result<Vec<(AssetId, Admission)>, InventoryError> {
    let candidates: HashMap<AssetId, &AssetEntry> = inventory
        .candidates()
        .map(|entry| (entry.asset_id, entry))
        .collect();
    let mut seen = Vec::with_capacity(inspected.len());
    let mut admissions = Vec::with_capacity(inspected.len());
    for asset in inspected {
        let entry = candidates
            .get(&asset.asset_id)
            .ok_or(InventoryError::NotACandidate(asset.asset_id))?;
        if seen.contains(&asset.asset_id) {
            return Err(InventoryError::DuplicateInput(asset.asset_id));
        }
        seen.push(asset.asset_id);
        admissions.push((
            asset.asset_id,
            admit_one(inventory, entry, asset, target, policy),
        ));
    }
    resolve_collisions(inspected, &mut admissions);
    Ok(admissions)
}

fn admit_one(
    inventory: &ReleaseInventory,
    entry: &AssetEntry,
    asset: &InspectedAsset,
    target: &TargetPlatform,
    policy: &InventoryPolicy,
) -> Admission {
    let package = &asset.package;
    if entry
        .api_digest
        .is_some_and(|claimed| claimed != asset.sha256)
    {
        // The bytes differ from what the provider announced for this asset.
        return Admission::Rejected(ReasonCode::EAssetMutated);
    }
    if package.ecosystem != target.ecosystem() || package.source {
        return Admission::Rejected(ReasonCode::EPlatformUnsupported);
    }
    if !target.accepts_native_arch(&package.arch) {
        return Admission::Held(ReasonCode::EPlatformUnsupported);
    }
    let channel = inventory
        .channel
        .with_marker(marker_in_native_version(&package.version));
    if !channel.admitted_by(policy.channel) {
        // Only a stable-flagged release with a pre-release native version
        // gets here: flagged pre-releases were excluded by the inventory.
        return Admission::Held(ReasonCode::EChannelUnclear);
    }
    Admission::Eligible
}

/// Applies the release-wide rules to the eligible assets.
fn resolve_collisions(inspected: &[InspectedAsset], admissions: &mut [(AssetId, Admission)]) {
    let mut first_by_digest: HashMap<Sha256Digest, AssetId> = HashMap::new();
    let mut digests_by_identity: HashMap<(&str, &str), Vec<Sha256Digest>> = HashMap::new();
    for (asset, (_, admission)) in inspected.iter().zip(admissions.iter_mut()) {
        if *admission != Admission::Eligible {
            continue;
        }
        if let Some(first) = first_by_digest.get(&asset.sha256) {
            *admission = Admission::Duplicate { of: *first };
            continue;
        }
        first_by_digest.insert(asset.sha256, asset.asset_id);
        digests_by_identity
            .entry((asset.package.name.as_str(), asset.package.arch.as_str()))
            .or_default()
            .push(asset.sha256);
    }
    for (asset, (_, admission)) in inspected.iter().zip(admissions.iter_mut()) {
        let identity = (asset.package.name.as_str(), asset.package.arch.as_str());
        let ambiguous = digests_by_identity
            .get(&identity)
            .is_some_and(|digests| digests.len() > 1);
        if ambiguous && matches!(admission, Admission::Eligible | Admission::Duplicate { .. }) {
            *admission = Admission::Held(ReasonCode::ESourceAmbiguous);
        }
    }
}

#[cfg(test)]
#[path = "release_tests.rs"]
mod tests;
