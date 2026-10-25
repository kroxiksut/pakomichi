// SPDX-License-Identifier: MIT OR Apache-2.0

//! Synchronization of one GitHub source with APT (P4-001a step 1b).
//!
//! One pass, in the order of the decision priority:
//!
//! 1. **Identity.** The pinned repository is reconciled by its ID; a
//!    transfer or a replacement suspends the source (the decision core
//!    holds every artifact).
//! 2. **Releases.** Every release of the listing, oldest first, so the
//!    trust floor rises as releases did. The inventory picks the assets
//!    for the target from their names alone.
//! 3. **Bytes.** Each candidate is fetched into the CAS and inspected by
//!    the isolated inspector. A recorded asset that now has other bytes is
//!    a replaced asset (`E_ASSET_MUTATED`).
//! 4. **Evidence and level.** Strict or Attested evidence of the exact
//!    bytes, and the level decision against the trust floor.
//! 5. **Family.** The first synchronization proposes every name it saw;
//!    later, a name outside the family is recorded as seen and held.
//! 6. **Decision.** System namespace, compatibility, and the decision core;
//!    every decision goes to the append-only log.
//! 7. **Publication.** For each level, the newest admissible artifacts of
//!    the activated names become a signed generation of that level's
//!    logical repository. Nothing is published for a source that is only
//!    observed or has no activated name.
//!
//! The APT configuration is a separate step over every source
//! ([`desired_apt`], [`apply_and_record`]), because one configuration
//! serves them all. Network, inspection, evidence, publication, and the
//! root applier are behind traits, so the whole pass is tested with
//! substitutes; the production ones are [`evidence::GitHubEvidence`],
//! [`publish::AptPublisher`], `inspect::SocketInspector`, and
//! `apt::operation::SocketApplier`.
//!
//! An error talking to GitHub, the inspector, or the publisher stops the
//! pass with [`SyncError`]; what was published before stays published.

pub mod evidence;
pub mod publish;
#[cfg(target_os = "linux")]
pub mod runner;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tokio::runtime::Handle;

pub use publish::{AptPublisher, apply_and_record, desired_apt};

use crate::attest::AttestedSigner;
use crate::cas::{ExpectedObject, Sha256Digest};
use crate::compat::{SystemPackages, Target, assess};
use crate::error::ReasonCode;
use crate::family::{
    Candidate, CompositionReview, Family, FamilyDecision, FamilyState, MemberKey, PackageMetadata,
    admit_family,
};
use crate::github::{
    AssetId, AssetLocator, GitHubClient, IdentityOutcome, PinnedRepository, Release, Transport,
};
use crate::inspect::DebInspection;
use crate::inventory::{
    Admission, InspectedAsset, InventoryPolicy, NativePackage, admit_release, inventory_release,
};
use crate::namespace::{self, Claims, SystemNamespace};
use crate::policy::assemble::{ArtifactInputs, NamespaceInput, SourceInputs, facts};
use crate::policy::level::{Level, LevelDecision, SourceLevel, Verified, decide_level};
use crate::policy::{Decision, Facts, Outcome, SourceMode, decide};
use crate::publish::apt::AptPackage;
use crate::state::{
    ArtifactRow, ArtifactState, DecisionObject, EvidenceRow, ReleaseRow, StateError, StateOwner,
};

/// Fetches an asset into the CAS and returns the object stored: by its
/// API digest when the release states one, otherwise by the digest of
/// the bytes received (R-005).
pub trait AssetFetch {
    fn fetch(
        &self,
        locator: AssetLocator,
        size: u64,
        api_digest: Option<Sha256Digest>,
    ) -> Result<ExpectedObject, String>;
}

/// Why the inspector gave no inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectFailure {
    /// The package bytes are refused: the artifact is malformed.
    Refused(String),
    /// The inspector could not be asked; the pass stops.
    Unavailable(String),
}

/// Inspects a DEB already in the CAS, in the isolated inspector.
pub trait PackageInspect {
    fn inspect_deb(&self, object: ExpectedObject) -> Result<DebInspection, InspectFailure>;
}

#[cfg(target_os = "linux")]
impl PackageInspect for crate::inspect::SocketInspector {
    fn inspect_deb(&self, object: ExpectedObject) -> Result<DebInspection, InspectFailure> {
        use crate::inspect::RemoteInspectError;
        Self::inspect_deb(self, object).map_err(|error| match error {
            RemoteInspectError::Unavailable(detail) => InspectFailure::Unavailable(detail),
            other => InspectFailure::Refused(other.to_string()),
        })
    }
}

/// Verified evidence ready to be recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecord {
    pub level: Level,
    pub signer_identity: String,
    pub predicate_type: &'static str,
    pub bundle_sha256: Sha256Digest,
    pub record_json: String,
}

/// What the evidence check found for one asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checked {
    pub verified: Verified,
    pub record: Option<EvidenceRecord>,
    /// Why, for the report.
    pub note: String,
}

impl Checked {
    pub fn nothing(note: &str) -> Self {
        Self {
            verified: Verified::Nothing,
            record: None,
            note: note.to_owned(),
        }
    }
}

/// Checks the provenance evidence of exact bytes. `Err` is a failure to
/// ask (GitHub unreachable), never a verdict about the bytes.
pub trait EvidenceCheck {
    fn check(
        &self,
        pinned: &PinnedRepository,
        release: &Release,
        asset_name: &str,
        sha256: Sha256Digest,
        signer: Option<&AttestedSigner>,
    ) -> Result<Checked, String>;
}

/// Publishes one generation of one level's logical repository.
pub trait LevelPublisher {
    fn publish(
        &mut self,
        source_key: &str,
        level: Level,
        packages: &[AptPackage],
    ) -> Result<u64, (ReasonCode, String)>;
}

/// The system as the namespace collector found it.
#[derive(Clone, Debug)]
pub enum SystemView {
    Known {
        namespace: SystemNamespace,
        packages: SystemPackages,
    },
    /// The collector's reason (`CollectError::reason_code`).
    Unknown(ReasonCode),
}

/// What a pass needs besides the state.
pub struct Sync<'a, T> {
    pub github: &'a GitHubClient<T>,
    pub runtime: Handle,
    pub fetch: &'a dyn AssetFetch,
    pub inspect: &'a dyn PackageInspect,
    pub evidence: &'a dyn EvidenceCheck,
    pub target: &'a Target,
    pub system: &'a SystemView,
    pub policy: InventoryPolicy,
}

/// Why a pass stopped. Nothing published before is withdrawn.
#[derive(Debug)]
pub enum SyncError {
    UnknownSource(String),
    GitHub(String),
    Fetch {
        asset: u64,
        detail: String,
    },
    Inspector(String),
    Evidence(String),
    /// A defect of the pass itself, not of the release.
    Inventory(String),
    /// The target or the publication store could not be read.
    Platform(String),
    Publish {
        level: Level,
        reason: ReasonCode,
        detail: String,
    },
    State(StateError),
}

impl SyncError {
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::GitHub(_) | Self::Fetch { .. } | Self::Evidence(_) => {
                Some(ReasonCode::EForgeUnavailable)
            }
            Self::Publish { reason, .. } => Some(*reason),
            Self::Platform(_) => Some(ReasonCode::EPlatformUnsupported),
            Self::UnknownSource(_) | Self::Inspector(_) | Self::Inventory(_) | Self::State(_) => {
                None
            }
        }
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSource(id) => write!(formatter, "no source {id}"),
            Self::GitHub(detail) => write!(formatter, "GitHub: {detail}"),
            Self::Fetch { asset, detail } => write!(formatter, "asset {asset}: {detail}"),
            Self::Inspector(detail) => write!(formatter, "inspector: {detail}"),
            Self::Evidence(detail) => write!(formatter, "evidence: {detail}"),
            Self::Inventory(detail) => write!(formatter, "inventory: {detail}"),
            Self::Platform(detail) => write!(formatter, "platform: {detail}"),
            Self::Publish {
                level,
                reason,
                detail,
            } => write!(
                formatter,
                "publishing the {} repository: {} ({detail})",
                level.as_str(),
                reason.as_str()
            ),
            Self::State(error) => write!(formatter, "state: {error}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<StateError> for SyncError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

/// What happened to one asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactReport {
    pub tag: String,
    pub filename: String,
    /// `name version arch`, when the package was inspected.
    pub package: Option<String>,
    pub outcome: ArtifactOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactOutcome {
    Published(Level),
    /// Admissible, but not published (superseded, or the name is not
    /// activated).
    Admissible,
    Held(ReasonCode, String),
    Rejected(ReasonCode, String),
}

/// What a pass did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncReport {
    pub source_id: String,
    pub identity_note: Option<String>,
    pub releases: usize,
    /// The listing hit its page limit; older releases were not seen.
    pub truncated: bool,
    pub artifacts: Vec<ArtifactReport>,
    pub generations: Vec<(Level, u64)>,
    pub family_revision: u32,
    pub family_approved: bool,
    /// Names and architectures outside the family, for an activation.
    pub review: Option<CompositionReview>,
}

impl SyncReport {
    /// Reason codes of every held or rejected artifact, once each.
    pub fn reason_codes(&self) -> Vec<ReasonCode> {
        let mut seen = BTreeSet::new();
        self.artifacts
            .iter()
            .filter_map(|artifact| match &artifact.outcome {
                ArtifactOutcome::Held(code, _) | ArtifactOutcome::Rejected(code, _) => Some(*code),
                ArtifactOutcome::Published(_) | ArtifactOutcome::Admissible => None,
            })
            .filter(|code| seen.insert(code.as_str()))
            .collect()
    }
}

/// One downloaded and inspected asset of the pass.
struct Seen {
    release: usize,
    asset_id: AssetId,
    filename: String,
    object: ExpectedObject,
    inspection: Result<DebInspection, String>,
    admission: Admission,
    asset_mutated: bool,
    checked: Option<Checked>,
    level: Option<LevelDecision>,
}

impl Seen {
    fn package(&self) -> Option<String> {
        self.inspection.as_ref().ok().map(|inspection| {
            let control = inspection.control();
            format!(
                "{} {} {}",
                control.package(),
                control.version(),
                control.architecture()
            )
        })
    }

    fn key(&self) -> Option<MemberKey> {
        self.inspection.as_ref().ok().map(|inspection| {
            MemberKey::new(
                crate::inventory::Ecosystem::Deb,
                inspection.control().package(),
            )
        })
    }
}

const fn channel_column(verdict: crate::inventory::ChannelVerdict) -> &'static str {
    match verdict {
        crate::inventory::ChannelVerdict::Stable => "stable",
        crate::inventory::ChannelVerdict::Prerelease => "prerelease",
        crate::inventory::ChannelVerdict::Unclear(_) => "unclear",
    }
}

/// One synchronization of `source_id` at `at`, publishing through
/// `publisher` when the source has activated names.
pub fn synchronize<T: Transport>(
    sync: &Sync<'_, T>,
    owner: &mut StateOwner,
    publisher: &mut dyn LevelPublisher,
    source_id: &str,
    at: &str,
) -> Result<SyncReport, SyncError> {
    let pinned = owner
        .pinned_repository(source_id)?
        .ok_or_else(|| SyncError::UnknownSource(source_id.to_owned()))?;
    let row = owner
        .sources()?
        .into_iter()
        .find(|row| row.id == source_id)
        .ok_or_else(|| SyncError::UnknownSource(source_id.to_owned()))?;
    let observing = row.state == "observing";
    let identity = sync
        .runtime
        .block_on(sync.github.reconcile(&pinned))
        .map_err(|error| SyncError::GitHub(error.to_string()))?;
    if identity.is_accepted() {
        owner.record_verified(source_id, at)?;
    }
    let listing = sync
        .runtime
        .block_on(sync.github.list_releases(&pinned))
        .map_err(|error| SyncError::GitHub(error.to_string()))?;
    let mut report = SyncReport {
        source_id: source_id.to_owned(),
        identity_note: match &identity {
            IdentityOutcome::Unchanged => None,
            other => Some(format!("{other:?}")),
        },
        releases: listing.releases.len(),
        truncated: listing.truncated,
        ..SyncReport::default()
    };
    let signer = owner.attested_signer(source_id)?;
    let recorded = owner.recorded_asset_digests(source_id)?;
    let mut level_state = SourceLevel {
        floor: row.trust_floor.as_deref().and_then(Level::from_column),
        pinned_consent: row.pinned_consent,
    };
    // Oldest first: the floor rises as the releases did.
    let releases: Vec<Release> = listing.releases.into_iter().rev().collect();
    let mut seen: Vec<Seen> = Vec::new();
    let mut release_rows: BTreeMap<usize, String> = BTreeMap::new();
    for (index, release) in releases.iter().enumerate() {
        let inventory = inventory_release(release, &sync.target.platform, &sync.policy);
        let mut inspected = Vec::new();
        let mut first = seen.len();
        for entry in inventory.candidates() {
            let locator = AssetLocator {
                repository: pinned.repository_id(),
                asset: entry.asset_id,
            };
            let object = sync
                .fetch
                .fetch(locator, entry.size, entry.api_digest)
                .map_err(|detail| SyncError::Fetch {
                    asset: entry.asset_id.get(),
                    detail,
                })?;
            let inspection = match sync.inspect.inspect_deb(object) {
                Ok(inspection) => Ok(inspection),
                Err(InspectFailure::Refused(detail)) => Err(detail),
                Err(InspectFailure::Unavailable(detail)) => {
                    return Err(SyncError::Inspector(detail));
                }
            };
            if let Ok(inspection) = &inspection {
                inspected.push(InspectedAsset {
                    asset_id: entry.asset_id,
                    sha256: object.sha256,
                    package: NativePackage::from_deb(inspection),
                });
            }
            let asset_mutated = recorded
                .get(&entry.asset_id.get())
                .is_some_and(|digests| !digests.contains(&object.sha256));
            seen.push(Seen {
                release: index,
                asset_id: entry.asset_id,
                filename: entry.name.clone(),
                object,
                inspection,
                admission: Admission::Eligible,
                asset_mutated,
                checked: None,
                level: None,
            });
        }
        if seen.len() == first {
            continue;
        }
        let admissions = admit_release(&inventory, &inspected, &sync.target.platform, &sync.policy)
            .map_err(|error| SyncError::Inventory(error.to_string()))?;
        let release_row = owner.record_release(
            source_id,
            &ReleaseRow {
                forge_release_id: release.id.get(),
                tag: &release.tag,
                commit: None,
                published_at: release.published_at.as_deref().unwrap_or(at),
                channel: channel_column(inventory.channel),
                immutable: release.immutable == Some(true),
            },
        )?;
        let approved = owner.approved_digests(source_id, &release_row)?;
        release_rows.insert(index, release_row);
        while first < seen.len() {
            let item = &mut seen[first];
            first += 1;
            if item.inspection.is_err() {
                continue;
            }
            item.admission = admissions
                .iter()
                .find(|(asset, _)| *asset == item.asset_id)
                .map_or(Admission::Eligible, |(_, admission)| admission.clone());
            if item.asset_mutated || item.admission != Admission::Eligible {
                continue;
            }
            let checked = sync
                .evidence
                .check(
                    &pinned,
                    release,
                    &item.filename,
                    item.object.sha256,
                    signer.as_ref(),
                )
                .map_err(SyncError::Evidence)?;
            let level = decide_level(
                &level_state,
                checked.verified,
                &item.object.sha256.to_hex(),
                &approved,
            );
            level_state.floor = level.floor;
            item.checked = Some(checked);
            item.level = Some(level);
        }
    }

    // The family: proposed from everything seen the first time; later a
    // name outside it is recorded as seen and held.
    let mut names: BTreeMap<MemberKey, BTreeSet<String>> = BTreeMap::new();
    for item in &seen {
        if let (Some(key), Ok(inspection)) = (item.key(), &item.inspection) {
            names
                .entry(key)
                .or_default()
                .insert(inspection.control().architecture().to_owned());
        }
    }
    let family = match owner.family(source_id)? {
        Some((_, family)) if family.state() == FamilyState::Approved => {
            for key in names.keys() {
                if family.arches(key).is_none() {
                    owner.record_seen_name(source_id, key)?;
                }
            }
            Some(family)
        }
        current if !names.is_empty() => {
            // Still proposed: every name seen so far, at the same revision.
            let mut members = names.clone();
            if let Some((_, proposed)) = &current {
                for (key, arches) in proposed.members() {
                    members
                        .entry(key.clone())
                        .or_default()
                        .extend(arches.iter().cloned());
                }
            }
            let revision = current.as_ref().map_or(1, |(_, family)| family.revision());
            let proposed =
                Family::restore(revision, FamilyState::Proposed, members).map_err(|_| {
                    StateError::CorruptRow {
                        table: "package_family",
                        problem: "empty family",
                    }
                })?;
            owner.save_family(source_id, &proposed)?;
            Some(proposed)
        }
        current => current.map(|(_, family)| family),
    };
    let Some(family) = family else {
        // Nothing for this target was ever seen.
        report_unrecorded(&seen, &releases, &mut report);
        return Ok(report);
    };
    report.family_revision = family.revision();
    report.family_approved = family.state() == FamilyState::Approved;
    let family_id = format!("{source_id}-family");

    // The decision for every inspected, eligible artifact.
    let empty_namespace = SystemNamespace::new();
    let empty_packages = SystemPackages::new(sync.target.platform.ecosystem());
    let (system_namespace, system_packages) = match sync.system {
        SystemView::Known {
            namespace,
            packages,
        } => (namespace, packages),
        SystemView::Unknown(_) => (&empty_namespace, &empty_packages),
    };
    let mut candidates = Vec::new();
    let mut metadata: BTreeMap<usize, PackageMetadata> = BTreeMap::new();
    let mut malformed: BTreeMap<usize, String> = BTreeMap::new();
    for (index, item) in seen.iter().enumerate() {
        let (Ok(inspection), Some(level)) = (&item.inspection, &item.level) else {
            continue;
        };
        let package = match PackageMetadata::from_deb(inspection) {
            Ok(package) => package,
            Err(error) => {
                malformed.insert(index, error.to_string());
                continue;
            }
        };
        let held = if level.served_at.is_none() {
            Some(ReasonCode::EEvidenceDowngrade)
        } else {
            None
        };
        candidates.push(Candidate {
            key: index,
            sha256: item.object.sha256,
            package: package.clone(),
            held,
        });
        metadata.insert(index, package);
    }
    let admission = admit_family(&family, &candidates, system_namespace);
    report.review = admission.review.clone();
    let modes = owner.name_modes(source_id)?;
    let family_offers: BTreeSet<String> = seen
        .iter()
        .filter_map(|item| item.inspection.as_ref().ok())
        .filter(|inspection| {
            family
                .arches(&MemberKey::new(
                    crate::inventory::Ecosystem::Deb,
                    inspection.control().package(),
                ))
                .is_some()
        })
        .flat_map(|inspection| {
            let claims = Claims::from_deb(inspection);
            std::iter::once(claims.name.clone()).chain(claims.provides)
        })
        .collect();

    let mut to_publish: BTreeMap<Level, Vec<usize>> = BTreeMap::new();
    let mut decided: BTreeMap<usize, (Facts, Decision)> = BTreeMap::new();
    for (index, package) in &metadata {
        let item = &seen[*index];
        let (Ok(inspection), Some(level)) = (&item.inspection, &item.level) else {
            continue;
        };
        let family_decision = admission
            .decision(index)
            .cloned()
            .unwrap_or(FamilyDecision::Held {
                reason: ReasonCode::EFamilyUnapproved,
                detail: crate::family::HoldDetail::NewName,
            });
        let key = MemberKey::new(package.ecosystem(), package.name());
        let requested_mode = if observing {
            SourceMode::Observing
        } else {
            modes.get(&key).copied().unwrap_or(SourceMode::Observing)
        };
        let check = match sync.system {
            SystemView::Known { namespace, .. } => {
                Some(namespace::check(namespace, &Claims::from_deb(inspection)))
            }
            SystemView::Unknown(_) => None,
        };
        let namespace_input = match (&check, sync.system) {
            (Some(check), _) => NamespaceInput::Checked(check),
            (None, SystemView::Unknown(code)) => NamespaceInput::Unavailable(*code),
            (None, SystemView::Known { .. }) => {
                NamespaceInput::Unavailable(ReasonCode::ESystemNamespaceUnknown)
            }
        };
        let compat = assess(sync.target, package, &family_offers, system_packages, false);
        let activated_earlier =
            owner.activated_earlier(source_id, package.ecosystem(), package.name())?;
        let sha256 = item.object.sha256.to_hex();
        let source_inputs = SourceInputs {
            source_id,
            requested_mode,
            identity: &identity,
            pinned_consent: row.pinned_consent,
            native_selection_proven: false,
            execution_policy: sync.target.execution_policy,
        };
        let artifact_inputs = ArtifactInputs {
            name: package.name(),
            version: package.version(),
            sha256: &sha256,
            level,
            asset_mutated: false,
            inspection_refused: false,
            channel: crate::inventory::ChannelVerdict::Stable,
            namespace: namespace_input,
            family: &family_decision,
            compat: &compat,
            ambiguous_with_other_source: false,
            provided_elsewhere: system_packages.knows(package.name()),
            activated_earlier,
            migration_confirmed: false,
        };
        let facts = facts(&source_inputs, &artifact_inputs);
        let decision = decide(&facts);
        if decision.published
            && family_decision == FamilyDecision::Publish
            && let Some(served) = level.served_at
        {
            to_publish.entry(served).or_default().push(*index);
        }
        // Logged with the artifact's own id once it is recorded below.
        decided.insert(*index, (facts, decision));
    }

    // Publication, level by level, only for activated names.
    let mut published_levels: BTreeMap<usize, Level> = BTreeMap::new();
    let source_key = source_id;
    for (level, indexes) in &to_publish {
        let packages: Vec<AptPackage> = indexes
            .iter()
            .filter_map(|index| {
                let item = &seen[*index];
                item.inspection.as_ref().ok().map(|inspection| AptPackage {
                    control: inspection.control().clone(),
                    object: item.object,
                })
            })
            .collect();
        let generation =
            publisher
                .publish(source_key, *level, &packages)
                .map_err(|(reason, detail)| SyncError::Publish {
                    level: *level,
                    reason,
                    detail,
                })?;
        report.generations.push((*level, generation));
        for index in indexes {
            published_levels.insert(*index, *level);
        }
    }
    // The floor only rises with verified evidence (`decide_level`); the
    // schema refuses a lower one.
    if let Some(floor) = level_state.floor {
        owner.raise_trust_floor(source_id, floor)?;
    }

    // Record every artifact with a name, and log its decision.
    for (index, item) in seen.iter().enumerate() {
        let release = &releases[item.release];
        let package = item.package();
        let mut outcome = None;
        if let (Ok(inspection), Some(release_row)) =
            (&item.inspection, release_rows.get(&item.release))
        {
            let control = inspection.control();
            let evidence_id = match item.checked.as_ref().and_then(|c| c.record.as_ref()) {
                Some(record) => Some(owner.record_evidence(
                    source_id,
                    &EvidenceRow {
                        level: record.level,
                        repository_id: pinned.repository_id().get(),
                        subject: item.object.sha256,
                        signer_identity: &record.signer_identity,
                        predicate_type: record.predicate_type,
                        bundle_sha256: record.bundle_sha256,
                        record_json: &record.record_json,
                        verifier_version: crate::attest::VERIFIER_VERSION,
                    },
                    at,
                )?),
                None => None,
            };
            let (state, artifact_outcome) = artifact_outcome(
                item,
                decided.get(&index).map(|(_, decision)| decision),
                malformed.get(&index),
                published_levels.get(&index),
            );
            let state = if evidence_id.is_none()
                && matches!(
                    state,
                    ArtifactState::Published | ArtifactState::Eligible | ArtifactState::Verified
                ) {
                ArtifactState::Held
            } else {
                state
            };
            let artifact_id = owner.record_artifact(
                source_id,
                &ArtifactRow {
                    release_row,
                    asset_id: item.asset_id.get(),
                    family_id: &family_id,
                    ecosystem: crate::inventory::Ecosystem::Deb,
                    name: control.package(),
                    version: control.version(),
                    architecture: control.architecture(),
                    filename: &item.filename,
                    sha256: item.object.sha256,
                    size: item.object.size,
                },
                evidence_id.as_deref(),
                state,
            )?;
            if let Some((facts, decision)) = decided.get(&index) {
                owner.record_decision(
                    DecisionObject::Artifact,
                    &artifact_id,
                    facts,
                    decision,
                    at,
                )?;
            }
            outcome = Some(artifact_outcome);
        }
        report.artifacts.push(ArtifactReport {
            tag: release.tag.clone(),
            filename: item.filename.clone(),
            package,
            outcome: outcome.unwrap_or_else(|| unrecorded_outcome(item)),
        });
    }
    Ok(report)
}

/// The state an artifact is recorded in, and what the report says.
fn artifact_outcome(
    item: &Seen,
    decided: Option<&Decision>,
    malformed: Option<&String>,
    published: Option<&Level>,
) -> (ArtifactState, ArtifactOutcome) {
    if let Some(detail) = malformed {
        return (
            ArtifactState::Rejected,
            ArtifactOutcome::Rejected(ReasonCode::EArtifactMalformed, detail.clone()),
        );
    }
    if item.asset_mutated {
        return (
            ArtifactState::Rejected,
            ArtifactOutcome::Rejected(
                ReasonCode::EAssetMutated,
                "the asset now has other bytes than recorded".to_owned(),
            ),
        );
    }
    match &item.admission {
        Admission::Held(code) => {
            return (
                ArtifactState::Held,
                ArtifactOutcome::Held(*code, "held by the release inventory".to_owned()),
            );
        }
        Admission::Rejected(code) => {
            return (
                ArtifactState::Rejected,
                ArtifactOutcome::Rejected(*code, "rejected by the release inventory".to_owned()),
            );
        }
        Admission::Duplicate { of } => {
            return (
                ArtifactState::Held,
                ArtifactOutcome::Held(
                    ReasonCode::ESourceAmbiguous,
                    format!("the same bytes as asset {of}"),
                ),
            );
        }
        Admission::Eligible => {}
    }
    if let Some(level) = published {
        return (ArtifactState::Published, ArtifactOutcome::Published(*level));
    }
    match decided {
        Some(decision) => match (decision.outcome, decision.reason) {
            (Outcome::Allow, _) => (ArtifactState::Eligible, ArtifactOutcome::Admissible),
            (Outcome::Deny, Some(code)) => (
                ArtifactState::Rejected,
                ArtifactOutcome::Rejected(code, decision.text.clone()),
            ),
            (_, Some(code)) => (
                ArtifactState::Held,
                ArtifactOutcome::Held(code, decision.text.clone()),
            ),
            (_, None) => (
                ArtifactState::Held,
                ArtifactOutcome::Held(ReasonCode::EEvidenceDowngrade, decision.text.clone()),
            ),
        },
        None => (
            ArtifactState::Held,
            ArtifactOutcome::Held(
                ReasonCode::EEvidenceDowngrade,
                item.checked
                    .as_ref()
                    .map_or_else(|| "not verified".to_owned(), |c| c.note.clone()),
            ),
        ),
    }
}

fn unrecorded_outcome(item: &Seen) -> ArtifactOutcome {
    match &item.inspection {
        Err(detail) => ArtifactOutcome::Rejected(ReasonCode::EArtifactMalformed, detail.clone()),
        Ok(_) => ArtifactOutcome::Held(
            ReasonCode::EFamilyUnapproved,
            "not recorded: no family yet".to_owned(),
        ),
    }
}

fn report_unrecorded(seen: &[Seen], releases: &[Release], report: &mut SyncReport) {
    for item in seen {
        report.artifacts.push(ArtifactReport {
            tag: releases[item.release].tag.clone(),
            filename: item.filename.clone(),
            package: item.package(),
            outcome: unrecorded_outcome(item),
        });
    }
}

#[cfg(test)]
mod tests;
