// SPDX-License-Identifier: MIT OR Apache-2.0

//! The admission decision (P2-009a, `architecture/policy-engine.md`).
//!
//! A pure function from versioned facts to `allow`, `hold`, or `deny`, with
//! the rule that decided, its version, a stable reason code, and a text.
//! The facts are what the other checks found: the source's identity
//! (`crate::github`), the provenance evidence (`crate::attest`), the
//! inspection (`crate::inspect`), the channel (`crate::inventory`), the
//! system namespace (`crate::namespace`), the family admission
//! (`crate::family`) and the operating system compatibility
//! (`crate::compat`). The rules run in the order of the decision priority;
//! the first that objects decides.
//!
//! The facts serialize to canonical JSON with a `schema_version`, and the
//! same facts always give the same decision and the same digest, so a
//! decision recorded in the append-only log can be replayed (P2-009b).
//! What a reason code does (reject, suspend, hold) is the behaviour column
//! of `specifications/errors.md`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cas::Sha256Digest;
use crate::error::ReasonCode;

/// The version of the facts format.
pub const FACTS_SCHEMA_VERSION: u32 = 1;

/// The outcome of one decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    /// Not admitted now; a later fact or a user decision can change it.
    Hold,
    /// These bytes are rejected for good.
    Deny,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Hold => "hold",
            Self::Deny => "deny",
        }
    }
}

/// What a reason code does to an artifact and to its source, from the
/// behaviour column of `specifications/errors.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Behaviour {
    /// Reject these bytes (`deny`).
    Reject,
    /// Suspend the source; its artifacts are held.
    SuspendSource,
    Hold,
}

/// The behaviour of a reason code in an admission decision.
pub const fn behaviour(code: ReasonCode) -> Behaviour {
    match code {
        ReasonCode::EAssetMutated
        | ReasonCode::EAttestationInvalid
        | ReasonCode::EArtifactMalformed => Behaviour::Reject,
        ReasonCode::ERepoIdChanged | ReasonCode::EOwnerTransfer => Behaviour::SuspendSource,
        _ => Behaviour::Hold,
    }
}

/// The rules in the order of the decision priority. The identifier and the
/// version are written into the decision log; a change of a rule's meaning
/// raises its version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Rule {
    Identity,
    Provenance,
    Composition,
    SuitableRelease,
    Conflicts,
    NativeFeasibility,
    Publication,
}

impl Rule {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Provenance => "provenance",
            Self::Composition => "composition",
            Self::SuitableRelease => "suitable_release",
            Self::Conflicts => "conflicts",
            Self::NativeFeasibility => "native_feasibility",
            Self::Publication => "publication",
        }
    }

    pub const fn version(self) -> u32 {
        1
    }
}

/// The base mode of a source (`architecture/policy-engine.md`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    Observing,
    Supplemental,
    Preferred,
    Suspended,
}

impl SourceMode {
    const fn publishes(self) -> bool {
        matches!(self, Self::Supplemental | Self::Preferred)
    }
}

/// What the reconciliation of the source's identity found.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Identity {
    Unchanged,
    /// Same repository and owner IDs, new name: allowed.
    Renamed,
    /// Same repository ID, an owner ID that was never confirmed.
    OwnerTransfer,
    /// Another repository ID behind the address.
    Replaced,
}

/// The provenance evidence of the artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    Strict,
    Attested,
    /// Pinned, and the user approved this release's exact digests.
    PinnedApproved,
    /// Pinned, waiting for the user's approval of the release.
    PinnedUnapproved,
    /// Weaker than the source's trust floor.
    Downgrade,
    /// Verification failed.
    Invalid,
}

/// What the own name of the package means on this system
/// (`namespace::OwnName`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnName {
    Free,
    /// A distribution application or a package installed from elsewhere.
    NeedsMigration,
    OsPart,
}

/// The facts about the source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFacts {
    pub source_id: String,
    pub requested_mode: SourceMode,
    pub identity: Identity,
    /// The source is admitted at the Pinned level (ADR-027).
    pub pinned: bool,
    /// The adapter showed that the native manager selects this source for
    /// the activated names (`preferred` needs it; P3-002, P3-004).
    pub native_selection_proven: bool,
    /// The operating system's execution policy is off
    /// (`compat::activation_allowed`).
    pub execution_policy_off: bool,
}

/// The facts about one artifact for one target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFacts {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub evidence: Evidence,
    /// The pinned asset changed (`github::release_pin`).
    pub asset_mutated: bool,
    /// The inspector rejected the bytes.
    pub malformed: bool,
    /// The release is not clearly on the followed channel.
    pub channel_unclear: bool,
    /// `None` when the system namespace could not be computed.
    pub namespace: Option<NamespaceFacts>,
    /// The reason the family admission held the artifact, if it did.
    pub family_hold: Option<ReasonCode>,
    /// The reason the compatibility check held the artifact, if it did.
    pub compat_hold: Option<ReasonCode>,
    /// The same version with other bytes is offered by another source.
    pub ambiguous_with_other_source: bool,
    /// The name is installed from, or available in, another enabled source
    /// (not the distribution's own; that is [`OwnName::NeedsMigration`]).
    pub provided_elsewhere: bool,
    /// This source activated the name before the distribution or another
    /// source offered it: it keeps its publisher (ADR-022 point 3).
    pub activated_earlier: bool,
    /// The user explicitly migrated this name to the source (ADR-012).
    pub migration_confirmed: bool,
}

/// What the system namespace check found (`namespace::Check`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceFacts {
    /// A `Provides`, `Replaces`, or `Obsoletes` names a member.
    pub relation_conflict: bool,
    pub own_name: OwnName,
}

/// Everything one decision is made from.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    pub schema_version: u32,
    pub source: SourceFacts,
    pub artifact: ArtifactFacts,
}

/// Why the facts cannot be decided.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactsError {
    UnsupportedVersion(u32),
    Malformed(String),
}

impl fmt::Display for FactsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported facts schema version {version}")
            }
            Self::Malformed(error) => write!(formatter, "malformed facts: {error}"),
        }
    }
}

impl std::error::Error for FactsError {}

impl Facts {
    pub const fn new(source: SourceFacts, artifact: ArtifactFacts) -> Self {
        Self {
            schema_version: FACTS_SCHEMA_VERSION,
            source,
            artifact,
        }
    }

    /// The canonical JSON written as the decision's evidence: fields in
    /// declaration order, no whitespace.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Reads facts back from the log; an unknown field or version is
    /// refused (ADR-019 point 2).
    pub fn from_json(text: &str) -> Result<Self, FactsError> {
        let facts: Self =
            serde_json::from_str(text).map_err(|error| FactsError::Malformed(error.to_string()))?;
        if facts.schema_version != FACTS_SCHEMA_VERSION {
            return Err(FactsError::UnsupportedVersion(facts.schema_version));
        }
        Ok(facts)
    }

    /// The digest of the canonical JSON.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::of(self.to_json().as_bytes())
    }
}

/// The mode a source effectively has, and why it differs from the
/// requested one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveMode {
    pub mode: SourceMode,
    pub rule: Rule,
    pub reason: Option<ReasonCode>,
    pub note: Option<&'static str>,
}

/// The effective mode of a source.
pub fn effective_mode(source: &SourceFacts) -> EffectiveMode {
    let keep = |mode| EffectiveMode {
        mode,
        rule: Rule::Publication,
        reason: None,
        note: None,
    };
    match source.identity {
        Identity::OwnerTransfer => {
            return EffectiveMode {
                mode: SourceMode::Suspended,
                rule: Rule::Identity,
                reason: Some(ReasonCode::EOwnerTransfer),
                note: Some("the repository owner changed; confirm the transfer"),
            };
        }
        Identity::Replaced => {
            return EffectiveMode {
                mode: SourceMode::Suspended,
                rule: Rule::Identity,
                reason: Some(ReasonCode::ERepoIdChanged),
                note: Some("the address now belongs to another repository"),
            };
        }
        Identity::Unchanged | Identity::Renamed => {}
    }
    if !source.execution_policy_off && source.requested_mode.publishes() {
        return EffectiveMode {
            mode: SourceMode::Observing,
            rule: Rule::SuitableRelease,
            reason: Some(ReasonCode::EExecutionPolicy),
            note: Some("activation refused while the execution policy is on or unknown"),
        };
    }
    match source.requested_mode {
        SourceMode::Preferred if source.pinned => EffectiveMode {
            mode: SourceMode::Observing,
            rule: Rule::NativeFeasibility,
            reason: None,
            note: Some("a Pinned source is supplemental only (ADR-027)"),
        },
        SourceMode::Preferred if !source.native_selection_proven => EffectiveMode {
            mode: SourceMode::Observing,
            rule: Rule::NativeFeasibility,
            reason: None,
            note: Some("preferred needs proof that the native manager selects this source"),
        },
        mode => keep(mode),
    }
}

/// The decision about one artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub outcome: Outcome,
    pub rule: Rule,
    pub reason: Option<ReasonCode>,
    pub text: String,
    /// Allowed and the source's effective mode publishes.
    pub published: bool,
    pub mode: SourceMode,
}

/// Decides one artifact.
pub fn decide(facts: &Facts) -> Decision {
    let mode = effective_mode(&facts.source);
    let objection = objection(facts, &mode);
    match objection {
        Some((rule, code, text)) => {
            let outcome = match behaviour(code) {
                Behaviour::Reject => Outcome::Deny,
                Behaviour::SuspendSource | Behaviour::Hold => Outcome::Hold,
            };
            Decision {
                outcome,
                rule,
                reason: Some(code),
                text,
                published: false,
                mode: mode.mode,
            }
        }
        None => Decision {
            outcome: Outcome::Allow,
            rule: Rule::Publication,
            reason: None,
            text: match mode.note {
                Some(note) if !mode.mode.publishes() => {
                    format!("admissible, not published: {note}")
                }
                _ if !mode.mode.publishes() => {
                    "admissible, not published: the source is observed".to_owned()
                }
                _ => "admissible and published".to_owned(),
            },
            published: mode.mode.publishes(),
            mode: mode.mode,
        },
    }
}

/// The first rule that objects, in the order of the decision priority.
fn objection(facts: &Facts, mode: &EffectiveMode) -> Option<(Rule, ReasonCode, String)> {
    let artifact = &facts.artifact;
    let object = |rule, code, text: &str| Some((rule, code, text.to_owned()));
    // 1. Identity.
    if let (Rule::Identity, Some(code)) = (mode.rule, mode.reason) {
        return object(
            Rule::Identity,
            code,
            mode.note.unwrap_or("the source identity changed"),
        );
    }
    // 2. Provenance: a contradiction rejects the bytes; weaker evidence holds.
    if artifact.asset_mutated {
        return object(
            Rule::Provenance,
            ReasonCode::EAssetMutated,
            "the pinned asset changed",
        );
    }
    if artifact.malformed {
        return object(
            Rule::Provenance,
            ReasonCode::EArtifactMalformed,
            "the package fails inspection",
        );
    }
    match artifact.evidence {
        Evidence::Invalid => {
            return object(
                Rule::Provenance,
                ReasonCode::EAttestationInvalid,
                "the provenance evidence failed verification",
            );
        }
        Evidence::Downgrade => {
            return object(
                Rule::Provenance,
                ReasonCode::EEvidenceDowngrade,
                "weaker evidence than the source's trust floor",
            );
        }
        Evidence::PinnedUnapproved => {
            return object(
                Rule::Provenance,
                ReasonCode::EReleaseApprovalRequired,
                "the Pinned release waits for approval",
            );
        }
        Evidence::PinnedApproved if !facts.source.pinned => {
            // An approval without Pinned consent is not evidence.
            return object(
                Rule::Provenance,
                ReasonCode::EEvidenceDowngrade,
                "a release approval without Pinned consent",
            );
        }
        Evidence::Strict | Evidence::Attested | Evidence::PinnedApproved => {}
    }
    // 3. Composition: the family and the system namespace.
    if let Some(code) = artifact.family_hold {
        return object(
            Rule::Composition,
            code,
            "the family admission holds the artifact",
        );
    }
    let Some(namespace) = &artifact.namespace else {
        return object(
            Rule::Composition,
            ReasonCode::ESystemNamespaceUnknown,
            "the system namespace is unknown",
        );
    };
    if namespace.relation_conflict {
        return object(
            Rule::Composition,
            ReasonCode::ESystemPackageConflict,
            "a relation names a system package",
        );
    }
    if namespace.own_name == OwnName::OsPart && !artifact.activated_earlier {
        return object(
            Rule::Composition,
            ReasonCode::ESystemPackageConflict,
            "the name is a part of the operating system",
        );
    }
    // 4. A suitable release: channel and compatibility.
    if artifact.channel_unclear {
        return object(
            Rule::SuitableRelease,
            ReasonCode::EChannelUnclear,
            "the release is not clearly on the followed channel",
        );
    }
    if let Some(code) = artifact.compat_hold {
        return object(
            Rule::SuitableRelease,
            code,
            "the compatibility check holds the artifact",
        );
    }
    if let (Rule::SuitableRelease, Some(code)) = (mode.rule, mode.reason) {
        return object(
            Rule::SuitableRelease,
            code,
            mode.note.unwrap_or("the release is not suitable"),
        );
    }
    // 5. Conflicts with what the system already gets elsewhere.
    if artifact.ambiguous_with_other_source {
        return object(
            Rule::Conflicts,
            ReasonCode::ESourceAmbiguous,
            "another source offers this version with other bytes",
        );
    }
    let taken = namespace.own_name == OwnName::NeedsMigration || artifact.provided_elsewhere;
    if taken && !artifact.activated_earlier {
        // Only an explicit migration of a Strict or Attested source in
        // `preferred` mode takes a name over (ADR-012, ADR-027 point 5).
        let migrated = artifact.migration_confirmed
            && !facts.source.pinned
            && facts.source.requested_mode == SourceMode::Preferred;
        if !migrated {
            return object(
                Rule::Conflicts,
                ReasonCode::ENameProvidedElsewhere,
                "another source or the distribution provides this name",
            );
        }
    }
    None
}

pub mod level;

#[cfg(test)]
mod tests;
