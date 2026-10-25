// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building the decision's facts from what the other modules found
//! (P2-009b). Every conversion from a module's own result into a fact
//! lives here, once, so the admission decision never reads a module type
//! and a module never guesses how the decision reads it.
//!
//! - identity: `github::IdentityOutcome`;
//! - evidence: `policy::level::LevelDecision` (the ratchet and Pinned);
//! - channel: `inventory::ChannelVerdict`;
//! - system namespace: `namespace::Check`, or the collector's reason when it
//!   could not be computed (`namespace::collect::CollectError`);
//! - family: `family::FamilyDecision`;
//! - compatibility and the execution policy: `compat`.

use super::level::LevelDecision;
use super::{
    ArtifactFacts, Facts, Identity, Namespace, NamespaceFacts, OwnName, SourceFacts, SourceMode,
};
use crate::compat::{Assessment, ExecutionPolicy};
use crate::error::ReasonCode;
use crate::family::FamilyDecision;
use crate::github::IdentityOutcome;
use crate::inventory::ChannelVerdict;
use crate::namespace;

/// The source as the modules found it.
#[derive(Clone, Debug)]
pub struct SourceInputs<'a> {
    pub source_id: &'a str,
    pub requested_mode: SourceMode,
    pub identity: &'a IdentityOutcome,
    /// `forge_repository.pinned_consent_at` is set (ADR-027).
    pub pinned_consent: bool,
    /// The adapter proved that the native manager selects this source.
    pub native_selection_proven: bool,
    pub execution_policy: ExecutionPolicy,
}

/// What the system namespace step produced for one artifact.
#[derive(Clone, Copy, Debug)]
pub enum NamespaceInput<'a> {
    Checked(&'a namespace::Check),
    /// The namespace could not be computed; the collector's reason code
    /// (`CollectError::reason_code`).
    Unavailable(ReasonCode),
}

/// One artifact for one target, as the modules found it.
#[derive(Clone, Debug)]
pub struct ArtifactInputs<'a, K> {
    pub name: &'a str,
    pub version: &'a str,
    pub sha256: &'a str,
    pub level: &'a LevelDecision,
    /// The pinned asset now has other bytes (`github::release_pin`).
    pub asset_mutated: bool,
    /// The inspector refused the package bytes.
    pub inspection_refused: bool,
    pub channel: ChannelVerdict,
    pub namespace: NamespaceInput<'a>,
    pub family: &'a FamilyDecision<K>,
    pub compat: &'a Assessment,
    pub ambiguous_with_other_source: bool,
    pub provided_elsewhere: bool,
    pub activated_earlier: bool,
    pub migration_confirmed: bool,
}

pub fn identity(outcome: &IdentityOutcome) -> Identity {
    match outcome {
        IdentityOutcome::Unchanged => Identity::Unchanged,
        IdentityOutcome::Renamed { .. } => Identity::Renamed,
        IdentityOutcome::Transferred { .. } => Identity::OwnerTransfer,
        IdentityOutcome::Replaced { .. } => Identity::Replaced,
    }
}

pub fn own_name(own: namespace::OwnName) -> OwnName {
    match own {
        namespace::OwnName::Free => OwnName::Free,
        namespace::OwnName::NeedsMigration => OwnName::NeedsMigration,
        namespace::OwnName::OsPart => OwnName::OsPart,
    }
}

pub fn namespace_facts(input: NamespaceInput<'_>) -> Namespace {
    match input {
        NamespaceInput::Checked(check) => Namespace::Known(NamespaceFacts {
            relation_conflict: !check.conflicts.is_empty(),
            own_name: own_name(check.own_name),
        }),
        NamespaceInput::Unavailable(code) => Namespace::Unknown(code),
    }
}

/// A release is on the followed channel unless a marker contradicts the
/// provider's stable flag; pre-releases are excluded earlier, by the
/// inventory, when the channel does not follow them.
pub const fn channel_unclear(verdict: ChannelVerdict) -> bool {
    matches!(verdict, ChannelVerdict::Unclear(_))
}

pub fn source_facts(inputs: &SourceInputs<'_>) -> SourceFacts {
    SourceFacts {
        source_id: inputs.source_id.to_owned(),
        requested_mode: inputs.requested_mode,
        identity: identity(inputs.identity),
        pinned: inputs.pinned_consent,
        native_selection_proven: inputs.native_selection_proven,
        execution_policy_off: matches!(inputs.execution_policy, ExecutionPolicy::Off),
    }
}

pub fn artifact_facts<K>(inputs: &ArtifactInputs<'_, K>) -> ArtifactFacts {
    ArtifactFacts {
        name: inputs.name.to_owned(),
        version: inputs.version.to_owned(),
        sha256: inputs.sha256.to_owned(),
        evidence: inputs.level.evidence,
        asset_mutated: inputs.asset_mutated,
        malformed: inputs.inspection_refused,
        channel_unclear: channel_unclear(inputs.channel),
        namespace: namespace_facts(inputs.namespace),
        family_hold: inputs.family.reason_code(),
        compat_hold: inputs.compat.reason_code(),
        ambiguous_with_other_source: inputs.ambiguous_with_other_source,
        provided_elsewhere: inputs.provided_elsewhere,
        activated_earlier: inputs.activated_earlier,
        migration_confirmed: inputs.migration_confirmed,
    }
}

pub fn facts<K>(source: &SourceInputs<'_>, artifact: &ArtifactInputs<'_, K>) -> Facts {
    Facts::new(source_facts(source), artifact_facts(artifact))
}

#[cfg(test)]
#[path = "assemble_tests.rs"]
mod tests;
