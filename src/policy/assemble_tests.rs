// SPDX-License-Identifier: MIT OR Apache-2.0

//! Each test feeds a module's own result through the assembly and the
//! decision, and checks what the user would see: a mapping that drops or
//! softens a module's finding admits what that module refused.

use super::*;
use crate::compat::{BuildClaim, CompatHold, Confidence};
use crate::family::HoldDetail;
use crate::github::{OwnerId, OwnerLogin, RepositoryId, RepositoryIdentity, RepositoryName};
use crate::inventory::PrereleaseMarker;
use crate::policy::level::LevelDecision;
use crate::policy::{Decision, Evidence, Outcome, Rule, decide};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn admitted_level() -> LevelDecision {
    LevelDecision {
        evidence: Evidence::Attested,
        served_at: Some(crate::policy::level::Level::Attested),
        floor: Some(crate::policy::level::Level::Attested),
    }
}

fn compatible() -> Assessment {
    Assessment {
        format_arch_ok: true,
        build: BuildClaim::Generic,
        dependencies: None,
        declared_dependency_satisfiable: true,
        platform_claimed: false,
        platform_tested: false,
        confidence: Confidence::DependenciesSatisfiable,
        hold: None,
    }
}

fn free_name() -> namespace::Check {
    namespace::Check {
        conflicts: Vec::new(),
        own_name: namespace::OwnName::Free,
    }
}

struct World {
    identity: IdentityOutcome,
    execution_policy: ExecutionPolicy,
    level: LevelDecision,
    channel: ChannelVerdict,
    check: namespace::Check,
    unavailable: Option<ReasonCode>,
    family: FamilyDecision<u32>,
    compat: Assessment,
}

impl World {
    /// An Attested artifact of a source in `supplemental` mode that every
    /// module admits.
    fn admitted() -> Self {
        Self {
            identity: IdentityOutcome::Unchanged,
            execution_policy: ExecutionPolicy::Off,
            level: admitted_level(),
            channel: ChannelVerdict::Stable,
            check: free_name(),
            unavailable: None,
            family: FamilyDecision::Publish,
            compat: compatible(),
        }
    }

    fn decide(&self) -> Decision {
        let source = SourceInputs {
            source_id: "source-1",
            requested_mode: SourceMode::Supplemental,
            identity: &self.identity,
            pinned_consent: false,
            native_selection_proven: false,
            execution_policy: self.execution_policy,
        };
        let artifact = ArtifactInputs {
            name: "sampleapp",
            version: "1.0-1",
            sha256: "a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9",
            level: &self.level,
            asset_mutated: false,
            inspection_refused: false,
            channel: self.channel,
            namespace: match self.unavailable {
                Some(code) => NamespaceInput::Unavailable(code),
                None => NamespaceInput::Checked(&self.check),
            },
            family: &self.family,
            compat: &self.compat,
            ambiguous_with_other_source: false,
            provided_elsewhere: false,
            activated_earlier: false,
            migration_confirmed: false,
        };
        decide(&facts(&source, &artifact))
    }
}

fn held(decision: &Decision, code: ReasonCode) {
    assert_eq!(decision.outcome, Outcome::Hold, "{decision:?}");
    assert_eq!(decision.reason, Some(code), "{decision:?}");
    assert!(!decision.published);
}

#[test]
fn an_artifact_every_module_admits_is_published() {
    let decision = World::admitted().decide();
    assert_eq!(decision.outcome, Outcome::Allow);
    assert!(decision.published, "{decision:?}");
}

#[test]
fn a_transferred_or_replaced_repository_suspends_the_source() -> TestResult {
    let identity = RepositoryIdentity::new(
        RepositoryId::new(1_429_109_739)?,
        OwnerId::new(99)?,
        OwnerLogin::new("someone-else")?,
        RepositoryName::new("pchi-test")?,
    );
    let mut world = World::admitted();
    world.identity = IdentityOutcome::Transferred {
        previous_owner_id: OwnerId::new(2_264_172)?,
        current: identity,
    };
    held(&world.decide(), ReasonCode::EOwnerTransfer);
    world.identity = IdentityOutcome::Replaced {
        expected: RepositoryId::new(1_429_109_739)?,
        observed: RepositoryId::new(7)?,
    };
    held(&world.decide(), ReasonCode::ERepoIdChanged);
    Ok(())
}

#[test]
fn an_execution_policy_that_is_on_or_unknown_stops_publication() {
    for policy in [ExecutionPolicy::On, ExecutionPolicy::Unknown] {
        let mut world = World::admitted();
        world.execution_policy = policy;
        held(&world.decide(), ReasonCode::EExecutionPolicy);
    }
}

#[test]
fn the_evidence_comes_from_the_level_decision() {
    let mut world = World::admitted();
    world.level.evidence = Evidence::Downgrade;
    world.level.served_at = None;
    held(&world.decide(), ReasonCode::EEvidenceDowngrade);
    world.level.evidence = Evidence::Invalid;
    let decision = world.decide();
    assert_eq!(decision.outcome, Outcome::Deny);
    assert_eq!(decision.reason, Some(ReasonCode::EAttestationInvalid));
}

#[test]
fn a_pre_release_marker_on_a_stable_release_holds_it() {
    let mut world = World::admitted();
    world.channel = ChannelVerdict::Unclear(PrereleaseMarker::Preview);
    held(&world.decide(), ReasonCode::EChannelUnclear);
}

#[test]
fn every_namespace_finding_reaches_the_decision() {
    let mut world = World::admitted();
    world.check.conflicts.push(namespace::Conflict {
        relation: namespace::Relation::Replaces,
        name: "libc6".to_owned(),
    });
    held(&world.decide(), ReasonCode::ESystemPackageConflict);
    let mut world = World::admitted();
    world.check.own_name = namespace::OwnName::OsPart;
    held(&world.decide(), ReasonCode::ESystemPackageConflict);
    let mut world = World::admitted();
    world.check.own_name = namespace::OwnName::NeedsMigration;
    held(&world.decide(), ReasonCode::ENameProvidedElsewhere);
}

#[test]
fn a_namespace_that_cannot_be_collected_holds_with_the_collector_reason() {
    for error in [
        namespace::collect::CollectError::Unsupported,
        namespace::collect::CollectError::NoDistributionSource,
    ] {
        let mut world = World::admitted();
        world.unavailable = Some(error.reason_code());
        let decision = world.decide();
        held(&decision, error.reason_code());
        assert_eq!(decision.rule, Rule::Composition);
    }
}

#[test]
fn only_a_family_hold_holds_superseded_and_duplicates_do_not() {
    let mut world = World::admitted();
    world.family = FamilyDecision::Held {
        reason: ReasonCode::EFamilyUnapproved,
        detail: HoldDetail::EarlierCheck,
    };
    held(&world.decide(), ReasonCode::EFamilyUnapproved);
    for family in [
        FamilyDecision::Superseded,
        FamilyDecision::Duplicate { of: 1 },
    ] {
        let mut world = World::admitted();
        world.family = family;
        assert_eq!(world.decide().outcome, Outcome::Allow);
    }
}

#[test]
fn a_compatibility_hold_reaches_the_decision() {
    let mut world = World::admitted();
    world.compat.hold = Some(CompatHold::Dependency {
        clause: "libfoo (>= 3)".to_owned(),
    });
    held(&world.decide(), ReasonCode::EDependencyUnsatisfiable);
}
