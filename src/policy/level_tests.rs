// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use super::*;
use crate::error::ReasonCode;
use crate::policy::{
    ArtifactFacts, Facts, Identity, Namespace, NamespaceFacts, OwnName, SourceFacts, SourceMode,
    decide,
};

const DIGEST: &str = "8fcda58d824b4fea8f98e036083f398f497941af4b8c15de5dac02dd900576fd";
const OTHER: &str = "a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9";

fn source(floor: Option<Level>, pinned_consent: bool) -> SourceLevel {
    SourceLevel {
        floor,
        pinned_consent,
    }
}

fn none() -> BTreeSet<String> {
    BTreeSet::new()
}

fn approved(digest: &str) -> BTreeSet<String> {
    [digest.to_owned()].into()
}

/// The admission decision of an artifact with this level decision.
fn admission(level: &LevelDecision, pinned_consent: bool) -> crate::policy::Decision {
    decide(&Facts::new(
        SourceFacts {
            source_id: "s1".to_owned(),
            requested_mode: SourceMode::Supplemental,
            identity: Identity::Unchanged,
            pinned: pinned_consent,
            native_selection_proven: false,
            execution_policy_off: true,
        },
        ArtifactFacts {
            name: "netwatch".to_owned(),
            version: "0.36.0".to_owned(),
            sha256: DIGEST.to_owned(),
            evidence: level.evidence,
            asset_mutated: false,
            malformed: false,
            channel_unclear: false,
            namespace: Namespace::Known(NamespaceFacts {
                relation_conflict: false,
                own_name: OwnName::Free,
            }),
            family_hold: None,
            compat_hold: None,
            ambiguous_with_other_source: false,
            provided_elsewhere: false,
            activated_earlier: false,
            migration_confirmed: false,
        },
    ))
}

#[test]
fn n038_a_release_weaker_than_the_floor_is_held_and_the_floor_stays() {
    // No attestation after attested releases.
    let attested = source(Some(Level::Attested), false);
    let decision = decide_level(&attested, Verified::Nothing, DIGEST, &none());
    assert_eq!(decision.evidence, Evidence::Downgrade);
    assert_eq!(
        decision.floor,
        Some(Level::Attested),
        "the floor never drops"
    );
    assert_eq!(decision.served_at, None);
    assert_eq!(
        admission(&decision, false).reason,
        Some(ReasonCode::EEvidenceDowngrade)
    );

    // Attested after Strict is a downgrade too.
    let strict = source(Some(Level::Strict), false);
    let decision = decide_level(&strict, Verified::Attested, DIGEST, &none());
    assert_eq!(decision.evidence, Evidence::Downgrade);
    assert_eq!(decision.floor, Some(Level::Strict));
}

#[test]
fn the_floor_rises_with_stronger_evidence_and_only_upwards() {
    let new = source(None, false);
    let first = decide_level(&new, Verified::Attested, DIGEST, &none());
    assert_eq!(
        (first.evidence, first.served_at, first.floor),
        (
            Evidence::Attested,
            Some(Level::Attested),
            Some(Level::Attested)
        )
    );
    assert!(first.floor_raised(None));

    let raised = decide_level(
        &source(Some(Level::Attested), false),
        Verified::Strict,
        DIGEST,
        &none(),
    );
    assert_eq!(raised.floor, Some(Level::Strict));
    assert!(raised.floor_raised(Some(Level::Attested)));

    let same = decide_level(
        &source(Some(Level::Strict), false),
        Verified::Strict,
        DIGEST,
        &none(),
    );
    assert_eq!(same.floor, Some(Level::Strict));
    assert!(!same.floor_raised(Some(Level::Strict)));

    // A Pinned source gains a verified release: the floor rises.
    let pinned = decide_level(
        &source(Some(Level::Pinned), true),
        Verified::Attested,
        DIGEST,
        &none(),
    );
    assert_eq!(pinned.floor, Some(Level::Attested));
}

#[test]
fn n039_a_pinned_release_waits_for_approval_of_its_exact_digest() {
    let pinned = source(Some(Level::Pinned), true);
    let waiting = decide_level(&pinned, Verified::Nothing, DIGEST, &none());
    assert_eq!(waiting.evidence, Evidence::PinnedUnapproved);
    assert_eq!(
        admission(&waiting, true).reason,
        Some(ReasonCode::EReleaseApprovalRequired)
    );

    // An approval of other bytes approves nothing.
    let other = decide_level(&pinned, Verified::Nothing, DIGEST, &approved(OTHER));
    assert_eq!(other.evidence, Evidence::PinnedUnapproved);

    let approved_release = decide_level(&pinned, Verified::Nothing, DIGEST, &approved(DIGEST));
    assert_eq!(approved_release.evidence, Evidence::PinnedApproved);
    assert_eq!(approved_release.served_at, Some(Level::Pinned));
    let admitted = admission(&approved_release, true);
    assert_eq!(admitted.reason, None);
    assert!(admitted.published);
}

#[test]
fn a_first_pinned_release_sets_the_floor_to_pinned() {
    let new = source(None, true);
    let decision = decide_level(&new, Verified::Nothing, DIGEST, &approved(DIGEST));
    assert_eq!(decision.floor, Some(Level::Pinned));
    let waiting = decide_level(&new, Verified::Nothing, DIGEST, &none());
    assert_eq!(waiting.floor, None, "nothing admitted, nothing set");
}

#[test]
fn no_pinned_without_consent_whatever_the_floor_column_says() {
    // The schema does not tie `trust_floor = 'pinned'` to consent.
    for floor in [None, Some(Level::Pinned)] {
        let decision = decide_level(
            &source(floor, false),
            Verified::Nothing,
            DIGEST,
            &approved(DIGEST),
        );
        assert_eq!(decision.evidence, Evidence::Downgrade, "{floor:?}");
        assert_eq!(decision.served_at, None);
        assert_eq!(
            admission(&decision, false).reason,
            Some(ReasonCode::EEvidenceDowngrade)
        );
    }
}

#[test]
fn withdrawn_consent_holds_published_pinned_releases_again() {
    // Approved and published while consent stood.
    let before = decide_level(
        &source(Some(Level::Pinned), true),
        Verified::Nothing,
        DIGEST,
        &approved(DIGEST),
    );
    assert!(admission(&before, true).published);
    // Consent withdrawn (`pinned_consent_at` в†’ NULL); the approval row stays
    // in the append-only table, but it is no longer evidence.
    let after = decide_level(
        &source(Some(Level::Pinned), false),
        Verified::Nothing,
        DIGEST,
        &approved(DIGEST),
    );
    let decision = admission(&after, false);
    assert_eq!(decision.reason, Some(ReasonCode::EEvidenceDowngrade));
    assert!(
        !decision.published,
        "a release published under consent is taken out of publication"
    );
    // Even an approval-only fact on a source without consent is refused.
    let stale = LevelDecision {
        evidence: Evidence::PinnedApproved,
        served_at: Some(Level::Pinned),
        floor: Some(Level::Pinned),
    };
    assert!(!admission(&stale, false).published);
}

#[test]
fn a_downgrade_with_pinned_consent_can_be_approved_and_the_floor_stays() {
    // `specifications/errors.md`: where the source has Pinned consent the
    // user approves the release explicitly.
    let attested = source(Some(Level::Attested), true);
    let held = decide_level(&attested, Verified::Nothing, DIGEST, &none());
    assert_eq!(
        held.evidence,
        Evidence::Downgrade,
        "until approved it is a downgrade"
    );
    let approved_release = decide_level(&attested, Verified::Nothing, DIGEST, &approved(DIGEST));
    assert_eq!(approved_release.evidence, Evidence::PinnedApproved);
    assert_eq!(
        approved_release.served_at,
        Some(Level::Pinned),
        "served from the Pinned repository"
    );
    assert_eq!(
        approved_release.floor,
        Some(Level::Attested),
        "the floor stays"
    );
}

#[test]
fn invalid_evidence_is_never_rescued_by_an_approval() {
    let decision = decide_level(
        &source(Some(Level::Pinned), true),
        Verified::Invalid,
        DIGEST,
        &approved(DIGEST),
    );
    assert_eq!(decision.evidence, Evidence::Invalid);
    assert_eq!(
        admission(&decision, true).reason,
        Some(ReasonCode::EAttestationInvalid)
    );
}

#[test]
fn every_level_has_its_own_logical_repository() -> Result<(), InvalidSourceKey> {
    let repositories: Vec<LogicalRepository> = Level::ALL
        .iter()
        .map(|level| logical_repository("netwatch", *level))
        .collect::<Result<_, _>>()?;
    for repository in &repositories {
        assert_eq!(repository.apt_origin, "Pakomichi");
        assert_eq!(repository.apt_label, repository.dnf_id);
    }
    let labels: BTreeSet<&str> = repositories.iter().map(|r| r.apt_label.as_str()).collect();
    let names: BTreeSet<&str> = repositories.iter().map(|r| r.dnf_name.as_str()).collect();
    assert_eq!(labels.len(), 3);
    assert_eq!(names.len(), 3);
    assert_eq!(repositories[0].dnf_id, "pakomichi-netwatch-pinned");
    assert!(
        repositories[0]
            .dnf_name
            .contains("no cryptographic provenance"),
        "the risk is visible without pchi"
    );
    Ok(())
}

#[test]
fn a_source_key_that_cannot_name_a_repository_is_refused() {
    for key in [
        "",
        "Netwatch",
        "net watch",
        "net/watch",
        "-x",
        "a.b",
        &"x".repeat(MAX_SOURCE_KEY + 1),
    ] {
        assert!(logical_repository(key, Level::Strict).is_err(), "{key:?}");
    }
}

#[test]
fn every_accepted_source_key_names_a_repository_the_publisher_accepts() {
    // A key the level layer accepts but the store and the APT index refuse
    // would be admitted and then never published.
    for length in 1..=64 {
        let key = "x".repeat(length);
        for level in Level::ALL {
            if let Ok(repository) = logical_repository(&key, level) {
                assert!(
                    crate::publish::RepoName::new(&repository.apt_label).is_ok(),
                    "{} characters",
                    repository.apt_label.len()
                );
                assert!(
                    crate::publish::apt::AptRepository::new(&repository.apt_label, &["amd64"])
                        .is_ok()
                );
            }
        }
    }
}

#[test]
fn levels_read_back_from_the_floor_column() {
    for level in Level::ALL {
        assert_eq!(Level::from_column(level.as_str()), Some(level));
    }
    assert_eq!(
        Level::from_column("signed"),
        None,
        "Signed is deferred to 0.2"
    );
    assert!(Level::Pinned < Level::Attested && Level::Attested < Level::Strict);
}

#[test]
fn n039_an_asset_changed_after_approval_is_denied_as_mutated() {
    // Approved bytes DIGEST; the asset under the pinned ID now has OTHER.
    let pinned = source(Some(Level::Pinned), true);
    let level = decide_level(&pinned, Verified::Nothing, OTHER, &approved(DIGEST));
    assert_eq!(
        level.evidence,
        Evidence::PinnedUnapproved,
        "an approval binds to its exact bytes"
    );
    let mut facts = Facts::new(
        SourceFacts {
            source_id: "s1".to_owned(),
            requested_mode: SourceMode::Supplemental,
            identity: Identity::Unchanged,
            pinned: true,
            native_selection_proven: false,
            execution_policy_off: true,
        },
        ArtifactFacts {
            name: "netwatch".to_owned(),
            version: "0.36.0".to_owned(),
            sha256: OTHER.to_owned(),
            evidence: level.evidence,
            asset_mutated: true,
            malformed: false,
            channel_unclear: false,
            namespace: Namespace::Known(NamespaceFacts {
                relation_conflict: false,
                own_name: OwnName::Free,
            }),
            family_hold: None,
            compat_hold: None,
            ambiguous_with_other_source: false,
            provided_elsewhere: false,
            activated_earlier: false,
            migration_confirmed: false,
        },
    );
    let decision = decide(&facts);
    assert_eq!(decision.reason, Some(ReasonCode::EAssetMutated));
    assert_eq!(decision.outcome, crate::policy::Outcome::Deny);
    // The pin check is what denies; without it the bytes still wait for
    // their own approval and are never published under the old one.
    facts.artifact.asset_mutated = false;
    assert_eq!(
        decide(&facts).reason,
        Some(ReasonCode::EReleaseApprovalRequired)
    );
}

#[test]
fn n037_a_pinned_source_is_never_preferred_and_never_displaces_a_distribution_package() {
    let approved_release = decide_level(
        &source(Some(Level::Pinned), true),
        Verified::Nothing,
        DIGEST,
        &approved(DIGEST),
    );
    let base = |mode| {
        Facts::new(
            SourceFacts {
                source_id: "s1".to_owned(),
                requested_mode: mode,
                identity: Identity::Unchanged,
                pinned: true,
                native_selection_proven: true,
                execution_policy_off: true,
            },
            ArtifactFacts {
                name: "curl".to_owned(),
                version: "8.99.0".to_owned(),
                sha256: DIGEST.to_owned(),
                evidence: approved_release.evidence,
                asset_mutated: false,
                malformed: false,
                channel_unclear: false,
                namespace: Namespace::Known(NamespaceFacts {
                    relation_conflict: false,
                    own_name: OwnName::Free,
                }),
                family_hold: None,
                compat_hold: None,
                ambiguous_with_other_source: false,
                provided_elsewhere: false,
                activated_earlier: false,
                migration_confirmed: false,
            },
        )
    };
    // `--policy preferred` on a Pinned source: never a preferred source.
    let preferred = decide(&base(SourceMode::Preferred));
    assert_eq!(preferred.mode, SourceMode::Observing);
    assert!(!preferred.published);
    // A name the distribution ships, even with an explicit migration.
    for own_name in [OwnName::NeedsMigration, OwnName::OsPart] {
        let mut facts = base(SourceMode::Preferred);
        if let Some(namespace) = facts.artifact.namespace.known_mut() {
            namespace.own_name = own_name;
        }
        facts.artifact.migration_confirmed = true;
        let decision = decide(&facts);
        assert_eq!(
            decision.outcome,
            crate::policy::Outcome::Hold,
            "{own_name:?}"
        );
        assert!(!decision.published);
    }
}
