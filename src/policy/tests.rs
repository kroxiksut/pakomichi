// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

fn source(mode: SourceMode) -> SourceFacts {
    SourceFacts {
        source_id: "source-1".to_owned(),
        requested_mode: mode,
        identity: Identity::Unchanged,
        pinned: false,
        native_selection_proven: false,
        execution_policy_off: true,
    }
}

fn artifact() -> ArtifactFacts {
    ArtifactFacts {
        name: "netwatch".to_owned(),
        version: "0.35.4".to_owned(),
        sha256: "8fcda58d824b4fea8f98e036083f398f497941af4b8c15de5dac02dd900576fd".to_owned(),
        evidence: Evidence::Attested,
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
    }
}

fn supplemental() -> Facts {
    Facts::new(source(SourceMode::Supplemental), artifact())
}

fn assert_decision(facts: &Facts, outcome: Outcome, rule: Rule, reason: Option<ReasonCode>) {
    let decision = decide(facts);
    assert_eq!(
        (decision.outcome, decision.rule, decision.reason),
        (outcome, rule, reason),
        "{decision:?}"
    );
    if outcome != Outcome::Allow {
        assert!(
            !decision.published,
            "a held or denied artifact is never published"
        );
    }
}

#[test]
fn an_admissible_artifact_of_a_supplemental_source_is_published() {
    let decision = decide(&supplemental());
    assert_eq!(decision.outcome, Outcome::Allow);
    assert!(decision.published);
    assert_eq!(decision.mode, SourceMode::Supplemental);
    assert_eq!(decision.reason, None);
}

#[test]
fn a_source_never_becomes_preferred_without_proof_of_native_selection() {
    let mut facts = Facts::new(source(SourceMode::Preferred), artifact());
    let decision = decide(&facts);
    assert_eq!(decision.mode, SourceMode::Observing, "no false preferred");
    assert_eq!(decision.outcome, Outcome::Allow);
    assert!(!decision.published);
    assert_eq!(effective_mode(&facts.source).rule, Rule::NativeFeasibility);

    facts.source.native_selection_proven = true;
    let decision = decide(&facts);
    assert_eq!(decision.mode, SourceMode::Preferred);
    assert!(decision.published);
}

#[test]
fn a_pinned_source_is_never_preferred() {
    let mut facts = Facts::new(source(SourceMode::Preferred), artifact());
    facts.source.pinned = true;
    facts.source.native_selection_proven = true;
    facts.artifact.evidence = Evidence::PinnedApproved;
    let decision = decide(&facts);
    assert_eq!(decision.mode, SourceMode::Observing);
    assert!(!decision.published);
}

#[test]
fn an_observed_source_publishes_nothing() {
    let decision = decide(&Facts::new(source(SourceMode::Observing), artifact()));
    assert_eq!(decision.outcome, Outcome::Allow);
    assert!(!decision.published);
}

#[test]
fn a_changed_identity_suspends_the_source_before_anything_else() {
    let mut facts = supplemental();
    facts.source.identity = Identity::OwnerTransfer;
    // Even an invalid attestation is decided by the identity first.
    facts.artifact.evidence = Evidence::Invalid;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Identity,
        Some(ReasonCode::EOwnerTransfer),
    );
    assert_eq!(decide(&facts).mode, SourceMode::Suspended);

    facts.source.identity = Identity::Replaced;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Identity,
        Some(ReasonCode::ERepoIdChanged),
    );

    facts.source.identity = Identity::Renamed;
    facts.artifact.evidence = Evidence::Attested;
    assert_decision(&facts, Outcome::Allow, Rule::Publication, None);
}

#[test]
fn contradicting_bytes_are_denied_and_weaker_evidence_is_held() {
    let mut facts = supplemental();
    facts.artifact.asset_mutated = true;
    assert_decision(
        &facts,
        Outcome::Deny,
        Rule::Provenance,
        Some(ReasonCode::EAssetMutated),
    );

    let mut facts = supplemental();
    facts.artifact.malformed = true;
    assert_decision(
        &facts,
        Outcome::Deny,
        Rule::Provenance,
        Some(ReasonCode::EArtifactMalformed),
    );

    let mut facts = supplemental();
    facts.artifact.evidence = Evidence::Invalid;
    assert_decision(
        &facts,
        Outcome::Deny,
        Rule::Provenance,
        Some(ReasonCode::EAttestationInvalid),
    );

    let mut facts = supplemental();
    facts.artifact.evidence = Evidence::Downgrade;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Provenance,
        Some(ReasonCode::EEvidenceDowngrade),
    );
}

#[test]
fn a_pinned_release_needs_both_consent_and_approval() {
    let mut facts = supplemental();
    facts.source.pinned = true;
    facts.artifact.evidence = Evidence::PinnedUnapproved;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Provenance,
        Some(ReasonCode::EReleaseApprovalRequired),
    );

    facts.artifact.evidence = Evidence::PinnedApproved;
    assert_decision(&facts, Outcome::Allow, Rule::Publication, None);

    // An approval on a source without Pinned consent is not evidence.
    facts.source.pinned = false;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Provenance,
        Some(ReasonCode::EEvidenceDowngrade),
    );
}

#[test]
fn composition_holds_come_from_the_family_and_the_namespace() {
    let mut facts = supplemental();
    facts.artifact.family_hold = Some(ReasonCode::EFamilyUnapproved);
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Composition,
        Some(ReasonCode::EFamilyUnapproved),
    );

    let mut facts = supplemental();
    facts.artifact.namespace = Namespace::Unknown(ReasonCode::ESystemNamespaceUnknown);
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Composition,
        Some(ReasonCode::ESystemNamespaceUnknown),
    );

    let mut facts = supplemental();
    if let Some(namespace) = facts.artifact.namespace.known_mut() {
        namespace.relation_conflict = true;
    }
    // A name activated earlier keeps its publisher, but a Provides of a
    // system package is never excused.
    facts.artifact.activated_earlier = true;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Composition,
        Some(ReasonCode::ESystemPackageConflict),
    );
}

#[test]
fn an_os_part_name_is_held_unless_this_source_had_it_first() {
    let mut facts = supplemental();
    if let Some(namespace) = facts.artifact.namespace.known_mut() {
        namespace.own_name = OwnName::OsPart;
    }
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Composition,
        Some(ReasonCode::ESystemPackageConflict),
    );
    facts.artifact.activated_earlier = true;
    assert_decision(&facts, Outcome::Allow, Rule::Publication, None);
}

#[test]
fn a_name_the_distribution_or_another_source_provides_is_not_activated_in_supplemental() {
    let mut facts = supplemental();
    if let Some(namespace) = facts.artifact.namespace.known_mut() {
        namespace.own_name = OwnName::NeedsMigration;
    }
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Conflicts,
        Some(ReasonCode::ENameProvidedElsewhere),
    );

    let mut facts = supplemental();
    facts.artifact.provided_elsewhere = true;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Conflicts,
        Some(ReasonCode::ENameProvidedElsewhere),
    );

    // A confirmed migration counts only in preferred mode.
    facts.artifact.migration_confirmed = true;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Conflicts,
        Some(ReasonCode::ENameProvidedElsewhere),
    );

    // Kept when this source had the name first.
    let mut facts = supplemental();
    facts.artifact.provided_elsewhere = true;
    facts.artifact.activated_earlier = true;
    assert_decision(&facts, Outcome::Allow, Rule::Publication, None);
}

#[test]
fn only_an_explicit_migration_of_a_non_pinned_preferred_source_takes_a_name_over() {
    let mut facts = Facts::new(source(SourceMode::Preferred), artifact());
    facts.source.native_selection_proven = true;
    facts.artifact.provided_elsewhere = true;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Conflicts,
        Some(ReasonCode::ENameProvidedElsewhere),
    );

    facts.artifact.migration_confirmed = true;
    assert_decision(&facts, Outcome::Allow, Rule::Publication, None);
    assert!(decide(&facts).published);

    // A Pinned source never migrates a name (ADR-027 point 5).
    facts.source.pinned = true;
    facts.artifact.evidence = Evidence::PinnedApproved;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Conflicts,
        Some(ReasonCode::ENameProvidedElsewhere),
    );
}

#[test]
fn n035_an_execution_policy_refuses_activation_and_holds_everything() {
    let mut facts = supplemental();
    facts.source.execution_policy_off = false;
    let decision = decide(&facts);
    assert_eq!(decision.mode, SourceMode::Observing);
    assert_eq!(decision.reason, Some(ReasonCode::EExecutionPolicy));
    assert_eq!(decision.outcome, Outcome::Hold);
    assert!(!decision.published);
}

#[test]
fn channel_compatibility_and_ambiguity_hold() {
    let mut facts = supplemental();
    facts.artifact.channel_unclear = true;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::SuitableRelease,
        Some(ReasonCode::EChannelUnclear),
    );

    let mut facts = supplemental();
    facts.artifact.compat_hold = Some(ReasonCode::EDependencyUnsatisfiable);
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::SuitableRelease,
        Some(ReasonCode::EDependencyUnsatisfiable),
    );

    let mut facts = supplemental();
    facts.artifact.ambiguous_with_other_source = true;
    assert_decision(
        &facts,
        Outcome::Hold,
        Rule::Conflicts,
        Some(ReasonCode::ESourceAmbiguous),
    );
}

#[test]
fn a_recorded_decision_replays_to_the_same_outcome_and_digest() -> Result<(), FactsError> {
    let mut facts = supplemental();
    facts.artifact.compat_hold = Some(ReasonCode::EDependencyUnsatisfiable);
    let json = facts.to_json();
    let replayed = Facts::from_json(&json)?;
    assert_eq!(replayed, facts);
    assert_eq!(decide(&replayed), decide(&facts));
    assert_eq!(replayed.digest(), facts.digest());
    assert_eq!(replayed.to_json(), json, "the evidence JSON is canonical");
    Ok(())
}

#[test]
fn every_fact_changes_the_digest() {
    let base = supplemental();
    let mut variants = Vec::new();
    let mut variant = |edit: fn(&mut Facts)| {
        let mut facts = base.clone();
        edit(&mut facts);
        variants.push(facts.digest());
    };
    variant(|facts| facts.source.source_id.push('x'));
    variant(|facts| facts.source.pinned = true);
    variant(|facts| facts.source.native_selection_proven = true);
    variant(|facts| facts.artifact.sha256.replace_range(0..1, "9"));
    variant(|facts| facts.artifact.provided_elsewhere = true);
    variant(|facts| {
        facts.artifact.namespace = Namespace::Unknown(ReasonCode::ESystemNamespaceUnknown)
    });
    variant(|facts| {
        facts.artifact.namespace = Namespace::Unknown(ReasonCode::EPlatformUnsupported)
    });
    variant(|facts| facts.artifact.evidence = Evidence::Strict);
    let mut all = variants.clone();
    all.push(base.digest());
    all.sort_by_key(Sha256Digest::to_hex);
    all.dedup();
    assert_eq!(
        all.len(),
        variants.len() + 1,
        "two different facts gave one digest"
    );
}

#[test]
fn facts_of_another_version_or_with_an_unknown_field_are_refused() {
    let json = supplemental().to_json();
    let newer = json.replacen("\"schema_version\":2", "\"schema_version\":3", 1);
    assert_eq!(
        Facts::from_json(&newer),
        Err(FactsError::UnsupportedVersion(3))
    );
    let extra = json.replacen("\"pinned\":false", "\"pinned\":false,\"trusted\":true", 1);
    assert!(matches!(
        Facts::from_json(&extra),
        Err(FactsError::Malformed(_))
    ));
    let missing = json.replacen("\"pinned\":false,", "", 1);
    assert!(
        matches!(Facts::from_json(&missing), Err(FactsError::Malformed(_))),
        "an absent protection field is never read as a default"
    );
}

#[test]
fn the_behaviour_table_matches_the_error_specification() {
    // `specifications/errors.md`: "Reject" → deny, "Suspend" → suspend the
    // source, anything else holds or is not an admission outcome.
    let spec = include_str!("../../docs/en/specifications/errors.md");
    for code in ReasonCode::ALL {
        let row = spec
            .lines()
            .find(|line| line.starts_with(&format!("| `{}` |", code.as_str())))
            .unwrap_or_else(|| panic!("{code} has no row"));
        let behaviour_column = row.rsplit('|').nth(1).unwrap_or_default().trim();
        let expected = if behaviour_column.starts_with("Reject") {
            Behaviour::Reject
        } else if behaviour_column.starts_with("Suspend") {
            Behaviour::SuspendSource
        } else {
            Behaviour::Hold
        };
        assert_eq!(behaviour(code), expected, "{code}: {behaviour_column}");
    }
}

#[test]
fn a_decision_logged_in_version_1_replays_as_it_was_decided()
-> Result<(), Box<dyn std::error::Error>> {
    // Rows written before version 2 stay in the append-only log; replaying
    // them must give the outcome they were written with.
    for namespace in [true, false] {
        let mut facts = supplemental();
        if !namespace {
            facts.artifact.namespace = Namespace::Unknown(ReasonCode::ESystemNamespaceUnknown);
        }
        let mut value: serde_json::Value = serde_json::from_str(&facts.to_json())?;
        value["schema_version"] = 1.into();
        let inner = value["artifact"]["namespace"]["known"].clone();
        value["artifact"]["namespace"] = inner;
        let replayed = Facts::from_json(&value.to_string())?;
        assert_eq!(replayed, facts);
        assert_eq!(decide(&replayed), decide(&facts));
    }
    Ok(())
}

#[test]
fn an_unknown_namespace_holds_with_the_reason_of_its_collector() {
    // An unsupported platform is not "missing metadata, run apt update".
    for code in [
        ReasonCode::ESystemNamespaceUnknown,
        ReasonCode::EPlatformUnsupported,
    ] {
        let mut facts = supplemental();
        facts.artifact.namespace = Namespace::Unknown(code);
        let decision = decide(&facts);
        assert_eq!(decision.outcome, Outcome::Hold);
        assert_eq!(decision.rule, Rule::Composition);
        assert_eq!(decision.reason, Some(code));
        assert!(!decision.published);
    }
}
