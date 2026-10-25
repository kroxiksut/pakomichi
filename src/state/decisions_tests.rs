// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;

use super::*;
use crate::error::ReasonCode;
use crate::policy::{
    ArtifactFacts, Evidence, Identity, Namespace, NamespaceFacts, Outcome, OwnName, SourceFacts,
    SourceMode, decide,
};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

fn facts() -> Facts {
    Facts::new(
        SourceFacts {
            source_id: "s1".to_owned(),
            requested_mode: SourceMode::Supplemental,
            identity: Identity::Unchanged,
            pinned: false,
            native_selection_proven: false,
            execution_policy_off: true,
        },
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
        },
    )
}

fn record(owner: &mut StateOwner, facts: &Facts, at: &str) -> Result<Recorded, StateError> {
    owner.record_decision(DecisionObject::Artifact, "a1", facts, &decide(facts), at)
}

#[test]
fn a_recorded_decision_replays_to_the_same_outcome() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let mut held = facts();
    held.artifact.compat_hold = Some(ReasonCode::EDependencyUnsatisfiable);
    record(&mut owner, &facts(), "2026-10-23T10:00:00Z")?;
    record(&mut owner, &held, "2026-10-23T11:00:00Z")?;

    let log = owner.decisions(DecisionObject::Artifact, "a1")?;
    assert_eq!(log.len(), 2);
    assert_eq!(
        (log[0].outcome.as_str(), log[0].reason_code.as_str()),
        ("allow", "")
    );
    assert_eq!(
        (
            log[1].outcome.as_str(),
            log[1].reason_code.as_str(),
            log[1].rule_id.as_str()
        ),
        ("hold", "E_DEPENDENCY_UNSATISFIABLE", "suitable_release")
    );
    for row in &log {
        assert_eq!(replay(row), Replay::Same, "{row:?}");
    }
    Ok(())
}

#[test]
fn a_synchronization_that_changes_nothing_writes_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let Recorded::Written { event_id } = record(&mut owner, &facts(), "2026-10-23T10:00:00Z")?
    else {
        return Err("the first decision was not written".into());
    };
    assert_eq!(
        record(&mut owner, &facts(), "2026-10-23T10:05:00Z")?,
        Recorded::Unchanged { event_id }
    );
    assert_eq!(owner.decisions(DecisionObject::Artifact, "a1")?.len(), 1);

    // A changed fact with the same outcome is still a new decision.
    let mut renamed = facts();
    renamed.source.identity = Identity::Renamed;
    assert!(matches!(
        record(&mut owner, &renamed, "2026-10-23T10:10:00Z")?,
        Recorded::Written { .. }
    ));
    // Returning to the earlier facts is written again: the log is a history.
    assert!(matches!(
        record(&mut owner, &facts(), "2026-10-23T10:15:00Z")?,
        Recorded::Written { .. }
    ));
    assert_eq!(owner.decisions(DecisionObject::Artifact, "a1")?.len(), 3);
    Ok(())
}

#[test]
fn a_row_whose_facts_give_another_decision_is_reported() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    // A forged row: an `allow` whose facts say the attestation is invalid.
    let mut invalid = facts();
    invalid.artifact.evidence = Evidence::Invalid;
    owner.connection().execute(
        "INSERT INTO decision_log (event_id, object_type, object_id, rule_id, rule_version, outcome, \
         reason_code, reason_text, evidence_json, created_at) \
         VALUES ('forged', 'artifact', 'a1', 'publication', 1, 'allow', '', 'admissible', ?1, '2026-10-23T10:00:00Z')",
        [invalid.to_json()],
    )?;
    let log = owner.decisions(DecisionObject::Artifact, "a1")?;
    let Replay::Different { now } = replay(&log[0]) else {
        return Err(format!("not reported: {:?}", replay(&log[0])).into());
    };
    assert_eq!(now.outcome, Outcome::Deny);
    assert_eq!(now.reason, Some(ReasonCode::EAttestationInvalid));

    // Same rule and reason, softer outcome: a `hold` where the facts deny.
    owner.connection().execute(
        "INSERT INTO decision_log (event_id, object_type, object_id, rule_id, rule_version, outcome, \
         reason_code, reason_text, evidence_json, created_at) \
         VALUES ('softened', 'artifact', 'a2', 'provenance', 1, 'hold', 'E_ATTESTATION_INVALID', 'x', ?1, \
         '2026-10-23T10:00:00Z')",
        [invalid.to_json()],
    )?;
    let log = owner.decisions(DecisionObject::Artifact, "a2")?;
    assert!(
        matches!(replay(&log[0]), Replay::Different { .. }),
        "{:?}",
        replay(&log[0])
    );
    Ok(())
}

#[test]
fn unreadable_facts_and_another_rule_version_are_not_a_match() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let extra =
        facts()
            .to_json()
            .replacen("\"pinned\":false", "\"pinned\":false,\"trusted\":true", 1);
    owner.connection().execute(
        "INSERT INTO decision_log (event_id, object_type, object_id, rule_id, rule_version, outcome, \
         reason_code, reason_text, evidence_json, created_at) VALUES \
         ('extra', 'artifact', 'a1', 'publication', 1, 'allow', '', 'x', ?1, '2026-10-23T10:00:00Z'), \
         ('old-rule', 'artifact', 'a1', 'publication', 7, 'allow', '', 'x', ?2, '2026-10-23T10:01:00Z')",
        [extra, facts().to_json()],
    )?;
    let log = owner.decisions(DecisionObject::Artifact, "a1")?;
    assert!(matches!(
        replay(&log[0]),
        Replay::Unreadable(FactsError::Malformed(_))
    ));
    assert_eq!(
        replay(&log[1]),
        Replay::RuleChanged {
            logged: 7,
            current: 1
        }
    );
    Ok(())
}

#[test]
fn the_log_cannot_be_rewritten() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    record(&mut owner, &facts(), "2026-10-23T10:00:00Z")?;
    for statement in [
        "UPDATE decision_log SET outcome = 'deny'",
        "UPDATE decision_log SET evidence_json = '{}'",
        "DELETE FROM decision_log",
    ] {
        assert!(
            owner.connection().execute(statement, []).is_err(),
            "{statement}"
        );
    }
    let log = owner.decisions(DecisionObject::Artifact, "a1")?;
    assert_eq!(log.len(), 1);
    assert_eq!(replay(&log[0]), Replay::Same);
    Ok(())
}
