// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: &str = "2026-10-24T12:00:00Z";

fn owner_with_sources() -> Result<(TempDir, StateOwner), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    for (id, repository) in [("source-1", "1001"), ("source-2", "1002")] {
        owner.connection().execute(
            "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, \
             first_seen_at) VALUES (?1, 'github', ?2, 'owner-1', 'https://example.invalid/r', ?3)",
            params![id, repository, AT],
        )?;
    }
    Ok((dir, owner))
}

#[test]
fn a_name_activated_in_one_source_is_refused_in_another() -> TestResult {
    // Two sources with a 990 pin for one name: the higher version would
    // decide the publisher.
    let (_dir, mut owner) = owner_with_sources()?;
    assert_eq!(
        owner.record_activation("source-1", Ecosystem::Deb, "sampleapp", AT)?,
        Activation::Recorded
    );
    assert!(matches!(
        owner.record_activation("source-2", Ecosystem::Deb, "sampleapp", AT),
        Err(StateError::NameActivatedElsewhere)
    ));
    assert_eq!(
        owner.record_activation("source-1", Ecosystem::Deb, "sampleapp", AT)?,
        Activation::AlreadyOpen
    );
    // Another ecosystem's package of the same name is another package.
    owner.record_activation("source-2", Ecosystem::Rpm, "sampleapp", AT)?;
    Ok(())
}

#[test]
fn only_the_activating_source_keeps_the_name_and_only_while_it_is_open() -> TestResult {
    let (_dir, mut owner) = owner_with_sources()?;
    assert!(!owner.activated_earlier("source-1", Ecosystem::Deb, "sampleapp")?);
    owner.record_activation("source-1", Ecosystem::Deb, "sampleapp", AT)?;
    assert!(owner.activated_earlier("source-1", Ecosystem::Deb, "sampleapp")?);
    assert!(!owner.activated_earlier("source-2", Ecosystem::Deb, "sampleapp")?);
    assert!(!owner.activated_earlier("source-1", Ecosystem::Rpm, "sampleapp")?);
    // After deactivation a new activation is a new decision: the name may
    // be taken by now.
    assert!(owner.end_activation("source-1", Ecosystem::Deb, "sampleapp", AT)?);
    assert!(!owner.end_activation("source-1", Ecosystem::Deb, "sampleapp", AT)?);
    assert!(!owner.activated_earlier("source-1", Ecosystem::Deb, "sampleapp")?);
    owner.record_activation("source-2", Ecosystem::Deb, "sampleapp", AT)?;
    assert!(owner.activated_earlier("source-2", Ecosystem::Deb, "sampleapp")?);
    Ok(())
}
