// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::github::{OwnerId, OwnerLogin, RepositoryId, RepositoryIdentity, RepositoryName};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: &str = "2026-10-24T12:00:00Z";

fn pinned(owner: &str, name: &str) -> Result<PinnedRepository, Box<dyn std::error::Error>> {
    Ok(PinnedRepository::pin(RepositoryIdentity::new(
        RepositoryId::new(1_429_109_739)?,
        OwnerId::new(2_264_172)?,
        OwnerLogin::new(owner)?,
        RepositoryName::new(name)?,
    )))
}

#[test]
fn a_source_is_recorded_by_its_ids_and_restored_as_pinned() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let pin = pinned("kroxiksut", "pchi-test")?;
    let id = owner.add_source(&pin, false, None, AT)?;
    assert_eq!(id, "github-1429109739");
    let restored = owner
        .pinned_repository(&id)?
        .ok_or("the source is not restored")?;
    assert_eq!(restored, pin);
    let rows = owner.sources()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "registered");
    assert_eq!(
        rows[0].trust_floor, None,
        "no level before the first admission"
    );
    assert!(!rows[0].pinned_consent, "Pinned consent is never a default");
    Ok(())
}

#[test]
fn the_same_repository_under_another_name_is_not_a_second_source() -> TestResult {
    // A renamed or transferred repository resolves to the same ID; two
    // sources for it would each keep their own pins and trust floor.
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let id = owner.add_source(&pinned("kroxiksut", "pchi-test")?, true, None, AT)?;
    // Refused under the new name, it must not leave its signer behind.
    let again = owner.add_source(
        &pinned("pchi-test-org", "pchi-test-renamed")?,
        false,
        Some(&signer(".github/workflows/evil.yml")?),
        AT,
    );
    assert!(
        matches!(&again, Err(StateError::SourceExists { id: existing }) if *existing == id),
        "{again:?}"
    );
    let rows = owner.sources()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "observing");
    assert_eq!(
        rows[0].canonical_url,
        "https://github.com/kroxiksut/pchi-test"
    );
    assert_eq!(rows[0].signer, None);
    Ok(())
}

fn signer(workflow: &str) -> Result<AttestedSigner, Box<dyn std::error::Error>> {
    Ok(AttestedSigner::new(workflow, SignerRef::ReleaseTag).map_err(|_| "bad workflow")?)
}

#[test]
fn the_latest_confirmed_signer_wins_and_the_earlier_ones_stay() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let first = signer(".github/workflows/release.yml")?;
    let id = owner.add_source(&pinned("kroxiksut", "pchi-test")?, false, Some(&first), AT)?;
    assert_eq!(owner.attested_signer(&id)?, Some(first));
    let moved = AttestedSigner::new(
        ".github/workflows/publish.yml",
        SignerRef::Branch("main".into()),
    )
    .map_err(|_| "bad workflow")?;
    owner.confirm_signer(&id, &moved, "2026-10-25T00:00:00Z")?;
    assert_eq!(owner.sources()?[0].signer.as_ref(), Some(&moved));
    let kept: i64 = owner.connection().query_row(
        "SELECT count(*) FROM attested_signer WHERE source_id = ?1",
        [&id],
        |row| row.get(0),
    )?;
    assert_eq!(kept, 2, "who could sign before stays on record");
    Ok(())
}
