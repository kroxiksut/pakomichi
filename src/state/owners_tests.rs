// SPDX-License-Identifier: MIT OR Apache-2.0

//! Owner IDs are those of the R-003 test repository: user `2264172`, then
//! organization `346117935` after the transfer on 2026-10-22.

use std::error::Error;

use super::*;
use crate::github::{
    OwnerId, OwnerLogin, PinnedRepository, RepositoryId, RepositoryIdentity, RepositoryName,
};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

const USER: &str = "2264172";
const ORGANIZATION: &str = "346117935";

fn open_with_source(dir: &TempDir) -> Result<StateOwner, Box<dyn Error>> {
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    owner.connection().execute(
        "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, first_seen_at) \
         VALUES ('s1', 'github', '1429109739', ?1, 'https://github.com/kroxiksut/pchi-test', \
         '2026-10-22T05:08:16Z')",
        [USER],
    )?;
    Ok(owner)
}

fn current_owner(owner: &mut StateOwner) -> rusqlite::Result<String> {
    owner.connection().query_row(
        "SELECT owner_id FROM forge_repository WHERE id = 's1'",
        [],
        |row| row.get(0),
    )
}

#[test]
fn adding_a_source_records_its_pinned_owner() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = open_with_source(&dir)?;
    assert_eq!(
        owner.owner_confirmations("s1")?,
        vec![OwnerConfirmation {
            owner_id: USER.to_owned(),
            kind: OwnerConfirmationKind::Pinned,
            confirmed_at: "2026-10-22T05:08:16Z".to_owned(),
        }]
    );
    assert!(owner.owner_confirmations("missing")?.is_empty());
    Ok(())
}

#[test]
fn a_confirmed_transfer_survives_reopening_and_restores_the_pin() -> TestResult {
    let dir = TempDir::new()?;
    {
        let mut owner = open_with_source(&dir)?;
        owner.confirm_owner_transfer("s1", ORGANIZATION, "2026-10-22T06:10:09Z")?;
        assert_eq!(current_owner(&mut owner)?, ORGANIZATION);
    }
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let confirmed = owner.confirmed_owner_ids("s1")?;
    assert_eq!(
        confirmed.iter().map(String::as_str).collect::<Vec<_>>(),
        vec![USER, ORGANIZATION]
    );

    // The stored set restores the pin, so releases attested under the user
    // still pass after the transfer (R-003 probe case T3).
    let current = RepositoryIdentity::new(
        RepositoryId::new(1_429_109_739)?,
        OwnerId::new(current_owner(&mut owner)?.parse()?)?,
        OwnerLogin::new("pchi-test-org")?,
        RepositoryName::new("pchi-test-renamed")?,
    );
    let earlier = confirmed
        .iter()
        .map(|id| Ok(OwnerId::new(id.parse()?)?))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let pinned = PinnedRepository::restore(current, earlier);
    assert!(pinned.accepts_owner(OwnerId::new(2_264_172)?));
    assert!(pinned.accepts_owner(OwnerId::new(346_117_935)?));
    Ok(())
}

#[test]
fn a_move_back_is_recorded_as_another_transfer() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = open_with_source(&dir)?;
    owner.confirm_owner_transfer("s1", ORGANIZATION, "2026-10-22T06:10:09Z")?;
    owner.confirm_owner_transfer("s1", USER, "2026-10-23T09:00:00Z")?;
    let kinds: Vec<_> = owner
        .owner_confirmations("s1")?
        .into_iter()
        .map(|confirmation| (confirmation.owner_id, confirmation.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (USER.to_owned(), OwnerConfirmationKind::Pinned),
            (ORGANIZATION.to_owned(), OwnerConfirmationKind::Transfer),
            (USER.to_owned(), OwnerConfirmationKind::Transfer),
        ]
    );
    assert_eq!(current_owner(&mut owner)?, USER);
    assert_eq!(owner.confirmed_owner_ids("s1")?.len(), 2);
    Ok(())
}

#[test]
fn refused_confirmations_name_their_rule_and_change_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = open_with_source(&dir)?;
    assert!(matches!(
        owner.confirm_owner_transfer("s1", USER, "2026-10-22T06:10:09Z"),
        Err(StateError::OwnerConfirmationRefused {
            rule: "a transfer confirms another owner"
        })
    ));
    assert!(matches!(
        owner.confirm_owner_transfer("missing", ORGANIZATION, "2026-10-22T06:10:09Z"),
        Err(StateError::OwnerConfirmationRefused {
            rule: "a transfer needs a pinned source"
        })
    ));
    // The owner ID never changes without a confirmation.
    let direct = owner.connection().execute(
        "UPDATE forge_repository SET owner_id = ?1 WHERE id = 's1'",
        [ORGANIZATION],
    );
    assert!(direct.is_err());
    // Confirmations are append-only.
    for statement in [
        "UPDATE repository_owner_confirmation SET owner_id = '1'",
        "DELETE FROM repository_owner_confirmation",
    ] {
        assert!(
            owner.connection().execute(statement, []).is_err(),
            "{statement}"
        );
    }
    assert_eq!(owner.owner_confirmations("s1")?.len(), 1);
    assert_eq!(current_owner(&mut owner)?, USER);
    Ok(())
}

/// Adds source `bad` with the given row values; the insert trigger pins
/// its owner, so only the corrupt field differs from a valid source.
fn insert_source(
    owner: &mut StateOwner,
    forge: &str,
    repository_id: &str,
    owner_id: &str,
    canonical_url: &str,
) -> rusqlite::Result<usize> {
    owner.connection().execute(
        "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, first_seen_at) \
         VALUES ('bad', ?1, ?2, ?3, ?4, '2026-10-22T05:08:16Z')",
        [forge, repository_id, owner_id, canonical_url],
    )
}

#[test]
fn a_stored_pin_accepts_every_confirmed_owner() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = open_with_source(&dir)?;
    owner.confirm_owner_transfer("s1", ORGANIZATION, "2026-10-22T06:10:09Z")?;
    let pinned = owner
        .pinned_repository("s1")?
        .ok_or("the source has a pin")?;
    assert_eq!(pinned.repository_id(), RepositoryId::new(1_429_109_739)?);
    assert_eq!(pinned.identity().owner().as_str(), "kroxiksut");
    assert!(pinned.accepts_owner(OwnerId::new(2_264_172)?));
    assert!(pinned.accepts_owner(OwnerId::new(346_117_935)?));
    assert!(!pinned.accepts_owner(OwnerId::new(1)?));
    assert!(owner.pinned_repository("missing")?.is_none());
    Ok(())
}

#[test]
fn a_corrupt_source_row_is_an_invalid_database() -> TestResult {
    let cases = [
        (
            "gitlab",
            "1429109739",
            USER,
            "https://github.com/kroxiksut/pchi-test",
        ),
        (
            "github",
            "x1",
            USER,
            "https://github.com/kroxiksut/pchi-test",
        ),
        (
            "github",
            "+1429109739",
            USER,
            "https://github.com/kroxiksut/pchi-test",
        ),
        (
            "github",
            "0",
            USER,
            "https://github.com/kroxiksut/pchi-test",
        ),
        (
            "github",
            "1429109739",
            "-2264172",
            "https://github.com/kroxiksut/pchi-test",
        ),
        (
            "github",
            "1429109739",
            USER,
            "http://github.com/kroxiksut/pchi-test",
        ),
        (
            "github",
            "1429109739",
            USER,
            "https://github.comkroxiksut/pchi-test",
        ),
        ("github", "1429109739", USER, "https://github.com/kroxiksut"),
        (
            "github",
            "1429109739",
            USER,
            "https://github.com/kroxiksut/pchi-test/",
        ),
        ("github", "1429109739", USER, "https://github.com/a/b/c"),
        (
            "github",
            "1429109739",
            USER,
            "https://github.com/kro xiksut/pchi-test",
        ),
        (
            "github",
            "1429109739",
            USER,
            "https://github.com/kroxiksut/",
        ),
    ];
    for (forge, repository_id, owner_id, canonical_url) in cases {
        let dir = TempDir::new()?;
        let mut owner = StateOwner::open(&dir.join("state.db"))?;
        insert_source(&mut owner, forge, repository_id, owner_id, canonical_url)?;
        let result = owner.pinned_repository("bad");
        assert!(
            matches!(result, Err(StateError::InvalidDatabase { .. })),
            "{forge} {repository_id} {owner_id} {canonical_url}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn a_current_owner_without_a_confirmation_is_an_invalid_database() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    // Only a damaged schema can hold a source without its pinned owner.
    owner
        .connection()
        .execute("DROP TRIGGER forge_repository_records_pinned_owner", [])?;
    insert_source(
        &mut owner,
        "github",
        "1429109739",
        USER,
        "https://github.com/kroxiksut/pchi-test",
    )?;
    let result = owner.pinned_repository("bad");
    assert!(
        matches!(
            result,
            Err(StateError::InvalidDatabase {
                problem: "forge_repository.owner_id is not a confirmed owner of the source"
            })
        ),
        "{result:?}"
    );
    Ok(())
}
