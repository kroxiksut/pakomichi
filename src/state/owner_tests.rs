// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::*;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

fn insert_source(owner: &StateOwner, id: &str, repository_id: &str) -> rusqlite::Result<usize> {
    owner.connection.execute(
        "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, first_seen_at) \
         VALUES (?1, 'github', ?2, '1', 'https://github.com/o/r', '2026-10-21T00:00:00Z')",
        [id, repository_id],
    )
}

fn source_ids(owner: &StateOwner) -> rusqlite::Result<Vec<String>> {
    let mut statement = owner
        .connection
        .prepare("SELECT id FROM forge_repository ORDER BY id")?;
    statement.query_map([], |row| row.get(0))?.collect()
}

fn mode_of(path: &Path) -> io::Result<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

#[test]
fn the_sqlite_floor_is_enforced_with_a_platform_reason() {
    assert!(check_sqlite_version(MIN_SQLITE_VERSION).is_ok());
    assert!(check_sqlite_version(3_051_002).is_ok());
    let error = check_sqlite_version(3_034_000).err();
    assert!(matches!(
        error,
        Some(StateError::SqliteTooOld { found: 3_034_000 })
    ));
    let error = error.map(|error| (error.reason_code(), error.to_string()));
    assert_eq!(
        error,
        Some((
            Some(ReasonCode::EPlatformUnsupported),
            "system SQLite 3.34.0 is older than the required 3.34.1".to_owned()
        ))
    );
    // The library this test links against is at or above the floor.
    assert!(check_sqlite_version(rusqlite::version_number()).is_ok());
}

#[test]
fn opening_creates_a_private_database_with_the_schema() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.join("state.db");
    let owner = StateOwner::open(&path)?;

    assert_eq!(mode_of(&path)?, 0o600);
    assert_eq!(mode_of(&lock_path(&path))?, 0o600);
    assert_eq!(owner.schema_version()?, SCHEMA_VERSION);
    let mode: String = owner
        .connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    let migrations: i64 =
        owner
            .connection
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })?;
    assert_eq!(migrations, SCHEMA_VERSION);

    // Foreign keys are enforced on the owner's connection.
    let orphan = owner.connection.execute(
        "INSERT INTO repository_previous_address (source_id, canonical_url, observed_at) \
         VALUES ('missing', 'https://github.com/o/r', '2026-10-21T00:00:00Z')",
        [],
    );
    assert!(orphan.is_err());
    Ok(())
}

#[test]
fn reopening_applies_nothing_twice() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.join("state.db");
    {
        let owner = StateOwner::open(&path)?;
        insert_source(&owner, "s1", "100")?;
    }
    let owner = StateOwner::open(&path)?;
    assert_eq!(owner.schema_version()?, SCHEMA_VERSION);
    assert_eq!(source_ids(&owner)?, vec!["s1".to_owned()]);
    Ok(())
}

#[test]
fn a_second_owner_is_refused_while_the_first_is_open() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.join("state.db");
    let first = StateOwner::open(&path)?;
    assert!(matches!(
        StateOwner::open(&path),
        Err(StateError::AlreadyOwned)
    ));
    drop(first);
    assert!(StateOwner::open(&path).is_ok());
    Ok(())
}

#[test]
fn a_database_from_a_newer_build_is_refused() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.join("state.db");
    {
        let owner = StateOwner::open(&path)?;
        owner
            .connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)?;
    }
    assert!(matches!(
        StateOwner::open(&path),
        Err(StateError::NewerSchema { found }) if found == SCHEMA_VERSION + 1
    ));
    Ok(())
}

#[test]
fn foreign_migration_records_are_refused() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.join("state.db");
    {
        let owner = StateOwner::open(&path)?;
        // A version past this build's last migration.
        owner.connection.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?1, 'not this build')",
            [SCHEMA_VERSION + 1],
        )?;
    }
    assert!(matches!(
        StateOwner::open(&path),
        Err(StateError::MigrationRecordMismatch)
    ));
    Ok(())
}

#[test]
fn unsafe_paths_are_refused() -> TestResult {
    let dir = TempDir::new()?;

    // The database is a symlink.
    let real = dir.join("real.db");
    StateOwner::open(&real)?;
    let link = dir.join("link.db");
    symlink(&real, &link)?;
    assert!(matches!(
        StateOwner::open(&link),
        Err(StateError::UnsafePath { .. })
    ));

    // The database is readable by others.
    let shared = dir.join("shared.db");
    StateOwner::open(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        StateOwner::open(&shared),
        Err(StateError::UnsafePath { .. })
    ));

    // The directory is writable by group.
    let open_dir = dir.join("open");
    fs::create_dir(&open_dir)?;
    fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o770))?;
    assert!(matches!(
        StateOwner::open(&open_dir.join("state.db")),
        Err(StateError::UnsafePath { .. })
    ));
    assert!(!open_dir.join("state.db").exists());
    Ok(())
}

#[test]
fn defensive_mode_blocks_schema_tampering() -> TestResult {
    let dir = TempDir::new()?;
    let owner = StateOwner::open(&dir.join("state.db"))?;
    let tampered = owner.connection.execute_batch(
        "PRAGMA writable_schema = ON; \
         UPDATE sqlite_master SET sql = 'CREATE TABLE artifact (id TEXT)' WHERE name = 'artifact';",
    );
    assert!(tampered.is_err());
    owner
        .connection
        .execute_batch("PRAGMA writable_schema = OFF;")?;
    assert!(
        owner
            .connection
            .prepare("SELECT state FROM artifact")
            .is_ok()
    );
    Ok(())
}

#[test]
fn backup_and_restore_round_trip() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    insert_source(&owner, "s1", "100")?;

    let backup = dir.join("backup.db");
    owner.backup_to(&backup)?;
    assert_eq!(mode_of(&backup)?, 0o600);

    insert_source(&owner, "s2", "200")?;
    assert_eq!(source_ids(&owner)?, vec!["s1".to_owned(), "s2".to_owned()]);

    owner.restore_from(&backup)?;
    assert_eq!(source_ids(&owner)?, vec!["s1".to_owned()]);
    assert_eq!(owner.schema_version()?, SCHEMA_VERSION);
    // The restored database keeps the owner's settings and constraints.
    assert!(
        insert_source(&owner, "s3", "100").is_err(),
        "repository_id stays unique"
    );
    Ok(())
}

#[test]
fn a_backup_never_overwrites_an_existing_file() -> TestResult {
    let dir = TempDir::new()?;
    let owner = StateOwner::open(&dir.join("state.db"))?;
    let existing = dir.join("existing.db");
    fs::write(&existing, b"keep me")?;
    assert!(matches!(
        owner.backup_to(&existing),
        Err(StateError::TargetExists)
    ));
    assert_eq!(fs::read(&existing)?, b"keep me");
    Ok(())
}

#[test]
fn restoring_from_a_missing_path_changes_nothing() -> TestResult {
    // `Connection::restore` in rusqlite would create the missing source
    // and copy an empty database over ours; the owner never creates it.
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    insert_source(&owner, "s1", "100")?;
    let missing = dir.join("missing.db");
    assert!(owner.restore_from(&missing).is_err());
    assert!(!missing.exists());
    assert_eq!(source_ids(&owner)?, vec!["s1".to_owned()]);
    Ok(())
}

#[test]
fn restoring_from_an_invalid_source_changes_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    insert_source(&owner, "s1", "100")?;

    // Not a database at all.
    let garbage = dir.join("garbage.db");
    fs::write(&garbage, vec![0x5a_u8; 8192])?;
    assert!(owner.restore_from(&garbage).is_err());

    // A valid SQLite file without this build's schema.
    let foreign = dir.join("foreign.db");
    Connection::open(&foreign)?.execute_batch("CREATE TABLE other (a TEXT);")?;
    assert!(matches!(
        owner.restore_from(&foreign),
        Err(StateError::InvalidDatabase { .. })
    ));

    // A valid backup marked as written by a newer build.
    let newer = dir.join("newer.db");
    owner.backup_to(&newer)?;
    Connection::open(&newer)?.pragma_update(None, "user_version", SCHEMA_VERSION + 1)?;
    assert!(matches!(
        owner.restore_from(&newer),
        Err(StateError::NewerSchema { found }) if found == SCHEMA_VERSION + 1
    ));

    // A symlink as the source.
    let backup = dir.join("backup.db");
    owner.backup_to(&backup)?;
    let link = dir.join("link.db");
    symlink(&backup, &link)?;
    assert!(matches!(
        owner.restore_from(&link),
        Err(StateError::UnsafePath { .. })
    ));

    assert_eq!(source_ids(&owner)?, vec!["s1".to_owned()]);
    Ok(())
}
