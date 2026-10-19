// SPDX-License-Identifier: MIT OR Apache-2.0

use rusqlite::{Connection, backup::Backup};
use std::error::Error;
use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};

/// A scratch directory that is removed when dropped, also after a failed assertion.
struct Scratch(PathBuf);

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Result<Scratch, Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!("pakomichi-{name}-{}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path)?;
    }
    fs::create_dir_all(&path)?;
    Ok(Scratch(path))
}

#[test]
fn system_sqlite_applies_schema_enforces_fk_and_backs_up() -> Result<(), Box<dyn Error>> {
    let directory = scratch("sqlite-probe")?;
    let source_path = directory.join("state.sqlite3");
    let backup_path = directory.join("backup.sqlite3");
    let connection = Connection::open(&source_path)?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    connection.execute_batch(include_str!("../../../migrations/0001_initial.sql"))?;

    let sqlite_version: String =
        connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    assert!(
        sqlite_version.as_str() >= "3.37",
        "SQLite {sqlite_version} is too old"
    );
    assert!(
        connection
            .execute(
                "INSERT INTO release_record (id, source_id, forge_release_id, tag, published_at, channel) VALUES ('release', 'missing-source', '1', 'v1', '2026-01-01T00:00:00Z', 'stable')",
                [],
            )
            .is_err(),
        "foreign keys must fail closed"
    );

    let mut backup_connection = Connection::open(&backup_path)?;
    Backup::new(&connection, &mut backup_connection)?.run_to_completion(
        5,
        std::time::Duration::from_millis(1),
        None,
    )?;
    let table_count: i64 = backup_connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'forge_repository'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(table_count, 1);
    Ok(())
}

#[test]
fn rpm_metadata_read_does_not_execute_scriptlets() -> Result<(), Box<dyn Error>> {
    let directory = scratch("rpm-probe")?;
    let marker = directory.join("scriptlet-ran");
    let rpm_path = directory.join("probe.rpm");
    let script = format!("touch {}", marker.display());

    let mut builder = rpm::PackageBuilder::new(
        "pakomichi-probe",
        "1.0.0",
        "MIT OR Apache-2.0",
        "noarch",
        "P0-004 metadata inspection fixture",
    );
    builder
        .release("1")
        .pre_install_script(script.as_str())
        .with_file_contents(
            "fixture\n",
            rpm::FileOptions::new("/usr/share/pakomichi-probe/fixture.txt"),
        )?;
    builder.build()?.write_file(&rpm_path)?;

    let metadata = rpm::PackageMetadata::open(&rpm_path)?;
    assert_eq!(metadata.get_name()?, "pakomichi-probe");
    assert_eq!(metadata.get_pre_install_script()?.script, script);
    assert!(
        !marker.exists(),
        "metadata inspection executed an RPM scriptlet"
    );

    let mut malformed = fs::read(&rpm_path)?;
    malformed.truncate(48);
    let malformed_path = directory.join("malformed.rpm");
    fs::write(&malformed_path, malformed)?;
    assert!(rpm::PackageMetadata::open(&malformed_path).is_err());
    assert!(
        !marker.exists(),
        "malformed RPM inspection executed a scriptlet"
    );
    Ok(())
}
