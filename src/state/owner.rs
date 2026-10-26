// SPDX-License-Identifier: MIT OR Apache-2.0

//! The single state owner: the only code that opens the SQLite state
//! database (ADR-013, ADR-017 point 2, ADR-020).

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::backup::{Backup, StepResult};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, MAIN_DB, OpenFlags};

use super::floor::{MIN_SQLITE_VERSION, format_version};
use crate::error::ReasonCode;

/// The schema version this build writes; `PRAGMA user_version` after the
/// last migration.
pub const SCHEMA_VERSION: i64 = 7;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

/// Forward-only migrations in order (`migrations/README.md`).
const MIGRATIONS: [Migration; 7] = [
    Migration {
        version: 1,
        name: "initial",
        sql: include_str!("../../migrations/0001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "repository_owner_confirmation",
        sql: include_str!("../../migrations/0002_repository_owner_confirmation.sql"),
    },
    Migration {
        version: 3,
        name: "name_activation",
        sql: include_str!("../../migrations/0003_name_activation.sql"),
    },
    Migration {
        version: 4,
        name: "attested_signer",
        sql: include_str!("../../migrations/0004_attested_signer.sql"),
    },
    Migration {
        version: 5,
        name: "family_membership",
        sql: include_str!("../../migrations/0005_family_membership.sql"),
    },
    Migration {
        version: 6,
        name: "evidence_full_check",
        sql: include_str!("../../migrations/0006_evidence_full_check.sql"),
    },
    Migration {
        version: 7,
        name: "evidence_bundle",
        sql: include_str!("../../migrations/0007_evidence_bundle.sql"),
    },
];

/// Why the state database could not be opened, migrated, backed up, or
/// restored. Messages carry no SQL text and no row data.
#[derive(Debug)]
pub enum StateError {
    /// The runtime SQLite library is older than the ADR-020 floor.
    SqliteTooOld {
        found: i32,
    },
    /// A path is a symlink, not a regular file or directory, or its
    /// directory is writable by group or others.
    UnsafePath {
        path: PathBuf,
        problem: &'static str,
    },
    /// Another process already owns this database.
    AlreadyOwned,
    /// The database was written by a newer Pakomichi.
    NewerSchema {
        found: i64,
    },
    /// The recorded migrations do not match this build.
    MigrationRecordMismatch,
    /// A backup or restore source failed validation.
    InvalidDatabase {
        problem: &'static str,
    },
    /// The backup destination already exists.
    TargetExists,
    /// The schema refused an owner confirmation (migration 0002); `rule`
    /// is the refusing trigger's message.
    OwnerConfirmationRefused {
        rule: &'static str,
    },
    /// A stored row does not parse as this build writes it.
    CorruptRow {
        table: &'static str,
        problem: &'static str,
    },
    /// An administrative operation is still `planned`: its outcome decides
    /// what the files hold, so it is recovered before anything new starts.
    OperationUnfinished,
    /// The operation is not `planned` (unknown, or already finished).
    OperationNotPlanned,
    /// The name is activated in another source: one publisher per name.
    NameActivatedElsewhere,
    /// The repository is already a source, under this identifier.
    SourceExists {
        id: String,
    },
    /// A family revision older than the stored one.
    StaleRevision,
    /// The evidence is not recorded for this source.
    UnknownEvidence,
    /// Evidence names at most 16 bundles (ADR-030, migration 0007).
    TooManyBundles,
    Sqlite(rusqlite::Error),
    Io(io::Error),
}

impl StateError {
    /// Only an unsuitable platform has a reason code; every other failure
    /// is an internal fault of the local installation.
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::SqliteTooOld { .. } => Some(ReasonCode::EPlatformUnsupported),
            _ => None,
        }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqliteTooOld { found } => write!(
                formatter,
                "system SQLite {} is older than the required {}",
                format_version(*found),
                format_version(MIN_SQLITE_VERSION)
            ),
            Self::UnsafePath { path, problem } => {
                write!(formatter, "unsafe state path {}: {problem}", path.display())
            }
            Self::AlreadyOwned => formatter.write_str("another process owns the state database"),
            Self::NewerSchema { found } => write!(
                formatter,
                "state database schema {found} is newer than this build ({SCHEMA_VERSION})"
            ),
            Self::MigrationRecordMismatch => {
                formatter.write_str("recorded migrations do not match this build")
            }
            Self::InvalidDatabase { problem } => write!(formatter, "invalid database: {problem}"),
            Self::TargetExists => formatter.write_str("backup destination already exists"),
            Self::OwnerConfirmationRefused { rule } => {
                write!(formatter, "owner confirmation refused: {rule}")
            }
            Self::CorruptRow { table, problem } => write!(formatter, "{table}: {problem}"),
            Self::OperationUnfinished => {
                formatter.write_str("an administrative operation is unfinished; recover it first")
            }
            Self::OperationNotPlanned => {
                formatter.write_str("the operation is unknown or already finished")
            }
            Self::NameActivatedElsewhere => {
                formatter.write_str("the name is activated in another source")
            }
            Self::SourceExists { id } => write!(formatter, "the repository is already source {id}"),
            Self::StaleRevision => formatter.write_str("the family has a newer revision"),
            Self::UnknownEvidence => {
                formatter.write_str("the evidence is not recorded for this source")
            }
            Self::TooManyBundles => formatter.write_str("evidence names at most 16 bundles"),
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<rusqlite::Error> for StateError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<io::Error> for StateError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Refuses a SQLite library older than [`MIN_SQLITE_VERSION`].
pub const fn check_sqlite_version(number: i32) -> Result<(), StateError> {
    if number < MIN_SQLITE_VERSION {
        return Err(StateError::SqliteTooOld { found: number });
    }
    Ok(())
}

/// The open state database. There is exactly one per installation: opening
/// takes an exclusive lock next to the database, so a second owner is
/// refused instead of writing concurrently.
pub struct StateOwner {
    connection: Connection,
    path: PathBuf,
    _lock: File,
}

impl fmt::Debug for StateOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateOwner")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl StateOwner {
    /// Checks the SQLite library, takes the owner lock, creates the
    /// database with mode 0600 if it does not exist, configures the
    /// connection, and applies pending migrations.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        check_sqlite_version(rusqlite::version_number())?;
        check_directory(path)?;
        let lock = take_lock(&lock_path(path))?;
        prepare_file(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure(&connection)?;
        let mut owner = Self {
            connection,
            path: path.to_owned(),
            _lock: lock,
        };
        owner.migrate()?;
        Ok(owner)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The connection, for the crate's own state modules only.
    pub(crate) fn connection(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub fn schema_version(&self) -> Result<i64, StateError> {
        Ok(user_version(&self.connection)?)
    }

    fn migrate(&mut self) -> Result<(), StateError> {
        let current = user_version(&self.connection)?;
        if current > SCHEMA_VERSION {
            return Err(StateError::NewerSchema { found: current });
        }
        for migration in MIGRATIONS
            .iter()
            .filter(|migration| migration.version > current)
        {
            if let Err(error) = self.connection.execute_batch(migration.sql) {
                // A failed statement inside the migration's own transaction
                // leaves it open; nothing of it may stay.
                if !self.connection.is_autocommit() {
                    let _ = self.connection.execute_batch("ROLLBACK");
                }
                return Err(error.into());
            }
        }
        verify_schema(&self.connection)
    }

    /// Copies the database to `destination`, a new file with mode 0600,
    /// through SQLite's online backup API, then validates the copy.
    pub fn backup_to(&self, destination: &Path) -> Result<(), StateError> {
        check_directory(destination)?;
        if destination.symlink_metadata().is_ok() {
            return Err(StateError::TargetExists);
        }
        create_private_file(destination)?;
        let result = (|| -> Result<(), StateError> {
            let mut target = Connection::open_with_flags(
                destination,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?;
            copy_all(&self.connection, &mut target)?;
            validate(&target)?;
            drop(target);
            File::open(destination)?.sync_all()?;
            sync_directory(destination)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(destination);
        }
        result
    }

    /// Replaces the contents of the database with `source`, after `source`
    /// has been opened read-only (never created) and validated. On any
    /// failure before the copy the database is untouched.
    pub fn restore_from(&mut self, source: &Path) -> Result<(), StateError> {
        let metadata = source.symlink_metadata()?;
        if !metadata.file_type().is_file() {
            return Err(unsafe_path(source, "not a regular file"));
        }
        let source = Connection::open_with_flags(
            source,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        validate(&source)?;
        copy_all(&source, &mut self.connection)?;
        configure(&self.connection)?;
        validate(&self.connection)
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn unsafe_path(path: &Path, problem: &'static str) -> StateError {
    StateError::UnsafePath {
        path: path.to_owned(),
        problem,
    }
}

/// The directory of `path` must be a real directory that only its owner
/// can write; otherwise another user could swap the files.
fn check_directory(path: &Path) -> Result<(), StateError> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let metadata = directory.symlink_metadata()?;
    if !metadata.file_type().is_dir() {
        return Err(unsafe_path(directory, "not a directory"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(unsafe_path(directory, "writable by group or others"));
    }
    Ok(())
}

fn take_lock(path: &Path) -> Result<File, StateError> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(std::fs::TryLockError::WouldBlock) => Err(StateError::AlreadyOwned),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

/// An existing database must be a regular file, not a symlink; a missing
/// one is created empty with mode 0600 so that SQLite never creates it
/// with the process umask.
fn prepare_file(path: &Path) -> Result<(), StateError> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_file() => {
            if metadata.mode() & 0o077 != 0 {
                return Err(unsafe_path(path, "readable or writable by group or others"));
            }
            Ok(())
        }
        Ok(_) => Err(unsafe_path(path, "not a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_private_file(path)?;
            sync_directory(path)
        }
        Err(error) => Err(error.into()),
    }
}

fn create_private_file(path: &Path) -> Result<(), StateError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StateError> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(directory)?.sync_all()?;
    Ok(())
}

/// Connection settings: foreign keys enforced, defensive mode on (no
/// writable schema, no shadow-table tampering), schema content not trusted
/// to call functions, WAL with full sync so a committed transaction
/// survives a power loss (R-004).
fn configure(connection: &Connection) -> Result<(), StateError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StateError::InvalidDatabase {
            problem: "WAL journal mode is not available",
        });
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    let foreign_keys: bool =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if !foreign_keys {
        return Err(StateError::InvalidDatabase {
            problem: "foreign keys cannot be enabled",
        });
    }
    Ok(())
}

fn user_version(connection: &Connection) -> rusqlite::Result<i64> {
    connection.pragma_query_value(None, "user_version", |row| row.get(0))
}

/// The schema version and the migration records must be exactly this
/// build's.
fn verify_schema(connection: &Connection) -> Result<(), StateError> {
    if user_version(connection)? != SCHEMA_VERSION {
        return Err(StateError::MigrationRecordMismatch);
    }
    let mut statement =
        connection.prepare("SELECT version, name FROM schema_migrations ORDER BY version")?;
    let recorded: Vec<(i64, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let expected: Vec<(i64, String)> = MIGRATIONS
        .iter()
        .map(|migration| (migration.version, migration.name.to_owned()))
        .collect();
    if recorded != expected {
        return Err(StateError::MigrationRecordMismatch);
    }
    Ok(())
}

/// A database is acceptable as a backup or restore source only when it
/// passes SQLite's integrity and foreign-key checks and carries exactly
/// this build's schema.
fn validate(connection: &Connection) -> Result<(), StateError> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(StateError::InvalidDatabase {
            problem: "integrity check failed",
        });
    }
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.exists([])? {
        return Err(StateError::InvalidDatabase {
            problem: "foreign key check failed",
        });
    }
    let version = user_version(connection)?;
    if version > SCHEMA_VERSION {
        return Err(StateError::NewerSchema { found: version });
    }
    verify_schema(connection).map_err(|error| match error {
        StateError::MigrationRecordMismatch => StateError::InvalidDatabase {
            problem: "schema does not match this build",
        },
        other => other,
    })
}

/// Copies every page in one step. The owner is the only writer, so the
/// source cannot change underneath; a busy or locked database is an error,
/// never a wait without end.
fn copy_all(source: &Connection, target: &mut Connection) -> Result<(), StateError> {
    let backup = Backup::new_with_names(source, MAIN_DB, target, MAIN_DB)?;
    match backup.step(-1)? {
        StepResult::Done => Ok(()),
        _ => Err(StateError::InvalidDatabase {
            problem: "database busy during copy",
        }),
    }
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
