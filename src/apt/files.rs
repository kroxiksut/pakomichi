// SPDX-License-Identifier: MIT OR Apache-2.0

//! Planning and applying changes to the APT files Pakomichi owns.
//!
//! Only the paths [`render`](super::config::render) names are touched, and
//! only when their bytes are the ones Pakomichi last wrote (`Known`, kept
//! by the caller in `AdminOperation`). A file someone else changed, removed,
//! or created under our name is drift: it is reported and never
//! overwritten or deleted. A file that already holds exactly the desired
//! bytes is adopted, which is how an apply interrupted after its rename
//! but before its record is finished.
//!
//! Order: writes go keyring, preferences, sources; removals go sources,
//! preferences, keyring. A source therefore never appears before the pins
//! of its activated names and never outlives them, so an `apt upgrade`
//! between two steps cannot move an activated name to another publisher.
//! Each write is staged in the target's directory under a name APT ignores
//! silently (`.<name>.pakomichi-new~`), synced, and renamed into place;
//! the directory is synced after every rename and unlink.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::config::{FileKind, ManagedFile};
use crate::cas::Sha256Digest;

const STAGING_SUFFIX: &str = ".pakomichi-new~";
/// Largest managed file read back (a keyring or a sources file).
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// The digests Pakomichi last wrote, by absolute path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Known(pub BTreeMap<String, Sha256Digest>);

/// A file that is not as Pakomichi left it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Drift {
    /// Our file now has other bytes, or is gone.
    Changed {
        path: String,
        expected: Sha256Digest,
        found: Option<Sha256Digest>,
    },
    /// A file at one of our paths that Pakomichi did not write, or that is
    /// not a regular file.
    Foreign { path: String },
}

/// One step of a plan, with what the target held when it was planned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    Write {
        file: ManagedFile,
        before: Option<Sha256Digest>,
    },
    Remove {
        kind: FileKind,
        path: String,
        before: Sha256Digest,
    },
}

impl Change {
    pub fn path(&self) -> &str {
        match self {
            Self::Write { file, .. } => &file.path,
            Self::Remove { path, .. } => path,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub drift: Vec<Drift>,
    /// Files that already hold the desired bytes but were not recorded.
    pub adopted: Vec<(String, Sha256Digest)>,
}

#[derive(Debug)]
pub enum ApplyError {
    Io(io::Error),
    /// The plan has drift; nothing is applied until it is resolved.
    Drift(Vec<Drift>),
    /// A target changed between planning and applying.
    Raced {
        path: String,
    },
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Drift(drift) => write!(
                formatter,
                "{} files are not as Pakomichi left them",
                drift.len()
            ),
            Self::Raced { path } => write!(formatter, "{path} changed while it was being applied"),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<io::Error> for ApplyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn under(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

/// The digest of a regular file at `path`, `None` when nothing is there.
/// A symlink or any other kind of entry is an error the caller turns into
/// drift.
fn observe(path: &Path) -> io::Result<Option<Sha256Digest>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::other("file too large"));
    }
    Ok(Some(Sha256Digest::of(&bytes)))
}

fn write_order(kind: FileKind) -> u8 {
    match kind {
        FileKind::Keyring => 0,
        FileKind::Preferences => 1,
        FileKind::Sources => 2,
    }
}

fn kind_of(path: &str) -> FileKind {
    if path.ends_with(".sources") {
        FileKind::Sources
    } else if path.ends_with(".gpg") {
        FileKind::Keyring
    } else {
        FileKind::Preferences
    }
}

/// Compares the desired files with what is under `root` and what was
/// last written.
pub fn plan(root: &Path, desired: &[ManagedFile], known: &Known) -> Plan {
    let mut plan = Plan::default();
    let mut writes = Vec::new();
    for file in desired {
        let target = under(root, &file.path);
        let wanted = Sha256Digest::of(&file.bytes);
        let recorded = known.0.get(&file.path).copied();
        match (observe(&target), recorded) {
            (Err(_), _) => plan.drift.push(Drift::Foreign {
                path: file.path.clone(),
            }),
            (Ok(found), _) if found == Some(wanted) => {
                if recorded != Some(wanted) {
                    plan.adopted.push((file.path.clone(), wanted));
                }
            }
            (Ok(None), None) => writes.push(Change::Write {
                file: file.clone(),
                before: None,
            }),
            (Ok(Some(found)), Some(expected)) if found == expected => writes.push(Change::Write {
                file: file.clone(),
                before: Some(found),
            }),
            (Ok(found), Some(expected)) => plan.drift.push(Drift::Changed {
                path: file.path.clone(),
                expected,
                found,
            }),
            (Ok(Some(_)), None) => plan.drift.push(Drift::Foreign {
                path: file.path.clone(),
            }),
        }
    }
    let mut removals = Vec::new();
    for (path, expected) in &known.0 {
        if desired.iter().any(|file| &file.path == path) {
            continue;
        }
        match observe(&under(root, path)) {
            Ok(None) => {}
            Ok(Some(found)) if found == *expected => removals.push(Change::Remove {
                kind: kind_of(path),
                path: path.clone(),
                before: found,
            }),
            Ok(found) => plan.drift.push(Drift::Changed {
                path: path.clone(),
                expected: *expected,
                found,
            }),
            Err(_) => plan.drift.push(Drift::Foreign { path: path.clone() }),
        }
    }
    writes.sort_by_key(|change| match change {
        Change::Write { file, .. } => write_order(file.kind),
        Change::Remove { .. } => u8::MAX,
    });
    removals.sort_by_key(|change| match change {
        Change::Remove { kind, .. } => u8::MAX - write_order(*kind),
        Change::Write { .. } => 0,
    });
    plan.changes = writes;
    plan.changes.extend(removals);
    plan
}

fn sync_dir(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

fn staging_path(target: &Path) -> io::Result<PathBuf> {
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("target has no file name"))?;
    Ok(target.with_file_name(format!(".{name}{STAGING_SUFFIX}")))
}

/// Removes staging files an interrupted apply left next to our targets.
fn remove_staging(root: &Path, plan: &Plan, known: &Known) -> io::Result<()> {
    let paths = plan
        .changes
        .iter()
        .map(Change::path)
        .chain(known.0.keys().map(String::as_str));
    for path in paths {
        let staging = staging_path(&under(root, path))?;
        match fs::remove_file(&staging) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Applies one change; `known` records it as soon as it is durable.
pub fn apply_change(root: &Path, change: &Change, known: &mut Known) -> Result<(), ApplyError> {
    let target = under(root, change.path());
    let raced = || ApplyError::Raced {
        path: change.path().to_owned(),
    };
    match change {
        Change::Write { file, before } => {
            if observe(&target).map_err(|_| raced())? != *before {
                return Err(raced());
            }
            let directory = target.parent().ok_or_else(raced)?;
            DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(directory)?;
            let staging = staging_path(&target)?;
            let result = (|| -> io::Result<()> {
                let mut staged = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&staging)?;
                staged.write_all(&file.bytes)?;
                staged.sync_all()?;
                fs::rename(&staging, &target)?;
                sync_dir(directory)
            })();
            if let Err(error) = result {
                let _ = fs::remove_file(&staging);
                return Err(error.into());
            }
            known
                .0
                .insert(file.path.clone(), Sha256Digest::of(&file.bytes));
        }
        Change::Remove { path, before, .. } => {
            if observe(&target).map_err(|_| raced())? != Some(*before) {
                return Err(raced());
            }
            fs::remove_file(&target)?;
            if let Some(directory) = target.parent() {
                sync_dir(directory)?;
            }
            known.0.remove(path);
        }
    }
    Ok(())
}

/// Applies a plan in order. A plan with drift applies nothing. On an error
/// `known` holds every change that was completed.
pub fn apply(root: &Path, plan: &Plan, known: &mut Known) -> Result<(), ApplyError> {
    apply_with(root, plan, known, &mut |_, _| Ok(()))
}

/// [`apply`] with `before` called ahead of every change: an error from it
/// stops the plan there, as a failed write would. Tests use it to stop at
/// each step.
pub(crate) fn apply_with(
    root: &Path,
    plan: &Plan,
    known: &mut Known,
    before: &mut dyn FnMut(usize, &Change) -> io::Result<()>,
) -> Result<(), ApplyError> {
    if !plan.drift.is_empty() {
        return Err(ApplyError::Drift(plan.drift.clone()));
    }
    remove_staging(root, plan, known)?;
    for (path, digest) in &plan.adopted {
        known.0.insert(path.clone(), *digest);
    }
    for (index, change) in plan.changes.iter().enumerate() {
        before(index, change)?;
        apply_change(root, change, known)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
