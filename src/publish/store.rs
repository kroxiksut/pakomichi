// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generation store on disk (ADR-008, ADR-024 points 1–3, R-004).
//!
//! Layout under the publish root:
//!
//! ```text
//! lock                               single publisher
//! tmp/                               staging; emptied when opened
//! ids/<source>.<backend>             last generation number allocated
//! repos/<repo>/current               "<n>\n", replaced atomically
//! repos/<repo>/generations/<n>.manifest
//! repos/<repo>/generations/<n>.failed   written, never made current
//! ```
//!
//! Files are the source of truth; SQLite rows are rebuilt by
//! [`GenerationStore::reconcile`].

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::manifest::{
    Backend, Entry, GenerationId, GenerationMeta, Manifest, ManifestError, PathClass, RepoName,
    RepoPath, SourceId, check_immutable_paths,
};
pub use super::reader::GenerationInfo;
use super::reader::{PublishReader, read_small, unsafe_entry, within_window};
use crate::cas::{CasError, ExpectedObject, GcRoots, Store as CasStore};
use crate::state::{StateError, StateOwner};

/// Why publishing, reading, or reconciling generations failed.
#[derive(Debug)]
pub enum PublishError {
    Manifest(ManifestError),
    /// An object the generation references is missing or corrupt in the CAS.
    Object(CasError),
    /// A file of the store is not what it must be (symlink, wrong kind,
    /// unsafe permissions, unparsable pointer).
    UnsafeEntry {
        path: PathBuf,
        problem: &'static str,
    },
    /// A manifest on disk does not match its location or does not parse.
    CorruptManifest {
        path: PathBuf,
    },
    /// Another publisher holds the store.
    AlreadyLocked,
    /// `current` would move to an older or equal generation.
    Rollback {
        current: GenerationId,
        requested: GenerationId,
    },
    /// The generation-number space of the source and backend is exhausted.
    IdsExhausted,
    /// The requested generation does not exist.
    UnknownGeneration,
    State(StateError),
    Io(io::Error),
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(formatter, "{error}"),
            Self::Object(error) => write!(formatter, "object: {error}"),
            Self::UnsafeEntry { path, problem } => {
                write!(
                    formatter,
                    "unsafe store entry {}: {problem}",
                    path.display()
                )
            }
            Self::CorruptManifest { path } => {
                write!(formatter, "corrupt manifest {}", path.display())
            }
            Self::AlreadyLocked => formatter.write_str("another publisher holds the store"),
            Self::Rollback { current, requested } => write!(
                formatter,
                "current is generation {current}; refusing to move it to {requested}"
            ),
            Self::IdsExhausted => formatter.write_str("generation numbers exhausted"),
            Self::UnknownGeneration => formatter.write_str("unknown generation"),
            Self::State(error) => write!(formatter, "state database: {error}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for PublishError {}

impl From<ManifestError> for PublishError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<io::Error> for PublishError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<StateError> for PublishError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<rusqlite::Error> for PublishError {
    fn from(error: rusqlite::Error) -> Self {
        Self::State(StateError::Sqlite(error))
    }
}

/// What opening the store repaired.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Recovery {
    /// Staging files left by a killed publisher and removed.
    pub removed_staging: usize,
    /// Generations written but never made current, now marked failed.
    pub failed: Vec<(RepoName, GenerationId)>,
}

/// What `reconcile` wrote.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    pub rows: usize,
    /// Repositories whose source has no `forge_repository` row.
    pub skipped_repos: Vec<RepoName>,
    /// Rows whose manifest is gone, now `collected`.
    pub collected_rows: usize,
}

/// The single writer of the publish root.
pub struct GenerationStore {
    root: PathBuf,
    reader: PublishReader,
    _lock: File,
}

impl fmt::Debug for GenerationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl GenerationStore {
    /// Opens or creates the store, takes the publisher lock, empties the
    /// staging directory, and marks generations that a killed publisher
    /// wrote but never made current as failed. Their numbers stay used.
    pub fn open(root: &Path) -> Result<(Self, Recovery), PublishError> {
        ensure_dir(root)?;
        for directory in ["tmp", "ids", "repos"] {
            ensure_dir(&root.join(directory))?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root.join("lock"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Err(PublishError::AlreadyLocked),
            Err(fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let store = Self {
            root: root.to_owned(),
            reader: PublishReader::uncached(root),
            _lock: lock,
        };
        let mut recovery = Recovery::default();
        for entry in fs::read_dir(store.root.join("tmp"))? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
                recovery.removed_staging += 1;
            }
        }
        for repo in store.repos()? {
            let current = store.current(&repo)?;
            for (id, failed) in store.manifest_files(&repo)? {
                if !failed && current.is_none_or(|current| id > current) {
                    let directory = store.generations_dir(&repo);
                    fs::rename(
                        directory.join(format!("{id}.manifest")),
                        directory.join(format!("{id}.failed")),
                    )?;
                    sync_dir(&directory)?;
                    recovery.failed.push((repo.clone(), id));
                }
            }
        }
        Ok((store, recovery))
    }

    fn repo_dir(&self, repo: &RepoName) -> PathBuf {
        self.reader.repo_dir(repo)
    }

    fn generations_dir(&self, repo: &RepoName) -> PathBuf {
        self.reader.generations_dir(repo)
    }

    fn ids_path(&self, source: &SourceId, backend: Backend) -> PathBuf {
        self.root
            .join("ids")
            .join(format!("{}.{}", source.as_str(), backend.as_str()))
    }

    /// The read-only view the repository reader also uses.
    pub fn reader(&self) -> &PublishReader {
        &self.reader
    }

    /// Every repository with a directory in the store.
    pub fn repos(&self) -> Result<Vec<RepoName>, PublishError> {
        self.reader.repos()
    }

    /// The current generation of `repo`, if it has one.
    pub fn current(&self, repo: &RepoName) -> Result<Option<GenerationId>, PublishError> {
        self.reader.current(repo)
    }

    /// Manifest files of `repo`: `(id, failed)`, ascending.
    fn manifest_files(&self, repo: &RepoName) -> Result<Vec<(GenerationId, bool)>, PublishError> {
        self.reader.manifest_files(repo)
    }

    /// Reads and checks one manifest: it must parse and name its own
    /// repository and generation.
    pub fn load(&self, repo: &RepoName, id: GenerationId) -> Result<Manifest, PublishError> {
        self.reader.load_file(repo, id, false)
    }

    fn load_file(
        &self,
        repo: &RepoName,
        id: GenerationId,
        failed: bool,
    ) -> Result<Manifest, PublishError> {
        self.reader.load_file(repo, id, failed)
    }

    /// Published generations of `repo` (current and retained), ascending,
    /// with their retirement times.
    pub fn generations(&self, repo: &RepoName) -> Result<Vec<GenerationInfo>, PublishError> {
        self.reader.generations(repo)
    }

    /// Publishes a new generation of `meta.repo` and makes it current.
    ///
    /// Every object must already be in the CAS and is fully verified. The
    /// number is allocated and recorded before the manifest is written, so
    /// a crash burns it instead of reusing it. Content-addressed paths must
    /// keep their bytes against every retained generation. The manifest is
    /// written once, then `current` is replaced atomically; the reader sees
    /// either the old or the new generation, never a mix (N-015).
    pub fn publish(
        &mut self,
        meta: GenerationMeta,
        objects: Vec<(RepoPath, ExpectedObject)>,
        cas: &CasStore,
        now: SystemTime,
    ) -> Result<GenerationId, PublishError> {
        for (_, object) in &objects {
            cas.verify(*object).map_err(PublishError::Object)?;
        }
        let repo = meta.repo.clone();
        ensure_dir(&self.repo_dir(&repo))?;
        ensure_dir(&self.generations_dir(&repo))?;
        let current = self.current(&repo)?;
        let id = self.allocate(&meta.source, meta.backend, &repo)?;
        if let Some(current) = current
            && id <= current
        {
            return Err(PublishError::Rollback {
                current,
                requested: id,
            });
        }
        let created_at = now
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let manifest = Manifest::new(meta, id, created_at, objects)?;
        let retained: Vec<Manifest> = self
            .generations(&repo)?
            .into_iter()
            .map(|info| self.load(&repo, info.id))
            .collect::<Result<_, _>>()?;
        check_immutable_paths(&manifest, &retained)?;

        let directory = self.generations_dir(&repo);
        self.write_new(
            &directory,
            &format!("{id}.manifest"),
            manifest.to_text().as_bytes(),
        )?;
        self.replace(
            &self.repo_dir(&repo),
            "current",
            format!("{id}\n").as_bytes(),
        )?;
        Ok(id)
    }

    /// The next number for the source and backend: above the recorded one
    /// and above every manifest of `repo`, recorded durably before use.
    fn allocate(
        &self,
        source: &SourceId,
        backend: Backend,
        repo: &RepoName,
    ) -> Result<GenerationId, PublishError> {
        let path = self.ids_path(source, backend);
        let recorded = match read_small(&path, 32) {
            Ok(text) => text
                .strip_suffix('\n')
                .and_then(|number| number.parse::<u64>().ok())
                .ok_or_else(|| unsafe_entry(&path, "invalid generation counter"))?,
            Err(PublishError::Io(error)) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        let highest_file = self
            .manifest_files(repo)?
            .last()
            .map_or(0, |(id, _)| id.get());
        let next = recorded
            .max(highest_file)
            .checked_add(1)
            .and_then(GenerationId::new)
            .ok_or(PublishError::IdsExhausted)?;
        self.replace(
            &self.root.join("ids"),
            &path_name(&path),
            format!("{next}\n").as_bytes(),
        )?;
        Ok(next)
    }

    /// Looks a path up the way the repository reader serves it (see
    /// [`PublishReader::resolve`]).
    pub fn resolve(
        &self,
        repo: &RepoName,
        path: &RepoPath,
        now: SystemTime,
        retention: Duration,
    ) -> Result<Option<(GenerationId, Entry)>, PublishError> {
        self.reader.resolve(repo, path, now, retention)
    }

    /// The GC roots of every repository: the current generation and the
    /// retired ones inside the retention window (ADR-024 point 2).
    pub fn gc_roots(&self, now: SystemTime, retention: Duration) -> Result<GcRoots, PublishError> {
        let mut roots = GcRoots::new(now, retention);
        for repo in self.repos()? {
            for info in self.generations(&repo)? {
                let manifest = self.load(&repo, info.id)?;
                roots.add_generation(info.retired_at, manifest.objects());
            }
        }
        Ok(roots)
    }

    /// Removes the manifests of retired generations past the window and of
    /// failed generations. The current generation is never removed; the
    /// numbers stay used.
    pub fn collect(
        &mut self,
        now: SystemTime,
        retention: Duration,
    ) -> Result<Vec<(RepoName, GenerationId)>, PublishError> {
        let mut removed = Vec::new();
        for repo in self.repos()? {
            let directory = self.generations_dir(&repo);
            for info in self.generations(&repo)? {
                if info.retired_at.is_some() && !within_window(info.retired_at, now, retention) {
                    fs::remove_file(directory.join(format!("{}.manifest", info.id)))?;
                    removed.push((repo.clone(), info.id));
                }
            }
            for (id, failed) in self.manifest_files(&repo)? {
                if failed {
                    fs::remove_file(directory.join(format!("{id}.failed")))?;
                    removed.push((repo.clone(), id));
                }
            }
            sync_dir(&directory)?;
        }
        Ok(removed)
    }

    /// Rebuilds the `snapshot` rows from the manifests (ADR-013): the
    /// current generation is `published`, retained ones `retired`, failed
    /// ones `failed`, and rows whose manifest is gone `collected`.
    /// `snapshot_artifact` rows belong to the index publishers.
    pub fn reconcile(&self, state: &mut StateOwner) -> Result<ReconcileReport, PublishError> {
        let mut report = ReconcileReport::default();
        let connection = state.connection();
        let transaction = connection.transaction()?;
        let mut present = Vec::new();
        for repo in self.repos()? {
            let current = self.current(&repo)?;
            let mut rows = Vec::new();
            for (id, failed) in self.manifest_files(&repo)? {
                let manifest = self.load_file(&repo, id, failed)?;
                let row_state = if failed {
                    "failed"
                } else if Some(id) == current {
                    "published"
                } else {
                    "retired"
                };
                rows.push((manifest, row_state));
            }
            let Some((first, _)) = rows.first() else {
                continue;
            };
            let known: bool = transaction.query_row(
                "SELECT EXISTS (SELECT 1 FROM forge_repository WHERE id = ?1)",
                [first.meta.source.as_str()],
                |row| row.get(0),
            )?;
            if !known {
                report.skipped_repos.push(repo.clone());
                continue;
            }
            for (manifest, row_state) in rows {
                let id = snapshot_id(&repo, manifest.generation);
                let details = serde_json::json!({
                    "repo": repo.as_str(),
                    "entries": manifest.len(),
                })
                .to_string();
                let signature = signature_digest(&manifest);
                transaction.execute(
                    "INSERT INTO snapshot (id, generation, source_id, native_backend, manifests_json, \
                     manifest_sha256, signature_sha256, valid_from, valid_until, state) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                     ON CONFLICT(id) DO UPDATE SET state = excluded.state, \
                     manifest_sha256 = excluded.manifest_sha256, \
                     signature_sha256 = excluded.signature_sha256, \
                     manifests_json = excluded.manifests_json",
                    rusqlite::params![
                        id,
                        i64::try_from(manifest.generation.get()).unwrap_or(i64::MAX),
                        manifest.meta.source.as_str(),
                        manifest.meta.backend.as_str(),
                        details,
                        manifest.digest().to_hex(),
                        signature,
                        manifest.meta.valid_from.as_str(),
                        manifest.meta.valid_until.as_str(),
                        row_state,
                    ],
                )?;
                present.push(id);
                report.rows += 1;
            }
        }
        let mut statement = transaction
            .prepare("SELECT id FROM snapshot WHERE state NOT IN ('collected', 'building')")?;
        let known: Vec<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        drop(statement);
        for id in known.into_iter().filter(|id| !present.contains(id)) {
            transaction.execute(
                "UPDATE snapshot SET state = 'collected' WHERE id = ?1",
                [&id],
            )?;
            report.collected_rows += 1;
        }
        transaction.commit()?;
        Ok(report)
    }

    /// Writes a file that must not exist yet: staging file in `tmp/`,
    /// `fsync`, rename, directory `fsync`.
    fn write_new(&self, directory: &Path, name: &str, bytes: &[u8]) -> Result<(), PublishError> {
        let target = directory.join(name);
        if target.symlink_metadata().is_ok() {
            return Err(unsafe_entry(&target, "already exists"));
        }
        self.replace(directory, name, bytes)
    }

    /// Replaces `directory/name` atomically with `bytes`, mode 0640.
    fn replace(&self, directory: &Path, name: &str, bytes: &[u8]) -> Result<(), PublishError> {
        let staging = self
            .root
            .join("tmp")
            .join(format!("{name}.{}.part", std::process::id()));
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&staging)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&staging, directory.join(name))?;
            sync_dir(directory)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&staging);
        }
        result.map_err(PublishError::Io)
    }
}

/// `snapshot.id`: `<repo>:<generation>`.
pub fn snapshot_id(repo: &RepoName, generation: GenerationId) -> String {
    format!("{}:{}", repo.as_str(), generation)
}

/// The digest of the signed metadata file of a generation, if it has one:
/// `InRelease` for APT, `repomd.xml.asc` for DNF.
fn signature_digest(manifest: &Manifest) -> Option<String> {
    manifest
        .entries()
        .find(|entry| {
            let name = entry.path.as_str().rsplit('/').next().unwrap_or_default();
            entry.class == PathClass::Mutable && matches!(name, "InRelease" | "repomd.xml.asc")
        })
        .map(|entry| entry.object.sha256.to_hex())
}

fn path_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Creates `path` as a 0750 directory, or checks an existing one: a real
/// directory, not writable by group or others.
fn ensure_dir(path: &Path) -> Result<(), PublishError> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_dir() => {
            if metadata.mode() & 0o022 != 0 {
                return Err(unsafe_entry(path, "writable by group or others"));
            }
            Ok(())
        }
        Ok(_) => Err(unsafe_entry(path, "not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
