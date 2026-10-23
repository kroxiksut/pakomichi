// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only view of the generation store.
//!
//! The repository reader (P3-005a) and the single publisher both look
//! generations up through this type, so the serving rule exists once. The
//! reader takes no lock and changes nothing: the publisher replaces
//! `current` atomically and writes each manifest once, so a reader sees one
//! complete generation or the next one, never a mix (N-015).

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::manifest::{Entry, GenerationId, Manifest, PathClass, RepoName, RepoPath};
use super::store::PublishError;

/// Largest manifest file read back.
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

/// Parsed manifests kept by a caching reader. Published manifests never
/// change, so an entry stays valid until its file is collected, after which
/// it is no longer listed and therefore never consulted.
const MANIFEST_CACHE_LIMIT: usize = 64;

type ManifestCache = HashMap<(RepoName, GenerationId), Arc<Manifest>>;

/// Read-only access to a publish root.
pub struct PublishReader {
    root: PathBuf,
    cache: Option<Mutex<ManifestCache>>,
}

impl std::fmt::Debug for PublishReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishReader")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl PublishReader {
    /// Opens an existing store for reading, with a manifest cache. The root
    /// and its `repos` directory must be real directories that neither group
    /// nor others can write.
    pub fn open(root: &Path) -> Result<Self, PublishError> {
        check_dir(root)?;
        check_dir(&root.join("repos"))?;
        Ok(Self {
            root: root.to_owned(),
            cache: Some(Mutex::new(HashMap::new())),
        })
    }

    /// The publisher's view: no cache, because the publisher also removes
    /// manifests and runs for a long time.
    pub(super) fn uncached(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            cache: None,
        }
    }

    pub(super) fn repo_dir(&self, repo: &RepoName) -> PathBuf {
        self.root.join("repos").join(repo.as_str())
    }

    pub(super) fn generations_dir(&self, repo: &RepoName) -> PathBuf {
        self.repo_dir(repo).join("generations")
    }

    /// Every repository with a directory in the store.
    pub fn repos(&self) -> Result<Vec<RepoName>, PublishError> {
        let mut repos = Vec::new();
        for entry in fs::read_dir(self.root.join("repos"))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str().and_then(|name| RepoName::new(name).ok()) else {
                return Err(unsafe_entry(&entry.path(), "not a repository name"));
            };
            if !entry.file_type()?.is_dir() {
                return Err(unsafe_entry(&entry.path(), "not a directory"));
            }
            repos.push(name);
        }
        repos.sort();
        Ok(repos)
    }

    /// The current generation of `repo`, if it has one.
    pub fn current(&self, repo: &RepoName) -> Result<Option<GenerationId>, PublishError> {
        let path = self.repo_dir(repo).join("current");
        let text = match read_small(&path, 32) {
            Ok(text) => text,
            Err(PublishError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        text.strip_suffix('\n')
            .and_then(|number| number.parse::<u64>().ok())
            .filter(|number| number.to_string() == text.trim_end())
            .and_then(GenerationId::new)
            .map(Some)
            .ok_or_else(|| unsafe_entry(&path, "invalid current pointer"))
    }

    /// Manifest files of `repo`: `(id, failed)`, ascending.
    pub(super) fn manifest_files(
        &self,
        repo: &RepoName,
    ) -> Result<Vec<(GenerationId, bool)>, PublishError> {
        let directory = self.generations_dir(repo);
        let mut files = Vec::new();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(files),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let parsed = name.to_str().and_then(|name| {
                let (number, failed) = match name.split_once('.') {
                    Some((number, "manifest")) => (number, false),
                    Some((number, "failed")) => (number, true),
                    _ => return None,
                };
                let id = number.parse::<u64>().ok().and_then(GenerationId::new)?;
                (id.to_string() == number).then_some((id, failed))
            });
            match parsed {
                Some(file) if entry.file_type()?.is_file() => files.push(file),
                _ => {
                    return Err(unsafe_entry(
                        &entry.path(),
                        "unexpected entry in generations",
                    ));
                }
            }
        }
        files.sort();
        Ok(files)
    }

    /// Reads and checks one published manifest: it must parse and name its
    /// own repository and generation.
    pub fn load(&self, repo: &RepoName, id: GenerationId) -> Result<Arc<Manifest>, PublishError> {
        let key = (repo.clone(), id);
        if let Some(cache) = &self.cache
            && let Some(manifest) = lock(cache).get(&key)
        {
            return Ok(Arc::clone(manifest));
        }
        let manifest = Arc::new(self.load_file(repo, id, false)?);
        if let Some(cache) = &self.cache {
            let mut cache = lock(cache);
            if cache.len() >= MANIFEST_CACHE_LIMIT {
                cache.clear();
            }
            cache.insert(key, Arc::clone(&manifest));
        }
        Ok(manifest)
    }

    pub(super) fn load_file(
        &self,
        repo: &RepoName,
        id: GenerationId,
        failed: bool,
    ) -> Result<Manifest, PublishError> {
        let suffix = if failed { "failed" } else { "manifest" };
        let path = self.generations_dir(repo).join(format!("{id}.{suffix}"));
        let text = match read_small(&path, MAX_MANIFEST_BYTES) {
            Ok(text) => text,
            Err(PublishError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(PublishError::UnknownGeneration);
            }
            Err(error) => return Err(error),
        };
        let manifest = Manifest::parse(&text)
            .map_err(|_| PublishError::CorruptManifest { path: path.clone() })?;
        if manifest.meta.repo != *repo || manifest.generation != id {
            return Err(PublishError::CorruptManifest { path });
        }
        Ok(manifest)
    }

    /// Published generations of `repo` (current and retained), ascending,
    /// with their retirement times: a generation retires when the next one
    /// becomes current, at that one's creation time.
    pub fn generations(&self, repo: &RepoName) -> Result<Vec<GenerationInfo>, PublishError> {
        let Some(current) = self.current(repo)? else {
            return Ok(Vec::new());
        };
        let published: Vec<GenerationId> = self
            .manifest_files(repo)?
            .into_iter()
            .filter(|(id, failed)| !failed && *id <= current)
            .map(|(id, _)| id)
            .collect();
        let mut infos = Vec::with_capacity(published.len());
        for (index, id) in published.iter().enumerate() {
            let retired_at = match published.get(index + 1) {
                Some(next) => {
                    Some(UNIX_EPOCH + Duration::from_secs(self.load(repo, *next)?.created_at))
                }
                None => None,
            };
            infos.push(GenerationInfo {
                id: *id,
                retired_at,
            });
        }
        Ok(infos)
    }

    /// Looks a path up the way the repository reader serves it: a mutable
    /// path only from the current generation; a content-addressed path from
    /// the current generation or any retained one inside the window, newest
    /// first (R-004 G2, G5).
    pub fn resolve(
        &self,
        repo: &RepoName,
        path: &RepoPath,
        now: SystemTime,
        retention: Duration,
    ) -> Result<Option<(GenerationId, Entry)>, PublishError> {
        let generations = self.generations(repo)?;
        for (newest, info) in generations.iter().rev().enumerate() {
            if !within_window(info.retired_at, now, retention) {
                break;
            }
            let manifest = self.load(repo, info.id)?;
            if let Some(entry) = manifest.get(path) {
                if newest > 0 && entry.class == PathClass::Mutable {
                    return Ok(None);
                }
                return Ok(Some((info.id, entry.clone())));
            }
        }
        Ok(None)
    }
}

/// One published generation of a repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationInfo {
    pub id: GenerationId,
    /// When the next generation replaced it; `None` for the current one.
    pub retired_at: Option<SystemTime>,
}

fn lock(cache: &Mutex<ManifestCache>) -> std::sync::MutexGuard<'_, ManifestCache> {
    // A poisoned cache holds only immutable manifests; keep using it.
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(super) fn within_window(
    retired_at: Option<SystemTime>,
    now: SystemTime,
    retention: Duration,
) -> bool {
    match retired_at {
        None => true,
        Some(retired) => retired
            .checked_add(retention)
            .is_none_or(|expiry| expiry > now),
    }
}

pub(super) fn unsafe_entry(path: &Path, problem: &'static str) -> PublishError {
    PublishError::UnsafeEntry {
        path: path.to_owned(),
        problem,
    }
}

/// Checks an existing directory: a real directory (not a symlink), not
/// writable by group or others.
fn check_dir(path: &Path) -> Result<(), PublishError> {
    let metadata = path.symlink_metadata()?;
    if !metadata.file_type().is_dir() {
        return Err(unsafe_entry(path, "not a directory"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(unsafe_entry(path, "writable by group or others"));
    }
    Ok(())
}

/// Reads a small regular file without following a symlink.
pub(super) fn read_small(path: &Path, limit: u64) -> Result<String, PublishError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                unsafe_entry(path, "symlink")
            } else {
                PublishError::Io(error)
            }
        })?;
    if !file.metadata()?.file_type().is_file() {
        return Err(unsafe_entry(path, "not a regular file"));
    }
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(unsafe_entry(path, "too large"));
    }
    Ok(text)
}
