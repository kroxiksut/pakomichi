// SPDX-License-Identifier: MIT OR Apache-2.0

//! The on-disk content-addressed store.
//!
//! Layout under the root:
//!
//! ```text
//! lock          exclusive lock held by the single writer process
//! objects/      <sha256> immutable objects, mode 0444
//! staging/      files being written; never served, removed at open
//! quarantine/   entries that failed verification, kept for inspection
//! ```
//!
//! Write protocol: a staging file in the same filesystem (`O_CREAT|O_EXCL`,
//! `O_NOFOLLOW`, mode 0600) is streamed while hashing, checked for size and
//! digest, `fsync`ed, made read-only, renamed to `objects/<sha256>`, and the
//! directory is `fsync`ed. A failure at any step removes the staging file,
//! so an object name only ever appears for verified bytes.

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::digest::{COPY_BUFFER_BYTES, ExpectedObject, Hasher, Sha256Digest, hash_reader};
use super::error::CasError;
use super::flight::SingleFlight;
use super::gc::{GcReport, GcRoots, Lease, LeaseTable};
use super::quota::{QuotaLedger, Reservation};

const OBJECTS: &str = "objects";
const STAGING: &str = "staging";
const QUARANTINE: &str = "quarantine";
const LOCK: &str = "lock";

const OBJECT_MODE: u32 = 0o444;
const STAGING_FILE_MODE: u32 = 0o600;
const PRIVATE_DIR_MODE: u32 = 0o700;
/// The repository reader runs as another user and reads objects through
/// group permission; nobody but the owner may write.
const SHARED_DIR_MODE: u32 = 0o750;

/// GitHub limits a release asset to 2 GiB.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    /// Upper bound for the bytes of all objects plus writes in progress.
    pub quota_bytes: Option<u64>,
    /// Upper bound for a single object.
    pub max_object_bytes: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            quota_bytes: None,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        }
    }
}

/// How much [`Store::open_object`] checks before returning the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    /// Regular file of the expected size, opened without following links.
    SizeOnly,
    /// As `SizeOnly`, plus the full SHA-256 of the bytes.
    Full,
}

/// An object that is in the store. While it is held, garbage collection in
/// this process keeps the object even if no root reaches it yet.
#[derive(Debug)]
pub struct StoredObject {
    digest: Sha256Digest,
    size: u64,
    path: PathBuf,
    newly_written: bool,
    lease: Lease,
}

impl StoredObject {
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `false` when an identical verified object was already stored.
    pub fn newly_written(&self) -> bool {
        self.newly_written
    }

    pub fn lease(&self) -> &Lease {
        &self.lease
    }
}

/// An open object that passed the requested verification, positioned at its
/// first byte. Reading through this handle serves exactly the checked inode.
#[derive(Debug)]
pub struct VerifiedObject {
    file: File,
    digest: Sha256Digest,
    size: u64,
}

impl VerifiedObject {
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

impl Read for VerifiedObject {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScrubReport {
    pub verified: usize,
    pub quarantined: Vec<Sha256Digest>,
    pub unknown_entries: usize,
}

/// The single-writer store. Opening it takes an exclusive lock on the root,
/// so staging cleanup, quota accounting, and garbage collection never race
/// another writer process. Within the process, writes of one digest are
/// serialised and garbage collection excludes publishing.
pub struct Store {
    objects: PathBuf,
    staging: PathBuf,
    quarantine: PathBuf,
    config: StoreConfig,
    ledger: QuotaLedger,
    flights: SingleFlight<Sha256Digest>,
    leases: LeaseTable,
    /// Read by writers, written by garbage collection.
    collecting: RwLock<()>,
    sequence: AtomicU64,
    recovered_staging: usize,
    _lock: File,
    #[cfg(test)]
    write_fault: std::sync::Mutex<Option<u64>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Store")
            .field("objects", &self.objects)
            .field("config", &self.config)
            .field("used_bytes", &self.ledger.used())
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens or creates the store, takes the writer lock, removes staging
    /// leftovers of an interrupted run, quarantines object entries that are
    /// not regular files, and counts the stored bytes.
    pub fn open(root: &Path, config: StoreConfig) -> Result<Self, CasError> {
        create_dir(root, SHARED_DIR_MODE)?;
        check_dir(root)?;

        let lock_path = root.join(LOCK);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(STAGING_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .map_err(|error| open_error("open lock", &lock_path, error))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(CasError::StoreBusy),
            Err(TryLockError::Error(error)) => {
                return Err(CasError::io("lock", &lock_path, error));
            }
        }

        let objects = root.join(OBJECTS);
        let staging = root.join(STAGING);
        let quarantine = root.join(QUARANTINE);
        for (dir, mode) in [
            (&objects, SHARED_DIR_MODE),
            (&staging, PRIVATE_DIR_MODE),
            (&quarantine, PRIVATE_DIR_MODE),
        ] {
            create_dir(dir, mode)?;
            check_dir(dir)?;
        }

        let mut store = Self {
            objects,
            staging,
            quarantine,
            config,
            ledger: QuotaLedger::new(config.quota_bytes, 0),
            flights: SingleFlight::new(),
            leases: LeaseTable::default(),
            collecting: RwLock::new(()),
            sequence: AtomicU64::new(0),
            recovered_staging: 0,
            _lock: lock,
            #[cfg(test)]
            write_fault: std::sync::Mutex::new(None),
        };
        store.recovered_staging = store.remove_staging_leftovers()?;
        let used = store.scan_objects()?;
        store.ledger = QuotaLedger::new(config.quota_bytes, used);
        Ok(store)
    }

    /// Staging files of an interrupted run that `open` removed.
    pub fn recovered_staging_files(&self) -> usize {
        self.recovered_staging
    }

    /// Bytes of stored objects plus writes in progress.
    pub fn used_bytes(&self) -> u64 {
        self.ledger.used()
    }

    pub fn object_path(&self, digest: &Sha256Digest) -> PathBuf {
        self.objects.join(digest.to_hex())
    }

    /// Stores `source` as the expected object, or returns the stored copy.
    pub fn put<R: Read>(
        &self,
        expected: ExpectedObject,
        source: R,
    ) -> Result<StoredObject, CasError> {
        self.ensure(expected, || Ok(source))
    }

    /// Returns the expected object, calling `fetch` only when no verified
    /// copy is stored. Concurrent calls for one digest run one at a time, so
    /// parallel requests produce one download and one object; a waiter that
    /// finds the object stored does not call its own `fetch`. A failed
    /// attempt is not shared: the next waiter tries its own `fetch`.
    pub fn ensure<R, F>(&self, expected: ExpectedObject, fetch: F) -> Result<StoredObject, CasError>
    where
        R: Read,
        F: FnOnce() -> io::Result<R>,
    {
        if expected.size > self.config.max_object_bytes {
            return Err(CasError::ObjectTooLarge {
                size: expected.size,
                limit: self.config.max_object_bytes,
            });
        }
        let _flight = self.flights.acquire(expected.sha256);
        {
            let _writing = self
                .collecting
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(stored) = self.existing(&expected)? {
                return Ok(stored);
            }
        }

        // The download runs without the collection lock: staging files are
        // invisible to garbage collection, and a slow source must not hold
        // up a collection pass (or the writes queued behind it).
        let reservation = self.ledger.reserve(expected.size)?;
        let source = fetch().map_err(|source| CasError::Source { source })?;
        let (path, file) = self.create_staging()?;
        let result = self
            .fill(file, &path, source, Limit::Exact(expected), None)
            .and_then(|_| {
                let _writing = self
                    .collecting
                    .read()
                    .unwrap_or_else(PoisonError::into_inner);
                self.publish(&path, &expected.sha256)
                    .map(|object_path| self.stored(expected, object_path, true))
            });
        match result {
            Ok(stored) => {
                reservation.commit(expected.size);
                Ok(stored)
            }
            Err(error) => {
                remove_staging(&path);
                Err(error)
            }
        }
    }

    /// Stores bytes whose digest is not known in advance, such as locally
    /// generated repository indexes, and names them by their digest.
    pub fn insert<R: Read>(&self, source: R) -> Result<StoredObject, CasError> {
        let (path, file) = self.create_staging()?;
        let mut reservation = self.ledger.reserve(0)?;
        let staged = self.fill(
            file,
            &path,
            source,
            Limit::AtMost(self.config.max_object_bytes),
            Some(&mut reservation),
        );
        let (digest, size) = match staged {
            Ok(staged) => staged,
            Err(error) => {
                remove_staging(&path);
                return Err(error);
            }
        };
        let expected = ExpectedObject::new(digest, size);

        // Lock order is always flight, then `collecting` (as in `ensure`).
        let _flight = self.flights.acquire(digest);
        let _writing = self
            .collecting
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        match self.existing(&expected) {
            Ok(Some(stored)) => {
                remove_staging(&path);
                return Ok(stored);
            }
            Ok(None) => {}
            Err(error) => {
                remove_staging(&path);
                return Err(error);
            }
        }
        // The lease is taken under the collection lock, so a collection pass
        // either runs before the object exists or sees the lease.
        match self.publish(&path, &digest) {
            Ok(object_path) => {
                reservation.commit(size);
                Ok(self.stored(expected, object_path, true))
            }
            Err(error) => {
                remove_staging(&path);
                Err(error)
            }
        }
    }

    /// Opens an object for reading without changing the store. A symlink,
    /// FIFO, or other non-regular entry is refused without blocking.
    pub fn open_object(
        &self,
        expected: ExpectedObject,
        verification: Verification,
    ) -> Result<VerifiedObject, CasError> {
        let path = self.object_path(&expected.sha256);
        let mut file = open_entry(&path, &expected.sha256)?;
        let size = file
            .metadata()
            .map_err(|error| CasError::io("stat", &path, error))?
            .len();
        if size != expected.size {
            return Err(CasError::SizeMismatch {
                expected: expected.size,
                actual: size,
            });
        }
        if verification == Verification::Full {
            let (actual, length) =
                hash_reader(&mut file).map_err(|error| CasError::io("read", &path, error))?;
            if actual != expected.sha256 || length != size {
                return Err(CasError::CorruptObject {
                    digest: expected.sha256,
                });
            }
            file.seek(SeekFrom::Start(0))
                .map_err(|error| CasError::io("seek", &path, error))?;
        }
        Ok(VerifiedObject {
            file,
            digest: expected.sha256,
            size,
        })
    }

    /// Fully verifies one object; a corrupt or unsafe entry is moved to
    /// quarantine and reported as [`CasError::CorruptObject`] or
    /// [`CasError::UnsafeEntry`].
    pub fn verify(&self, expected: ExpectedObject) -> Result<(), CasError> {
        let _flight = self.flights.acquire(expected.sha256);
        let _writing = self
            .collecting
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        match self.open_object(expected, Verification::Full) {
            Ok(_) => Ok(()),
            Err(CasError::SizeMismatch { .. }) => {
                // The entry may still match its name; only a digest check
                // can tell corruption from a wrong expectation.
                if self.check_named(&expected.sha256)? {
                    Err(CasError::SizeMismatch {
                        expected: expected.size,
                        actual: self.entry_size(&expected.sha256),
                    })
                } else {
                    Err(CasError::CorruptObject {
                        digest: expected.sha256,
                    })
                }
            }
            Err(error @ (CasError::CorruptObject { .. } | CasError::UnsafeEntry { .. })) => {
                self.quarantine_entry(&expected.sha256)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Re-hashes every object and quarantines those that do not match their
    /// names. Intended as the periodic scrub and as part of reconcile.
    pub fn scrub(&self) -> Result<ScrubReport, CasError> {
        let mut report = ScrubReport::default();
        for (_, digest) in self.object_names()? {
            let Some(digest) = digest else {
                report.unknown_entries += 1;
                continue;
            };
            let _flight = self.flights.acquire(digest);
            let _writing = self
                .collecting
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            match self.check_named(&digest) {
                Ok(true) => report.verified += 1,
                Ok(false) => report.quarantined.push(digest),
                Err(CasError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(report)
    }

    /// Deletes every object that no root reaches and no lease in this
    /// process holds. Publishing in this process waits until the pass ends;
    /// downloads into staging continue.
    pub fn collect_garbage(&self, roots: &GcRoots) -> Result<GcReport, CasError> {
        let _exclusive = self
            .collecting
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let mut report = GcReport::default();
        for (name, digest) in self.object_names()? {
            let Some(digest) = digest else {
                report.unknown_entries += 1;
                continue;
            };
            if roots.contains(&digest) {
                report.kept += 1;
                continue;
            }
            if self.leases.is_leased(&digest) {
                report.leased += 1;
                continue;
            }
            let path = self.objects.join(&name);
            let size = regular_size(&path);
            match fs::remove_file(&path) {
                Ok(()) => {
                    self.ledger.release(size);
                    report.freed_bytes = report.freed_bytes.saturating_add(size);
                    report.removed.push(digest);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(CasError::io("remove", &path, error)),
            }
        }
        if !report.removed.is_empty() {
            sync_dir(&self.objects)?;
        }
        Ok(report)
    }

    /// Returns a verified existing object, quarantining an entry that is
    /// corrupt or unsafe so that the caller writes a fresh copy.
    fn existing(&self, expected: &ExpectedObject) -> Result<Option<StoredObject>, CasError> {
        let path = self.object_path(&expected.sha256);
        match self.check_named(&expected.sha256) {
            Ok(true) => {}
            Ok(false) | Err(CasError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error),
        }
        let size = self.entry_size(&expected.sha256);
        if size != expected.size {
            // The stored bytes match the digest, so the expectation is wrong.
            return Err(CasError::SizeMismatch {
                expected: expected.size,
                actual: size,
            });
        }
        Ok(Some(self.stored(*expected, path, false)))
    }

    /// Whether the entry is a regular file whose bytes hash to its name.
    /// Anything else is quarantined and reported as `false`.
    fn check_named(&self, digest: &Sha256Digest) -> Result<bool, CasError> {
        let path = self.object_path(digest);
        let file = match open_entry(&path, digest) {
            Ok(file) => file,
            Err(CasError::UnsafeEntry { .. }) => {
                self.quarantine_entry(digest)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let (actual, _) = hash_reader(file).map_err(|error| CasError::io("read", &path, error))?;
        if actual == *digest {
            Ok(true)
        } else {
            self.quarantine_entry(digest)?;
            Ok(false)
        }
    }

    fn entry_size(&self, digest: &Sha256Digest) -> u64 {
        regular_size(&self.object_path(digest))
    }

    fn stored(&self, expected: ExpectedObject, path: PathBuf, newly_written: bool) -> StoredObject {
        StoredObject {
            digest: expected.sha256,
            size: expected.size,
            path,
            newly_written,
            lease: self.leases.acquire(expected.sha256),
        }
    }

    /// Moves an object entry, whatever its type, out of `objects/`.
    fn quarantine_entry(&self, digest: &Sha256Digest) -> Result<(), CasError> {
        let source = self.object_path(digest);
        let size = regular_size(&source);
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let target = self.quarantine.join(format!(
            "{}.{seconds}.{}",
            digest.to_hex(),
            self.sequence.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::rename(&source, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(CasError::io("quarantine", &source, error)),
        }
        self.ledger.release(size);
        sync_dir(&self.objects)?;
        sync_dir(&self.quarantine)
    }

    fn create_staging(&self) -> Result<(PathBuf, File), CasError> {
        let path = self.staging_path(self.sequence.fetch_add(1, Ordering::Relaxed));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(STAGING_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    CasError::UnsafeEntry {
                        path: path.clone(),
                        problem: "staging name already exists",
                    }
                } else {
                    open_error("create staging", &path, error)
                }
            })?;
        Ok((path, file))
    }

    fn staging_path(&self, sequence: u64) -> PathBuf {
        self.staging
            .join(format!("{}.{sequence}.part", std::process::id()))
    }

    /// Streams `source` into the staging file while hashing, checks the
    /// limit and the expectation, then makes the file durable and read-only.
    fn fill<R: Read>(
        &self,
        mut file: File,
        path: &Path,
        mut source: R,
        limit: Limit,
        mut reservation: Option<&mut Reservation<'_>>,
    ) -> Result<(Sha256Digest, u64), CasError> {
        let mut hasher = Hasher::new();
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        let mut sink = StagingSink {
            file: &mut file,
            written: 0,
            fail_after: self.write_fault(),
        };
        loop {
            let count = match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(CasError::Source { source }),
            };
            let total = hasher.length().saturating_add(count as u64);
            match limit {
                Limit::Exact(expected) if total > expected.size => {
                    return Err(CasError::SizeMismatch {
                        expected: expected.size,
                        actual: total,
                    });
                }
                Limit::AtMost(maximum) if total > maximum => {
                    return Err(CasError::ObjectTooLarge {
                        size: total,
                        limit: maximum,
                    });
                }
                _ => {}
            }
            if let Some(reservation) = reservation.as_deref_mut() {
                reservation.grow(count as u64)?;
            }
            sink.write_all(&buffer[..count])
                .map_err(|error| CasError::io("write", path, error))?;
            hasher.update(&buffer[..count]);
        }
        let (digest, size) = hasher.finish();
        if let Limit::Exact(expected) = limit {
            if size != expected.size {
                return Err(CasError::SizeMismatch {
                    expected: expected.size,
                    actual: size,
                });
            }
            if digest != expected.sha256 {
                return Err(CasError::DigestMismatch {
                    expected: expected.sha256,
                    actual: digest,
                });
            }
        }
        file.sync_all()
            .map_err(|error| CasError::io("fsync", path, error))?;
        file.set_permissions(fs::Permissions::from_mode(OBJECT_MODE))
            .map_err(|error| CasError::io("chmod", path, error))?;
        Ok((digest, size))
    }

    /// Renames a verified staging file into place. `rename` replaces
    /// whatever entry a racing actor put at the name (a symlink included)
    /// with the verified inode; it never writes through a link.
    fn publish(&self, staging: &Path, digest: &Sha256Digest) -> Result<PathBuf, CasError> {
        let target = self.object_path(digest);
        fs::rename(staging, &target).map_err(|error| CasError::io("rename", staging, error))?;
        sync_dir(&self.objects)?;
        Ok(target)
    }

    fn remove_staging_leftovers(&self) -> Result<usize, CasError> {
        let mut removed = 0;
        for entry in read_dir(&self.staging)? {
            let path = entry.path();
            let is_dir = fs::symlink_metadata(&path)
                .map(|metadata| metadata.is_dir())
                .unwrap_or(false);
            if is_dir {
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(CasError::io("remove staging", &path, error)),
            }
        }
        if removed > 0 {
            sync_dir(&self.staging)?;
        }
        Ok(removed)
    }

    /// Counts the bytes of regular object files and quarantines object
    /// entries of any other type.
    fn scan_objects(&self) -> Result<u64, CasError> {
        let mut used = 0_u64;
        for (name, digest) in self.object_names()? {
            let path = self.objects.join(&name);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(CasError::io("stat", &path, error)),
            };
            if metadata.is_file() {
                used = used.saturating_add(metadata.len());
            } else if let Some(digest) = digest {
                self.quarantine_entry(&digest)?;
            }
        }
        Ok(used)
    }

    /// Entry names in `objects/`, with the digest when the name is one.
    fn object_names(&self) -> Result<Vec<(String, Option<Sha256Digest>)>, CasError> {
        let mut names = Vec::new();
        for entry in read_dir(&self.objects)? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let digest = Sha256Digest::from_hex(&name).ok();
            names.push((name, digest));
        }
        Ok(names)
    }

    #[cfg(test)]
    fn write_fault(&self) -> Option<u64> {
        *self
            .write_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(not(test))]
    fn write_fault(&self) -> Option<u64> {
        None
    }
}

#[derive(Clone, Copy)]
enum Limit {
    Exact(ExpectedObject),
    AtMost(u64),
}

/// The staging file writer. Tests use `fail_after` to simulate `ENOSPC`
/// after a number of bytes; production code always passes `None`.
struct StagingSink<'a> {
    file: &'a mut File,
    written: u64,
    fail_after: Option<u64>,
}

impl Write for StagingSink<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if let Some(limit) = self.fail_after
            && self.written.saturating_add(buffer.len() as u64) > limit
        {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        let count = self.file.write(buffer)?;
        self.written = self.written.saturating_add(count as u64);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn create_dir(path: &Path, mode: u32) -> Result<(), CasError> {
    match DirBuilder::new().recursive(true).mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(error) => Err(CasError::io("create directory", path, error)),
    }
}

/// Refuses a store directory that is a symlink, not a directory, or
/// writable by group or others (who could plant entries in it).
fn check_dir(path: &Path) -> Result<(), CasError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| CasError::io("stat", path, error))?;
    let problem = if metadata.file_type().is_symlink() {
        Some("directory is a symlink")
    } else if !metadata.is_dir() {
        Some("not a directory")
    } else if metadata.permissions().mode() & 0o022 != 0 {
        Some("directory is writable by group or others")
    } else {
        None
    };
    match problem {
        Some(problem) => Err(CasError::UnsafeEntry {
            path: path.to_path_buf(),
            problem,
        }),
        None => Ok(()),
    }
}

/// Opens an object entry for reading: no symlink is followed, a FIFO does
/// not block the open, and only a regular file is accepted.
fn open_entry(path: &Path, digest: &Sha256Digest) -> Result<File, CasError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => CasError::NotFound { digest: *digest },
            _ => open_error("open", path, error),
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| CasError::io("stat", path, error))?;
    if metadata.is_file() {
        Ok(file)
    } else {
        Err(CasError::UnsafeEntry {
            path: path.to_path_buf(),
            problem: "not a regular file",
        })
    }
}

/// `O_NOFOLLOW` reports a symlink as `ELOOP`.
fn open_error(operation: &'static str, path: &Path, error: io::Error) -> CasError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        CasError::UnsafeEntry {
            path: path.to_path_buf(),
            problem: "symlink",
        }
    } else {
        CasError::io(operation, path, error)
    }
}

fn regular_size(path: &Path) -> u64 {
    fs::symlink_metadata(path)
        .ok()
        .filter(fs::Metadata::is_file)
        .map_or(0, |metadata| metadata.len())
}

fn read_dir(path: &Path) -> Result<Vec<fs::DirEntry>, CasError> {
    fs::read_dir(path)
        .and_then(|entries| entries.collect::<io::Result<Vec<_>>>())
        .map_err(|error| CasError::io("list", path, error))
}

fn sync_dir(path: &Path) -> Result<(), CasError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| CasError::io("fsync directory", path, error))
}

/// Best effort: a staging file left behind is removed at the next open.
fn remove_staging(path: &Path) {
    let _ = fs::remove_file(path);
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
