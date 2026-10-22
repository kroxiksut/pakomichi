// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime};

use super::*;
use crate::error::ReasonCode;

type TestResult = Result<(), Box<dyn Error>>;

/// A unique directory under the system temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "pakomichi-cas-test-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn store_root(&self) -> PathBuf {
        self.0.join("store")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(dir: &TempDir) -> Result<Store, CasError> {
    Store::open(&dir.store_root(), StoreConfig::default())
}

fn expected_for(bytes: &[u8]) -> ExpectedObject {
    ExpectedObject::new(Sha256Digest::of(bytes), bytes.len() as u64)
}

fn payload(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn entries(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

/// Nothing half-written may remain after a failed write.
fn assert_clean(dir: &TempDir, store: &Store) -> TestResult {
    let root = dir.store_root();
    assert_eq!(entries(&root.join(STAGING))?, Vec::<String>::new());
    assert_eq!(entries(&root.join(OBJECTS))?, Vec::<String>::new());
    assert_eq!(store.used_bytes(), 0);
    Ok(())
}

/// A source that yields some bytes and then fails, like a dropped download.
struct FailingSource {
    remaining: usize,
}

impl Read for FailingSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "upstream closed",
            ));
        }
        let count = buffer.len().min(self.remaining);
        buffer[..count].fill(7);
        self.remaining -= count;
        Ok(count)
    }
}

/// A source that delivers slowly in small pieces, to keep a write in flight.
struct SlowSource<'a> {
    bytes: &'a [u8],
}

impl Read for SlowSource<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        thread::sleep(Duration::from_millis(1));
        let count = buffer.len().min(self.bytes.len()).min(4096);
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn put_publishes_a_read_only_object() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(300_000, 1);
    let expected = expected_for(&bytes);

    let stored = store.put(expected, bytes.as_slice())?;
    assert!(stored.newly_written());
    assert_eq!(stored.digest(), expected.sha256);
    assert_eq!(stored.path(), store.object_path(&expected.sha256));
    assert_eq!(fs::read(stored.path())?, bytes);
    let mode = fs::symlink_metadata(stored.path())?.permissions().mode() & 0o777;
    assert_eq!(mode, OBJECT_MODE);
    assert_eq!(store.used_bytes(), bytes.len() as u64);
    assert_eq!(
        entries(&dir.store_root().join(STAGING))?,
        Vec::<String>::new()
    );

    let mut object = store.open_object(expected, Verification::Full)?;
    let mut read_back = Vec::new();
    object.read_to_end(&mut read_back)?;
    assert_eq!(read_back, bytes);
    Ok(())
}

#[test]
fn store_directories_are_not_writable_by_others() -> TestResult {
    let dir = TempDir::new()?;
    let _store = open(&dir)?;
    let root = dir.store_root();
    for (name, mode) in [
        (OBJECTS, SHARED_DIR_MODE),
        (STAGING, PRIVATE_DIR_MODE),
        (QUARANTINE, PRIVATE_DIR_MODE),
    ] {
        let actual = fs::metadata(root.join(name))?.permissions().mode() & 0o777;
        // The umask may remove bits but never adds any.
        assert_eq!(actual & !mode, 0, "{name}: {actual:o}");
    }
    Ok(())
}

#[test]
fn identical_puts_deduplicate() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(5000, 2);
    let expected = expected_for(&bytes);

    let first = store.put(expected, bytes.as_slice())?;
    let second = store.put(expected, bytes.as_slice())?;
    let inserted = store.insert(bytes.as_slice())?;
    assert!(first.newly_written());
    assert!(!second.newly_written());
    assert!(!inserted.newly_written());
    assert_eq!(inserted.digest(), expected.sha256);
    assert_eq!(entries(&dir.store_root().join(OBJECTS))?.len(), 1);
    assert_eq!(store.used_bytes(), bytes.len() as u64);
    Ok(())
}

#[test]
fn insert_names_bytes_by_their_digest() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = b"Package: example\nVersion: 1.0\n";
    let stored = store.insert(&bytes[..])?;
    assert_eq!(stored.digest(), Sha256Digest::of(bytes));
    assert_eq!(stored.size(), bytes.len() as u64);
    store.verify(expected_for(bytes))?;
    Ok(())
}

#[test]
fn concurrent_ensures_download_once_and_share_one_object() -> TestResult {
    let dir = TempDir::new()?;
    let store = Arc::new(open(&dir)?);
    let bytes = Arc::new(payload(512 * 1024, 3));
    let expected = expected_for(&bytes);
    let fetches = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(8));

    let workers: Vec<_> = (0..8)
        .map(|_| {
            let (store, bytes, fetches, barrier) = (
                store.clone(),
                bytes.clone(),
                fetches.clone(),
                barrier.clone(),
            );
            thread::spawn(move || {
                barrier.wait();
                store
                    .ensure(expected, || {
                        fetches.fetch_add(1, Ordering::SeqCst);
                        Ok(SlowSource { bytes: &bytes })
                    })
                    .map(|stored| (stored.newly_written(), stored.digest()))
            })
        })
        .collect();

    let mut written = 0;
    for worker in workers {
        let (newly_written, digest) = worker.join().map_err(|_| "worker panicked")??;
        assert_eq!(digest, expected.sha256);
        written += usize::from(newly_written);
    }
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    assert_eq!(written, 1);
    assert_eq!(
        entries(&dir.store_root().join(OBJECTS))?,
        vec![expected.sha256.to_hex()]
    );
    assert_eq!(store.used_bytes(), bytes.len() as u64);
    store.verify(expected)?;
    Ok(())
}

#[test]
fn a_failed_attempt_is_not_shared_with_waiters() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(10_000, 4);
    let expected = expected_for(&bytes);

    let failed = store.ensure(expected, || Ok(FailingSource { remaining: 100 }));
    assert!(matches!(failed, Err(CasError::Source { .. })));
    assert_clean(&dir, &store)?;
    let stored = store.ensure(expected, || Ok(bytes.as_slice()))?;
    assert!(stored.newly_written());
    Ok(())
}

#[test]
fn wrong_digest_publishes_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let accepted = payload(70_000, 5);
    let substituted = payload(70_000, 6);
    let expected = expected_for(&accepted);

    let error = match store.put(expected, substituted.as_slice()) {
        Err(error) => error,
        Ok(_) => return Err("substituted bytes were accepted".into()),
    };
    assert!(matches!(error, CasError::DigestMismatch { .. }));
    assert_eq!(error.reason_code(), Some(ReasonCode::ECacheDigestMismatch));
    assert_clean(&dir, &store)?;
    Ok(())
}

#[test]
fn truncated_and_oversized_sources_publish_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(200_000, 7);
    let expected = expected_for(&bytes);

    let truncated = store.put(expected, &bytes[..bytes.len() - 1]);
    assert!(matches!(
        truncated,
        Err(CasError::SizeMismatch {
            expected: 200_000,
            actual: 199_999
        })
    ));
    assert_clean(&dir, &store)?;

    // Reading stops at the first byte past the accepted size.
    let mut longer = bytes.clone();
    longer.extend_from_slice(&[0; 1 << 20]);
    let oversized = store.put(expected, longer.as_slice());
    match oversized {
        Err(CasError::SizeMismatch {
            expected: 200_000,
            actual,
        }) => {
            assert!(actual <= 200_000 + COPY_BUFFER_BYTES as u64);
        }
        other => return Err(format!("unexpected result {other:?}").into()),
    }
    assert_clean(&dir, &store)?;
    Ok(())
}

#[test]
fn a_dropped_download_publishes_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let expected = ExpectedObject::new(Sha256Digest::of(b"never complete"), 1_000_000);
    let result = store.put(expected, FailingSource { remaining: 300_000 });
    assert!(matches!(result, Err(CasError::Source { .. })));
    assert_clean(&dir, &store)?;
    Ok(())
}

#[test]
fn disk_full_while_writing_publishes_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    *store
        .write_fault
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(150_000);
    let bytes = payload(400_000, 8);

    let error = match store.put(expected_for(&bytes), bytes.as_slice()) {
        Err(error) => error,
        Ok(_) => return Err("write past ENOSPC succeeded".into()),
    };
    assert!(matches!(error, CasError::StorageFull { .. }));
    assert_eq!(error.reason_code(), Some(ReasonCode::EDiskExhausted));
    assert_clean(&dir, &store)?;

    let error = match store.insert(bytes.as_slice()) {
        Err(error) => error,
        Ok(_) => return Err("insert past ENOSPC succeeded".into()),
    };
    assert!(matches!(error, CasError::StorageFull { .. }));
    assert_clean(&dir, &store)?;
    Ok(())
}

#[test]
fn quota_is_checked_before_fetching() -> TestResult {
    let dir = TempDir::new()?;
    let config = StoreConfig {
        quota_bytes: Some(100_000),
        ..StoreConfig::default()
    };
    let store = Store::open(&dir.store_root(), config)?;
    let small = payload(60_000, 9);
    store.put(expected_for(&small), small.as_slice())?;

    let large = payload(60_000, 10);
    let fetched = AtomicBool::new(false);
    let result = store.ensure(expected_for(&large), || {
        fetched.store(true, Ordering::SeqCst);
        Ok(large.as_slice())
    });
    let error = match result {
        Err(error) => error,
        Ok(_) => return Err("stored past the quota".into()),
    };
    assert!(
        matches!(
            error,
            CasError::QuotaExceeded {
                available: 40_000,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.reason_code(), Some(ReasonCode::EDiskExhausted));
    assert!(!fetched.load(Ordering::SeqCst), "fetched despite the quota");
    assert_eq!(entries(&dir.store_root().join(OBJECTS))?.len(), 1);
    assert_eq!(store.used_bytes(), 60_000);

    // Unknown sizes are charged while streaming.
    let result = store.insert(large.as_slice());
    assert!(matches!(result, Err(CasError::QuotaExceeded { .. })));
    assert_eq!(
        entries(&dir.store_root().join(STAGING))?,
        Vec::<String>::new()
    );
    assert_eq!(store.used_bytes(), 60_000);
    Ok(())
}

#[test]
fn per_object_limit_is_enforced() -> TestResult {
    let dir = TempDir::new()?;
    let config = StoreConfig {
        max_object_bytes: 1000,
        ..StoreConfig::default()
    };
    let store = Store::open(&dir.store_root(), config)?;
    let bytes = payload(1001, 11);
    let result = store.ensure(expected_for(&bytes), || -> io::Result<&'static [u8]> {
        Err(io::Error::other("must not fetch"))
    });
    assert!(matches!(
        result,
        Err(CasError::ObjectTooLarge {
            size: 1001,
            limit: 1000
        })
    ));
    let result = store.insert(bytes.as_slice());
    assert!(matches!(
        result,
        Err(CasError::ObjectTooLarge { limit: 1000, .. })
    ));
    assert_clean(&dir, &store)?;
    Ok(())
}

#[test]
fn corrupt_object_is_detected_and_quarantined() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(100_000, 12);
    let expected = expected_for(&bytes);
    let path = store.put(expected, bytes.as_slice())?.path().to_path_buf();

    // Flip one bit in place, as a failing disk would.
    let mut damaged = bytes.clone();
    damaged[50_000] ^= 0x01;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    fs::write(&path, &damaged)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(OBJECT_MODE))?;

    // A size-only open cannot see the flip; a full check refuses to serve.
    store.open_object(expected, Verification::SizeOnly)?;
    let read_only = store.open_object(expected, Verification::Full);
    assert!(matches!(read_only, Err(CasError::CorruptObject { .. })));
    assert!(path.exists(), "a read-only check must not move the object");

    let error = match store.verify(expected) {
        Err(error) => error,
        Ok(()) => return Err("corrupt object verified".into()),
    };
    assert!(matches!(error, CasError::CorruptObject { .. }));
    assert_eq!(error.reason_code(), Some(ReasonCode::ECacheDigestMismatch));
    assert!(!path.exists());
    let quarantined = entries(&dir.store_root().join(QUARANTINE))?;
    assert_eq!(quarantined.len(), 1);
    assert!(quarantined[0].starts_with(&expected.sha256.to_hex()));
    assert_eq!(store.used_bytes(), 0);

    // The next request stores a fresh, verified copy.
    let restored = store.put(expected, bytes.as_slice())?;
    assert!(restored.newly_written());
    store.verify(expected)?;
    Ok(())
}

#[test]
fn ensure_replaces_a_corrupt_object_instead_of_returning_it() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(4096, 13);
    let expected = expected_for(&bytes);
    let path = store.object_path(&expected.sha256);
    fs::write(&path, payload(4096, 14))?;

    let stored = store.put(expected, bytes.as_slice())?;
    assert!(stored.newly_written());
    assert_eq!(fs::read(&path)?, bytes);
    assert_eq!(entries(&dir.store_root().join(QUARANTINE))?.len(), 1);
    Ok(())
}

#[test]
fn scrub_quarantines_only_mismatching_objects() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let good = payload(1000, 15);
    store.put(expected_for(&good), good.as_slice())?;
    let bad = payload(1000, 16);
    let bad_path = store
        .put(expected_for(&bad), bad.as_slice())?
        .path()
        .to_path_buf();
    fs::set_permissions(&bad_path, fs::Permissions::from_mode(0o644))?;
    fs::write(&bad_path, payload(1000, 17))?;
    fs::write(
        dir.store_root().join(OBJECTS).join("README"),
        b"not an object",
    )?;

    let report = store.scrub()?;
    assert_eq!(report.verified, 1);
    assert_eq!(report.quarantined, vec![Sha256Digest::of(&bad)]);
    assert_eq!(report.unknown_entries, 1);
    Ok(())
}

#[test]
fn symlink_at_the_object_path_is_never_served_or_followed() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(2048, 18);
    let expected = expected_for(&bytes);

    // The link target even holds the right bytes; it must still be refused.
    let outside = dir.path().join("outside");
    fs::write(&outside, &bytes)?;
    let object = store.object_path(&expected.sha256);
    symlink(&outside, &object)?;

    let opened = store.open_object(expected, Verification::Full);
    assert!(matches!(
        opened,
        Err(CasError::UnsafeEntry {
            problem: "symlink",
            ..
        })
    ));
    let verified = store.verify(expected);
    assert!(matches!(verified, Err(CasError::UnsafeEntry { .. })));
    assert!(
        fs::symlink_metadata(&object).is_err(),
        "link left in objects/"
    );

    symlink(&outside, &object)?;
    let stored = store.put(expected, bytes.as_slice())?;
    assert!(stored.newly_written());
    let metadata = fs::symlink_metadata(&object)?;
    assert!(metadata.is_file(), "the object must be a regular file");
    assert_eq!(fs::read(&outside)?, bytes, "the link target was modified");
    store.verify(expected)?;
    Ok(())
}

#[test]
fn symlink_at_the_staging_path_is_refused() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(2048, 19);
    let expected = expected_for(&bytes);

    let victim = dir.path().join("victim");
    fs::write(&victim, b"original")?;
    let next = store.staging_path(store.sequence.load(Ordering::SeqCst));
    symlink(&victim, &next)?;

    let result = store.put(expected, bytes.as_slice());
    assert!(matches!(result, Err(CasError::UnsafeEntry { .. })));
    assert_eq!(fs::read(&victim)?, b"original");
    assert!(fs::symlink_metadata(store.object_path(&expected.sha256)).is_err());
    Ok(())
}

#[test]
fn fifo_at_the_object_path_does_not_block() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let expected = expected_for(b"fifo");
    let object = store.object_path(&expected.sha256);
    let status = std::process::Command::new("mkfifo").arg(&object).status();
    match status {
        Ok(status) if status.success() => {}
        // Without mkfifo the case cannot be built; other tests cover links.
        _ => return Ok(()),
    }
    let opened = store.open_object(expected, Verification::Full);
    assert!(matches!(
        opened,
        Err(CasError::UnsafeEntry {
            problem: "not a regular file",
            ..
        })
    ));
    Ok(())
}

#[test]
fn symlinked_store_directory_is_refused() -> TestResult {
    let dir = TempDir::new()?;
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere)?;
    let root = dir.store_root();
    fs::create_dir(&root)?;
    symlink(&elsewhere, root.join(OBJECTS))?;

    let result = Store::open(&root, StoreConfig::default());
    assert!(matches!(result, Err(CasError::UnsafeEntry { .. })));
    Ok(())
}

#[test]
fn group_writable_store_directory_is_refused() -> TestResult {
    let dir = TempDir::new()?;
    let root = dir.store_root();
    fs::create_dir(&root)?;
    fs::create_dir(root.join(STAGING))?;
    fs::set_permissions(root.join(STAGING), fs::Permissions::from_mode(0o770))?;
    let result = Store::open(&root, StoreConfig::default());
    assert!(matches!(
        result,
        Err(CasError::UnsafeEntry {
            problem: "directory is writable by group or others",
            ..
        })
    ));
    Ok(())
}

#[test]
fn a_second_writer_is_refused_by_the_lock() -> TestResult {
    let dir = TempDir::new()?;
    let first = open(&dir)?;
    assert!(matches!(open(&dir), Err(CasError::StoreBusy)));
    drop(first);
    // Another test may spawn a process at this moment; until it execs, the
    // child holds a copy of every descriptor, the lock included, so allow a
    // short transient hold.
    for _ in 0..100 {
        match open(&dir) {
            Err(CasError::StoreBusy) => thread::sleep(Duration::from_millis(10)),
            other => {
                other?;
                return Ok(());
            }
        }
    }
    Err("the lock outlived its store".into())
}

#[test]
fn reopening_removes_staging_and_recounts_usage() -> TestResult {
    let dir = TempDir::new()?;
    let bytes = payload(12_345, 20);
    {
        let store = open(&dir)?;
        store.put(expected_for(&bytes), bytes.as_slice())?;
        // A writer killed mid-copy leaves a partial staging file behind.
        fs::write(
            dir.store_root().join(STAGING).join("1.0.part"),
            &bytes[..100],
        )?;
    }
    let store = open(&dir)?;
    assert_eq!(store.recovered_staging_files(), 1);
    assert_eq!(
        entries(&dir.store_root().join(STAGING))?,
        Vec::<String>::new()
    );
    assert_eq!(store.used_bytes(), bytes.len() as u64);
    store.verify(expected_for(&bytes))?;
    Ok(())
}

#[test]
fn reopening_quarantines_non_regular_object_entries() -> TestResult {
    let dir = TempDir::new()?;
    drop(open(&dir)?);
    let digest = Sha256Digest::of(b"planted");
    symlink(
        "/etc/hostname",
        dir.store_root().join(OBJECTS).join(digest.to_hex()),
    )?;
    let store = open(&dir)?;
    assert_eq!(
        entries(&dir.store_root().join(OBJECTS))?,
        Vec::<String>::new()
    );
    assert_eq!(entries(&dir.store_root().join(QUARANTINE))?.len(), 1);
    assert_eq!(store.used_bytes(), 0);
    Ok(())
}

#[test]
fn gc_removes_only_unreachable_unleased_objects() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let current = payload(1000, 21);
    let retained = payload(1000, 22);
    let expired = payload(1000, 23);
    let pinned = payload(1000, 24);
    let in_flight = payload(1000, 25);
    for bytes in [&current, &retained, &expired, &pinned] {
        store.put(expected_for(bytes), bytes.as_slice())?;
    }
    // Stored but not yet referenced: the caller still holds the handle.
    let held = store.put(expected_for(&in_flight), in_flight.as_slice())?;

    let now = SystemTime::now();
    let retention = Duration::from_secs(24 * 3600);
    let mut roots = GcRoots::new(now, retention);
    let shared = Sha256Digest::of(&current);
    assert!(roots.add_generation(None, [shared]));
    assert!(roots.add_generation(
        Some(now - Duration::from_secs(3600)),
        [shared, Sha256Digest::of(&retained)]
    ));
    assert!(!roots.add_generation(
        Some(now - Duration::from_secs(48 * 3600)),
        [shared, Sha256Digest::of(&expired)]
    ));
    roots.pin(Sha256Digest::of(&pinned));

    let report = store.collect_garbage(&roots)?;
    assert_eq!(report.removed, vec![Sha256Digest::of(&expired)]);
    assert_eq!(report.freed_bytes, 1000);
    assert_eq!(report.kept, 3);
    assert_eq!(report.leased, 1);
    assert_eq!(store.used_bytes(), 4000);
    for bytes in [&current, &retained, &pinned, &in_flight] {
        store.verify(expected_for(bytes))?;
    }

    drop(held);
    let report = store.collect_garbage(&roots)?;
    assert_eq!(report.removed, vec![Sha256Digest::of(&in_flight)]);
    assert_eq!(store.used_bytes(), 3000);
    Ok(())
}

#[test]
fn gc_running_concurrently_never_removes_a_held_object() -> TestResult {
    let dir = TempDir::new()?;
    let store = Arc::new(open(&dir)?);
    let stop = Arc::new(AtomicBool::new(false));
    let collector = {
        let (store, stop) = (store.clone(), stop.clone());
        thread::spawn(move || -> Result<usize, CasError> {
            let roots = GcRoots::new(SystemTime::now(), Duration::ZERO);
            let mut removed = 0;
            while !stop.load(Ordering::SeqCst) {
                removed += store.collect_garbage(&roots)?.removed.len();
                // Back-to-back passes would starve writers on a
                // writer-preferring lock; real collection is periodic.
                thread::sleep(Duration::from_millis(1));
            }
            Ok(removed)
        })
    };

    for round in 0..100_u32 {
        let bytes = payload(2000, round as u8)
            .into_iter()
            .chain(round.to_le_bytes())
            .collect::<Vec<_>>();
        let expected = expected_for(&bytes);
        let held = store.put(expected, bytes.as_slice())?;
        // While the handle is held the object must stay servable.
        store.open_object(expected, Verification::Full)?;
        drop(held);
    }
    stop.store(true, Ordering::SeqCst);
    let removed = collector.join().map_err(|_| "collector panicked")??;
    let final_pass = store.collect_garbage(&GcRoots::new(SystemTime::now(), Duration::ZERO))?;
    assert_eq!(removed + final_pass.removed.len(), 100);
    assert_eq!(store.used_bytes(), 0);
    Ok(())
}

#[test]
fn gc_reports_but_keeps_unknown_entries() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let foreign = dir.store_root().join(OBJECTS).join("not-a-digest");
    fs::write(&foreign, b"x")?;
    let report = store.collect_garbage(&GcRoots::new(SystemTime::now(), Duration::ZERO))?;
    assert_eq!(report.unknown_entries, 1);
    assert!(foreign.exists());
    Ok(())
}

#[test]
fn size_expectation_mismatch_on_a_good_object_is_not_corruption() -> TestResult {
    let dir = TempDir::new()?;
    let store = open(&dir)?;
    let bytes = payload(3000, 26);
    let expected = expected_for(&bytes);
    store.put(expected, bytes.as_slice())?;
    let wrong = ExpectedObject::new(expected.sha256, 2999);

    let result = store.put(wrong, bytes.as_slice());
    assert!(matches!(
        result,
        Err(CasError::SizeMismatch {
            expected: 2999,
            actual: 3000
        })
    ));
    let result = store.verify(wrong);
    assert!(matches!(result, Err(CasError::SizeMismatch { .. })));
    assert!(store.object_path(&expected.sha256).exists());
    assert_eq!(
        entries(&dir.store_root().join(QUARANTINE))?,
        Vec::<String>::new()
    );
    Ok(())
}

/// A real `ENOSPC` from the kernel. Needs a small dedicated filesystem,
/// for example `mount -t tmpfs -o size=1m tmpfs /mnt/pakomichi-small`, named
/// by `PAKOMICHI_TEST_SMALL_FS`; run with `--ignored`.
#[test]
#[ignore = "needs a small dedicated filesystem in PAKOMICHI_TEST_SMALL_FS"]
fn real_disk_full_publishes_nothing() -> TestResult {
    let Some(mount) = std::env::var_os("PAKOMICHI_TEST_SMALL_FS") else {
        return Err("PAKOMICHI_TEST_SMALL_FS is not set".into());
    };
    let root = Path::new(&mount).join("store");
    let store = Store::open(&root, StoreConfig::default())?;
    let kept = payload(100_000, 27);
    store.put(expected_for(&kept), kept.as_slice())?;

    let bytes = payload(4 * 1024 * 1024, 28);
    let error = match store.put(expected_for(&bytes), bytes.as_slice()) {
        Err(error) => error,
        Ok(_) => return Err("the filesystem is larger than the test object".into()),
    };
    assert!(matches!(error, CasError::StorageFull { .. }), "{error:?}");
    assert_eq!(error.reason_code(), Some(ReasonCode::EDiskExhausted));
    assert_eq!(entries(&root.join(STAGING))?, Vec::<String>::new());
    assert_eq!(
        entries(&root.join(OBJECTS))?,
        vec![Sha256Digest::of(&kept).to_hex()]
    );
    assert_eq!(store.used_bytes(), kept.len() as u64);
    store.verify(expected_for(&kept))?;
    drop(store);
    fs::remove_dir_all(&root)?;
    Ok(())
}
