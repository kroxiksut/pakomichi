// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::cas::{Sha256Digest, StoreConfig};
use crate::publish::Timestamp;

type TestResult = Result<(), Box<dyn Error>>;

const DAY: Duration = Duration::from_secs(86_400);

/// `(id, generation, state, signature_sha256)` of one `snapshot` row.
type SnapshotRow = (String, i64, String, Option<String>);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "pakomichi-publish-test-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _dir: TempDir,
    root: PathBuf,
    cas: CasStore,
}

impl Fixture {
    fn new() -> Result<(Self, GenerationStore), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let root = dir.join("publish");
        let cas = CasStore::open(&dir.join("cas"), StoreConfig::default())?;
        let (store, recovery) = GenerationStore::open(&root)?;
        assert_eq!(recovery, Recovery::default());
        Ok((
            Self {
                _dir: dir,
                root,
                cas,
            },
            store,
        ))
    }

    fn put(&self, bytes: &[u8]) -> Result<ExpectedObject, Box<dyn Error>> {
        let stored = self.cas.insert(bytes)?;
        Ok(ExpectedObject::new(stored.digest(), stored.size()))
    }

    /// An APT generation: `InRelease`, one index with its by-hash alias,
    /// and one package per name.
    fn apt(
        &self,
        release: &str,
        packages: &[&str],
    ) -> Result<Vec<(RepoPath, ExpectedObject)>, Box<dyn Error>> {
        let mut objects = vec![(
            RepoPath::new("dists/stable/InRelease")?,
            self.put(format!("signed {release}").as_bytes())?,
        )];
        let index = self.put(format!("index {release} {packages:?}").as_bytes())?;
        objects.push((
            RepoPath::new("dists/stable/main/binary-amd64/Packages")?,
            index,
        ));
        objects.push((
            RepoPath::new(&format!(
                "dists/stable/main/binary-amd64/by-hash/SHA256/{}",
                index.sha256.to_hex()
            ))?,
            index,
        ));
        for package in packages {
            let deb = self.put(package.as_bytes())?;
            objects.push((pool_path(&deb, package)?, deb));
        }
        Ok(objects)
    }
}

fn pool_path(object: &ExpectedObject, name: &str) -> Result<RepoPath, ManifestError> {
    RepoPath::new(&format!("pool/{}/{name}.deb", object.sha256.to_hex()))
}

fn meta(repo: &str, source: &str) -> Result<GenerationMeta, ManifestError> {
    Ok(GenerationMeta {
        repo: RepoName::new(repo)?,
        source: SourceId::new(source)?,
        backend: Backend::Apt,
        valid_from: Timestamp::new("2026-10-21T00:00:00Z")?,
        valid_until: Timestamp::new("2026-10-28T00:00:00Z")?,
    })
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn repo() -> Result<RepoName, ManifestError> {
    RepoName::new("src-1-apt-strict")
}

fn id(value: u64) -> GenerationId {
    GenerationId::new(value).unwrap_or_else(|| unreachable!("test ids are valid"))
}

const T0: u64 = 1_800_000_000;

#[test]
fn publishing_makes_the_generation_current() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    let objects = fixture.apt("1", &["tool-1.0"])?;
    let first = store.publish(
        meta("src-1-apt-strict", "src-1")?,
        objects,
        &fixture.cas,
        at(T0),
    )?;
    assert_eq!(first, id(1));
    assert_eq!(store.current(&repo()?)?, Some(first));

    let manifest_path = fixture
        .root
        .join("repos/src-1-apt-strict/generations/1.manifest");
    assert_eq!(
        fs::metadata(&manifest_path)?.permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("repos/src-1-apt-strict/current"))?,
        "1\n"
    );
    let loaded = store.load(&repo()?, first)?;
    assert_eq!(loaded.generation, first);
    assert_eq!(loaded.len(), 4);

    let release = RepoPath::new("dists/stable/InRelease")?;
    let found = store.resolve(&repo()?, &release, at(T0), DAY)?;
    assert_eq!(found.map(|(generation, _)| generation), Some(first));
    Ok(())
}

#[test]
fn old_package_paths_stay_reachable_but_old_metadata_does_not() -> TestResult {
    // R-004 G2/G5: a client holding the previous lists still gets its
    // packages; mutable metadata comes only from the current generation.
    let (fixture, mut store) = Fixture::new()?;
    let old_deb = fixture.put(b"tool-1.0")?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("1", &["tool-1.0"])?,
        &fixture.cas,
        at(T0),
    )?;
    let mut second = fixture.apt("2", &["tool-1.1"])?;
    second.push((
        RepoPath::new("dists/stable/Release.gpg")?,
        fixture.put(b"detached")?,
    ));
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        second,
        &fixture.cas,
        at(T0 + 60),
    )?;
    let repo = repo()?;

    let old_package = pool_path(&old_deb, "tool-1.0")?;
    let found = store.resolve(&repo, &old_package, at(T0 + 120), DAY)?;
    assert_eq!(
        found.map(|(generation, entry)| (generation, entry.object)),
        Some((id(1), old_deb))
    );

    let release = RepoPath::new("dists/stable/InRelease")?;
    let current = store.resolve(&repo, &release, at(T0 + 120), DAY)?;
    assert_eq!(current.map(|(generation, _)| generation), Some(id(2)));

    // The old index under its own digest is still there (G5), the old
    // plain path is not: the plain path now serves the new index.
    let old = store.load(&repo, id(1))?;
    let old_index = old
        .entries()
        .find(|entry| entry.path.as_str().contains("/by-hash/"))
        .map(|entry| entry.path.clone())
        .ok_or("old by-hash path")?;
    assert_eq!(
        store
            .resolve(&repo, &old_index, at(T0 + 120), DAY)?
            .map(|(generation, _)| generation),
        Some(id(1))
    );
    Ok(())
}

#[test]
fn a_mutable_path_of_an_older_generation_is_never_served() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    let mut first = fixture.apt("1", &["tool-1.0"])?;
    first.push((
        RepoPath::new("dists/stable/Release.gpg")?,
        fixture.put(b"detached")?,
    ));
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        first,
        &fixture.cas,
        at(T0),
    )?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("2", &["tool-1.0"])?,
        &fixture.cas,
        at(T0 + 60),
    )?;
    let gone = RepoPath::new("dists/stable/Release.gpg")?;
    assert_eq!(store.resolve(&repo()?, &gone, at(T0 + 120), DAY)?, None);
    Ok(())
}

#[test]
fn retention_window_bounds_reachability_and_collection() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    let old_deb = fixture.put(b"tool-1.0")?;
    let new_deb = fixture.put(b"tool-1.1")?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("1", &["tool-1.0"])?,
        &fixture.cas,
        at(T0),
    )?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("2", &["tool-1.1"])?,
        &fixture.cas,
        at(T0 + 3_600),
    )?;
    let repo = repo()?;
    let generations = store.generations(&repo)?;
    assert_eq!(
        generations,
        vec![
            GenerationInfo {
                id: id(1),
                retired_at: Some(at(T0 + 3_600))
            },
            GenerationInfo {
                id: id(2),
                retired_at: None
            },
        ]
    );

    // Inside the window: both generations are roots, nothing is collected.
    let inside = at(T0 + 3_600) + DAY - Duration::from_secs(1);
    let roots = store.gc_roots(inside, DAY)?;
    assert!(roots.contains(&old_deb.sha256) && roots.contains(&new_deb.sha256));
    assert!(store.collect(inside, DAY)?.is_empty());

    // Past the window: the old generation is gone from roots and disk, the
    // current one never is.
    let past = at(T0 + 3_600) + DAY;
    let old_package = pool_path(&old_deb, "tool-1.0")?;
    assert_eq!(store.resolve(&repo, &old_package, past, DAY)?, None);
    let roots = store.gc_roots(past, DAY)?;
    assert!(!roots.contains(&old_deb.sha256));
    assert!(roots.contains(&new_deb.sha256));
    assert_eq!(store.collect(past, DAY)?, vec![(repo.clone(), id(1))]);
    assert_eq!(store.current(&repo)?, Some(id(2)));
    assert!(store.load(&repo, id(2)).is_ok());
    assert!(matches!(
        store.load(&repo, id(1)),
        Err(PublishError::UnknownGeneration)
    ));
    // Even a year later the current generation stays.
    assert!(store.collect(past + 365 * DAY, DAY)?.is_empty());
    Ok(())
}

#[test]
fn a_failed_publish_burns_its_number_and_changes_nothing() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("1", &["tool-1.0"])?,
        &fixture.cas,
        at(T0),
    )?;

    // Every object is in the CAS, but one path is neither metadata nor
    // content-addressed: the generation is refused after its number was
    // allocated.
    let mut stray = fixture.apt("2", &[])?;
    stray.push((RepoPath::new("index.html")?, fixture.put(b"<html>")?));
    assert!(matches!(
        store.publish(
            meta("src-1-apt-strict", "src-1")?,
            stray,
            &fixture.cas,
            at(T0 + 60)
        ),
        Err(PublishError::Manifest(ManifestError::UnclassifiedPath(_)))
    ));
    assert_eq!(store.current(&repo()?)?, Some(id(1)));
    assert_eq!(store.generations(&repo()?)?.len(), 1);

    let next = store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("3", &["tool-1.0"])?,
        &fixture.cas,
        at(T0 + 120),
    )?;
    assert_eq!(next, id(3), "number 2 was allocated and is never reused");
    Ok(())
}

#[test]
fn an_object_missing_from_the_cas_is_refused_before_anything_is_written() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    let mut objects = fixture.apt("1", &[])?;
    let absent = ExpectedObject::new(Sha256Digest::of(b"never stored"), 12);
    objects.push((pool_path(&absent, "ghost")?, absent));
    assert!(matches!(
        store.publish(
            meta("src-1-apt-strict", "src-1")?,
            objects,
            &fixture.cas,
            at(T0)
        ),
        Err(PublishError::Object(_))
    ));
    assert_eq!(store.current(&repo()?)?, None);
    assert!(!fixture.root.join("ids/src-1.apt").exists());
    Ok(())
}

#[test]
fn a_manifest_never_made_current_is_marked_failed_on_open() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("1", &["tool-1.0"])?,
        &fixture.cas,
        at(T0),
    )?;
    // A publisher killed between writing manifest 2 and switching current.
    let next = Manifest::new(
        meta("src-1-apt-strict", "src-1")?,
        id(2),
        T0 + 60,
        fixture.apt("2", &["tool-1.1"])?,
    )?;
    let generations = fixture.root.join("repos/src-1-apt-strict/generations");
    fs::write(generations.join("2.manifest"), next.to_text())?;
    fs::write(fixture.root.join("tmp/2.manifest.123.part"), b"partial")?;
    drop(store);

    let (mut store, recovery) = GenerationStore::open(&fixture.root)?;
    assert_eq!(recovery.removed_staging, 1);
    assert_eq!(recovery.failed, vec![(repo()?, id(2))]);
    assert!(generations.join("2.failed").exists());
    assert_eq!(store.current(&repo()?)?, Some(id(1)));
    assert_eq!(store.generations(&repo()?)?.len(), 1);
    let after = store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("3", &["tool-1.1"])?,
        &fixture.cas,
        at(T0 + 120),
    )?;
    assert_eq!(after, id(3), "number 2 stays used");
    Ok(())
}

#[test]
fn numbers_never_go_back_even_if_the_counter_is_lost() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    for (release, time) in [("1", T0), ("2", T0 + 60), ("3", T0 + 120)] {
        store.publish(
            meta("src-1-apt-strict", "src-1")?,
            fixture.apt(release, &["tool"])?,
            &fixture.cas,
            at(time),
        )?;
    }
    fs::write(fixture.root.join("ids/src-1.apt"), b"1\n")?;
    let next = store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("4", &["tool"])?,
        &fixture.cas,
        at(T0 + 180),
    )?;
    assert_eq!(next, id(4));
    fs::remove_file(fixture.root.join("ids/src-1.apt"))?;
    let next = store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("5", &["tool"])?,
        &fixture.cas,
        at(T0 + 240),
    )?;
    assert_eq!(next, id(5));
    Ok(())
}

#[test]
fn levels_of_one_source_share_the_number_space() -> TestResult {
    // ADR-027: each provenance level is its own logical repository, while
    // `snapshot` keeps (source, backend, generation) unique.
    let (fixture, mut store) = Fixture::new()?;
    let strict = store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("1", &["a"])?,
        &fixture.cas,
        at(T0),
    )?;
    let pinned = store.publish(
        meta("src-1-apt-pinned", "src-1")?,
        fixture.apt("1p", &["b"])?,
        &fixture.cas,
        at(T0),
    )?;
    let other = store.publish(
        meta("src-2-apt-strict", "src-2")?,
        fixture.apt("1", &["c"])?,
        &fixture.cas,
        at(T0),
    )?;
    assert_eq!((strict, pinned, other), (id(1), id(2), id(1)));
    assert_eq!(
        store.current(&RepoName::new("src-1-apt-pinned")?)?,
        Some(id(2))
    );
    Ok(())
}

#[test]
fn a_second_publisher_is_refused() -> TestResult {
    let (fixture, _store) = Fixture::new()?;
    assert!(matches!(
        GenerationStore::open(&fixture.root),
        Err(PublishError::AlreadyLocked)
    ));
    Ok(())
}

#[test]
fn tampered_store_entries_are_refused() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("1", &["tool"])?,
        &fixture.cas,
        at(T0),
    )?;
    let repo = repo()?;
    let current = fixture.root.join("repos/src-1-apt-strict/current");

    fs::write(&current, b"01\n")?;
    assert!(matches!(
        store.current(&repo),
        Err(PublishError::UnsafeEntry { .. })
    ));
    fs::remove_file(&current)?;
    std::os::unix::fs::symlink(fixture.root.join("lock"), &current)?;
    assert!(matches!(
        store.current(&repo),
        Err(PublishError::UnsafeEntry { .. })
    ));
    fs::remove_file(&current)?;
    fs::write(&current, b"1\n")?;

    // A manifest that names another generation is corrupt.
    let manifest = fixture
        .root
        .join("repos/src-1-apt-strict/generations/1.manifest");
    let text = fs::read_to_string(&manifest)?.replacen("generation 1\n", "generation 9\n", 1);
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o640))?;
    fs::write(&manifest, text)?;
    assert!(matches!(
        store.load(&repo, id(1)),
        Err(PublishError::CorruptManifest { .. })
    ));
    Ok(())
}

#[test]
fn reconcile_rebuilds_snapshot_rows_from_manifests() -> TestResult {
    let (fixture, mut store) = Fixture::new()?;
    let state_dir = TempDir::new()?;
    let mut state = StateOwner::open(&state_dir.join("state.db"))?;
    state.connection().execute(
        "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, first_seen_at) \
         VALUES ('src-1', 'github', '100', '1', 'https://github.com/o/r', '2026-10-21T00:00:00Z')",
        [],
    )?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("1", &["tool-1.0"])?,
        &fixture.cas,
        at(T0),
    )?;
    store.publish(
        meta("src-1-apt-strict", "src-1")?,
        fixture.apt("2", &["tool-1.1"])?,
        &fixture.cas,
        at(T0 + 60),
    )?;
    // A repository of a source the database does not know.
    store.publish(
        meta("src-9-apt-strict", "src-9")?,
        fixture.apt("1", &["x"])?,
        &fixture.cas,
        at(T0),
    )?;

    let report = store.reconcile(&mut state)?;
    assert_eq!(report.rows, 2);
    assert_eq!(
        report.skipped_repos,
        vec![RepoName::new("src-9-apt-strict")?]
    );
    let rows = |state: &mut StateOwner| -> rusqlite::Result<Vec<SnapshotRow>> {
        let connection = state.connection();
        let mut statement = connection.prepare(
            "SELECT id, generation, state, signature_sha256 FROM snapshot ORDER BY generation",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect()
    };
    let found = rows(&mut state)?;
    assert_eq!(
        found
            .iter()
            .map(|(id, generation, row_state, _)| (id.as_str(), *generation, row_state.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("src-1-apt-strict:1", 1, "retired"),
            ("src-1-apt-strict:2", 2, "published")
        ]
    );
    let in_release = store
        .load(&repo()?, id(2))?
        .entries()
        .find(|entry| entry.path.as_str() == "dists/stable/InRelease")
        .map(|entry| entry.object.sha256.to_hex());
    assert_eq!(found[1].3, in_release);

    // Reconcile is idempotent, and a collected generation becomes
    // `collected`.
    assert_eq!(store.reconcile(&mut state)?.rows, 2);
    store.collect(at(T0 + 60) + DAY, DAY)?;
    let report = store.reconcile(&mut state)?;
    assert_eq!((report.rows, report.collected_rows), (1, 1));
    let states: Vec<String> = rows(&mut state)?
        .into_iter()
        .map(|(_, _, row_state, _)| row_state)
        .collect();
    assert_eq!(states, vec!["collected".to_owned(), "published".to_owned()]);
    Ok(())
}
