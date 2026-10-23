// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::cas::{CasError, ExpectedObject, Store as CasStore, StoreConfig};
use crate::publish::{
    Backend, GenerationMeta, GenerationStore, RepoName, RepoPath, SourceId, Timestamp,
};

type TestResult = Result<(), Box<dyn Error>>;

const DAY: Duration = Duration::from_secs(86_400);
const REPO: &str = "src-1-apt-strict";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "pakomichi-reader-test-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A publisher (writer) and a reader over the same roots.
struct Fixture {
    dir: TempDir,
    cas: CasStore,
    store: GenerationStore,
}

/// What one APT generation contains.
struct Published {
    release: Vec<u8>,
    package_path: String,
    package: Vec<u8>,
    package_object: ExpectedObject,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let dir = TempDir::new()?;
        let cas = CasStore::open(&dir.0.join("cas"), StoreConfig::default())?;
        let (store, _) = GenerationStore::open(&dir.0.join("publish"))?;
        Ok(Self { dir, cas, store })
    }

    fn repositories(&self, retention: Duration) -> Result<Repositories, OpenError> {
        Repositories::open(
            &self.dir.0.join("publish"),
            &self.dir.0.join("cas"),
            retention,
        )
    }

    fn put(&self, bytes: &[u8]) -> Result<ExpectedObject, Box<dyn Error>> {
        let stored = self.cas.insert(bytes)?;
        Ok(ExpectedObject::new(stored.digest(), stored.size()))
    }

    fn object_path(&self, object: &ExpectedObject) -> PathBuf {
        self.cas.object_path(&object.sha256)
    }

    /// Publishes `InRelease`, one index with its by-hash alias, and one
    /// package, at `now`.
    fn publish(&mut self, label: &str, now: SystemTime) -> Result<Published, Box<dyn Error>> {
        let release = format!("signed release {label}\n").into_bytes();
        let index = format!("Package: tool\nVersion: {label}\n").into_bytes();
        let package = format!("deb bytes of tool {label}").into_bytes();
        let release_object = self.put(&release)?;
        let index_object = self.put(&index)?;
        let package_object = self.put(&package)?;
        let package_path = format!("pool/{}/tool_{label}.deb", package_object.sha256.to_hex());
        let objects = vec![
            (RepoPath::new("dists/stable/InRelease")?, release_object),
            (
                RepoPath::new("dists/stable/main/binary-amd64/Packages")?,
                index_object,
            ),
            (
                RepoPath::new(&format!(
                    "dists/stable/main/binary-amd64/by-hash/SHA256/{}",
                    index_object.sha256.to_hex()
                ))?,
                index_object,
            ),
            (RepoPath::new(&package_path)?, package_object),
        ];
        let meta = GenerationMeta {
            repo: RepoName::new(REPO)?,
            source: SourceId::new("src-1")?,
            backend: Backend::Apt,
            valid_from: Timestamp::new("2026-10-21T00:00:00Z")?,
            valid_until: Timestamp::new("2026-10-28T00:00:00Z")?,
        };
        self.store.publish(meta, objects, &self.cas, now)?;
        Ok(Published {
            release,
            package_path,
            package,
            package_object,
        })
    }
}

fn read_all(lookup: Lookup) -> Result<Vec<u8>, Box<dyn Error>> {
    match lookup {
        Lookup::Found { mut object, .. } => {
            let mut bytes = Vec::new();
            object.read_to_end(&mut bytes)?;
            Ok(bytes)
        }
        other => Err(format!("expected an object, got {other:?}").into()),
    }
}

fn target(path: &str) -> String {
    format!("/{REPO}/{path}")
}

/// Overwrites an object's bytes in place, as corruption after
/// verification would (the store keeps objects 0444).
fn corrupt(path: &Path) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    let mut bytes = fs::read(path)?;
    if let Some(first) = bytes.first_mut() {
        *first ^= 0x01;
    }
    fs::write(path, bytes)
}

#[test]
fn current_metadata_and_packages_are_served_verified() -> TestResult {
    let mut fixture = Fixture::new()?;
    let now = SystemTime::now();
    let first = fixture.publish("1", now)?;
    let repositories = fixture.repositories(DAY)?;
    assert_eq!(
        read_all(repositories.lookup(&target("dists/stable/InRelease"), now))?,
        first.release
    );
    assert_eq!(
        read_all(repositories.lookup(&target(&first.package_path), now))?,
        first.package
    );
    Ok(())
}

#[test]
fn mutable_paths_follow_current_and_packages_stay_in_the_window() -> TestResult {
    let mut fixture = Fixture::new()?;
    let start = SystemTime::now();
    let first = fixture.publish("1", start)?;
    let repositories = fixture.repositories(DAY)?;
    let second = fixture.publish("2", start + Duration::from_secs(60))?;
    let later = start + Duration::from_secs(120);
    // R-004 G2: a client that read the old index still gets its package.
    assert_eq!(
        read_all(repositories.lookup(&target(&first.package_path), later))?,
        first.package
    );
    // Mutable metadata only from the current generation.
    assert_eq!(
        read_all(repositories.lookup(&target("dists/stable/InRelease"), later))?,
        second.release
    );
    // Past the window the retired package is gone (G4 control).
    let past = start + Duration::from_secs(60) + DAY + Duration::from_secs(1);
    assert!(matches!(
        repositories.lookup(&target(&first.package_path), past),
        Lookup::NotFound
    ));
    Ok(())
}

#[test]
fn an_object_changed_after_publication_is_not_served() -> TestResult {
    // N-017.
    let mut fixture = Fixture::new()?;
    let now = SystemTime::now();
    let first = fixture.publish("1", now)?;
    let repositories = fixture.repositories(DAY)?;
    corrupt(&fixture.object_path(&first.package_object))?;
    match repositories.lookup(&target(&first.package_path), now) {
        Lookup::ObjectRefused(CasError::CorruptObject { .. }) => {}
        other => return Err(format!("corrupt object was not refused: {other:?}").into()),
    }
    // The reader reports and does not move the object; the writer's scrub
    // quarantines it.
    assert!(fixture.object_path(&first.package_object).exists());
    Ok(())
}

#[test]
fn a_symlinked_object_is_refused() -> TestResult {
    // N-018: a symlink in the object store does not lead outside it.
    let mut fixture = Fixture::new()?;
    let now = SystemTime::now();
    let first = fixture.publish("1", now)?;
    let repositories = fixture.repositories(DAY)?;
    let object = fixture.object_path(&first.package_object);
    let outside = fixture.dir.0.join("outside");
    fs::write(&outside, &first.package)?;
    fs::remove_file(&object)?;
    std::os::unix::fs::symlink(&outside, &object)?;
    match repositories.lookup(&target(&first.package_path), now) {
        Lookup::ObjectRefused(CasError::UnsafeEntry { .. }) => Ok(()),
        other => Err(format!("symlinked object was not refused: {other:?}").into()),
    }
}

#[test]
fn refused_and_unknown_targets_are_not_found() -> TestResult {
    let mut fixture = Fixture::new()?;
    let now = SystemTime::now();
    fixture.publish("1", now)?;
    let repositories = fixture.repositories(DAY)?;
    for refused in [
        "/src-1-apt-strict/../src-1-apt-strict/dists/stable/InRelease",
        "/src-1-apt-strict/dists/%2e%2e/dists/stable/InRelease",
        "/src-1-apt-strict/dists%2fstable%2fInRelease",
        "/src-2-apt-strict/dists/stable/InRelease",
        "/src-1-apt-strict/dists/stable/Release",
        "/src-1-apt-strict/dists/stable/InRelease?x",
    ] {
        assert!(
            matches!(repositories.lookup(refused, now), Lookup::NotFound),
            "{refused}"
        );
    }
    Ok(())
}

#[test]
fn opening_refuses_a_group_writable_store() -> TestResult {
    let fixture = Fixture::new()?;
    let publish = fixture.dir.0.join("publish");
    fs::set_permissions(&publish, fs::Permissions::from_mode(0o770))?;
    assert!(fixture.repositories(DAY).is_err());
    fs::set_permissions(&publish, fs::Permissions::from_mode(0o750))?;
    assert!(fixture.repositories(DAY).is_ok());
    Ok(())
}

/// Serves `repositories` on an ephemeral loopback port.
async fn start(repositories: Repositories) -> Result<u16, Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(serve(listener, Arc::new(repositories), Limits::default()));
    Ok(port)
}

/// Sends raw request bytes and reads until the server closes.
async fn exchange(port: u16, request: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await??;
    Ok(response)
}

fn split(response: &[u8]) -> (String, Vec<u8>) {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(response.len(), |position| position + 4);
    (
        String::from_utf8_lossy(&response[..end]).into_owned(),
        response[end..].to_vec(),
    )
}

fn get(path: &str, port: u16, extra: &str) -> String {
    format!(
        "GET /{REPO}/{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}Connection: close\r\n\r\n"
    )
}

#[tokio::test]
async fn http_get_and_head_serve_the_object() -> TestResult {
    let mut fixture = Fixture::new()?;
    let first = fixture.publish("1", SystemTime::now())?;
    let port = start(fixture.repositories(DAY)?).await?;

    let (head, body) = split(&exchange(port, &get(&first.package_path, port, "")).await?);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("content-length: {}\r\n", first.package.len())),
        "{head}"
    );
    assert_eq!(body, first.package);

    let request = get(&first.package_path, port, "").replacen("GET", "HEAD", 1);
    let (head, body) = split(&exchange(port, &request).await?);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("content-length: {}\r\n", first.package.len())),
        "{head}"
    );
    assert!(body.is_empty());
    Ok(())
}

#[tokio::test]
async fn http_keep_alive_serves_several_requests() -> TestResult {
    let mut fixture = Fixture::new()?;
    let first = fixture.publish("1", SystemTime::now())?;
    let port = start(fixture.repositories(DAY)?).await?;
    let request = format!(
        "GET /{REPO}/dists/stable/InRelease HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n{}",
        get(&first.package_path, port, "")
    );
    let response = exchange(port, &request).await?;
    let text = String::from_utf8_lossy(&response);
    assert_eq!(text.matches("HTTP/1.1 200 ").count(), 2, "{text}");
    assert!(response.ends_with(&first.package));
    Ok(())
}

#[tokio::test]
async fn http_refuses_methods_that_could_change_anything() -> TestResult {
    // N-025: no POST or other configuration route.
    let mut fixture = Fixture::new()?;
    fixture.publish("1", SystemTime::now())?;
    let current = fixture.store.current(&RepoName::new(REPO)?)?;
    let port = start(fixture.repositories(DAY)?).await?;
    for method in [
        "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE",
    ] {
        let request = format!(
            "{method} /{REPO}/dists/stable/InRelease HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (head, _) = split(&exchange(port, &request).await?);
        assert!(head.starts_with("HTTP/1.1 405 "), "{method}: {head}");
        assert!(
            head.to_ascii_lowercase().contains("allow: get, head"),
            "{head}"
        );
    }
    assert_eq!(fixture.store.current(&RepoName::new(REPO)?)?, current);
    Ok(())
}

#[tokio::test]
async fn http_refuses_bodies_foreign_hosts_and_absolute_targets() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish("1", SystemTime::now())?;
    let port = start(fixture.repositories(DAY)?).await?;
    let path = format!("/{REPO}/dists/stable/InRelease");
    for (request, expected) in [
        (
            format!(
                "GET {path} HTTP/1.1\r\nHost: evil.example:{port}\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 400 ",
        ),
        (
            format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 400 ",
        ),
        (format!("GET {path} HTTP/1.0\r\n\r\n"), "HTTP/1.0 400 "),
        (
            format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"
            ),
            "HTTP/1.1 400 ",
        ),
        (
            format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
            ),
            "HTTP/1.1 400 ",
        ),
        (
            format!(
                "GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 400 ",
        ),
        (
            format!(
                "GET /{REPO}/dists/%2e%2e/%2e%2e/InRelease HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            ),
            "HTTP/1.1 404 ",
        ),
    ] {
        let (head, _) = split(&exchange(port, &request).await?);
        assert!(head.starts_with(expected), "{request:?}: {head}");
    }
    Ok(())
}

#[tokio::test]
async fn http_does_not_send_a_corrupt_object() -> TestResult {
    // N-017 end to end: no byte of the object leaves the reader.
    let mut fixture = Fixture::new()?;
    let first = fixture.publish("1", SystemTime::now())?;
    corrupt(&fixture.object_path(&first.package_object))?;
    let port = start(fixture.repositories(DAY)?).await?;
    let (head, body) = split(&exchange(port, &get(&first.package_path, port, "")).await?);
    assert!(head.starts_with("HTTP/1.1 500 "), "{head}");
    assert_eq!(body, b"object unavailable\n");
    Ok(())
}

#[tokio::test]
async fn a_non_loopback_listener_is_refused() -> TestResult {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    assert!(check_loopback(&listener).is_err());
    let loopback = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    assert!(check_loopback(&loopback).is_ok());
    Ok(())
}

#[test]
fn a_large_object_is_streamed_whole() -> TestResult {
    // More than one 64 KiB chunk, and not a multiple of it.
    let mut fixture = Fixture::new()?;
    let bytes: Vec<u8> = (0..200_003_u32).map(|value| (value % 251) as u8).collect();
    let object = fixture.put(&bytes)?;
    let path = format!("pool/{}/big_1.deb", object.sha256.to_hex());
    let meta = GenerationMeta {
        repo: RepoName::new(REPO)?,
        source: SourceId::new("src-1")?,
        backend: Backend::Apt,
        valid_from: Timestamp::new("2026-10-21T00:00:00Z")?,
        valid_until: Timestamp::new("2026-10-28T00:00:00Z")?,
    };
    let release = fixture.put(b"signed")?;
    fixture.store.publish(
        meta,
        vec![
            (RepoPath::new("dists/stable/InRelease")?, release),
            (RepoPath::new(&path)?, object),
        ],
        &fixture.cas,
        SystemTime::now(),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        let port = start(fixture.repositories(DAY)?).await?;
        exchange(port, &get(&path, port, "")).await
    })?;
    let (head, body) = split(&response);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(body.len(), bytes.len());
    assert!(body == bytes);
    Ok(())
}
