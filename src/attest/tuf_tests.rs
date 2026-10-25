// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline tests on snapshots of both TUF repositories recorded by
//! `research/p2-003b/fetch-tuf.py` (`tests/data/tuf/`); expiry is evaluated
//! at the recording time unless a test moves it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sigstore_tuf::transport::{FetchFuture, Repository};

use super::*;
use crate::attest::{AttestationVerifier, ensure_crypto_provider};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A recorded repository served from memory, or a repository that is down.
struct Fixture {
    files: HashMap<String, Vec<u8>>,
    down: bool,
}

impl Fixture {
    fn load(instance: TufInstance) -> Result<Self, Box<dyn std::error::Error>> {
        let root = data_dir(instance);
        let mut files = HashMap::new();
        let mut pending = vec![root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                } else {
                    let relative = entry
                        .path()
                        .strip_prefix(&root)?
                        .to_string_lossy()
                        .replace('\\', "/");
                    files.insert(relative, std::fs::read(entry.path())?);
                }
            }
        }
        Ok(Self { files, down: false })
    }

    fn down() -> Self {
        Self {
            files: HashMap::new(),
            down: true,
        }
    }

    fn get(&self, name: &str) -> sigstore_tuf::Result<Option<Vec<u8>>> {
        if self.down {
            return Err(sigstore_tuf::Error::transport("connection refused (test)"));
        }
        Ok(self.files.get(name).cloned())
    }

    /// Replaces one file, for tampering.
    fn with(mut self, name: &str, change: impl FnOnce(&mut Vec<u8>)) -> Result<Self, String> {
        let file = self.files.get_mut(name).ok_or(format!("no {name}"))?;
        change(file);
        Ok(self)
    }
}

impl Repository for Fixture {
    fn fetch_metadata<'a>(&'a self, name: &'a str, _max_length: u64) -> FetchFuture<'a> {
        let result = self.get(name);
        Box::pin(async move { result })
    }

    fn fetch_target<'a>(&'a self, path: &'a str, _max_length: u64) -> FetchFuture<'a> {
        let result = self.get(&format!("targets/{path}"));
        Box::pin(async move { result })
    }
}

fn data_dir(instance: TufInstance) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/tuf")
        .join(instance.cache_name())
}

/// The later of the two recording times.
fn recorded() -> Result<jiff::Timestamp, Box<dyn std::error::Error>> {
    let mut latest = None;
    for instance in TufInstance::ALL {
        let text = std::fs::read_to_string(data_dir(instance).join("recorded.txt"))?;
        let time: jiff::Timestamp = text.trim().parse()?;
        latest = latest.max(Some(time));
    }
    latest.ok_or_else(|| "no recording".into())
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "pakomichi-tuf-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sets the test process up the way a Pakomichi process starts: the crypto
/// provider first (TUF verification panics without it), then the runtime.
/// Relying on another test to install the provider holds only while every
/// test shares one process; under nextest each test has its own.
fn runtime() -> Result<tokio::runtime::Runtime, Box<dyn std::error::Error>> {
    ensure_crypto_provider()?;
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

const V1: &str = include_str!("../../tests/data/attest/pchi-test-v0.1.0.jsonl");

/// The refreshed roots verify the owner's test-repository attestations.
fn verifies_pchi_test(roots: &crate::attest::TrustedRoots) -> TestResult {
    use crate::attest::{ExpectedProvenance, SourceRef};
    use crate::cas::Sha256Digest;
    use crate::github::{
        GitObjectId, OwnerId, OwnerLogin, PinnedRepository, RepositoryId, RepositoryIdentity,
        RepositoryName,
    };
    ensure_crypto_provider()?;
    let verifier = AttestationVerifier::new(roots)?;
    let repository = PinnedRepository::pin(RepositoryIdentity::new(
        RepositoryId::new(1_429_109_739)?,
        OwnerId::new(2_264_172)?,
        OwnerLogin::new("kroxiksut")?,
        RepositoryName::new("pchi-test")?,
    ));
    let expected = ExpectedProvenance::new(
        &repository,
        ".github/workflows/immutable-release.yml",
        SourceRef::Branch("main".into()),
        GitObjectId::from_hex("6ee0f9f53e5a296bd19904188d055608f32ffd82").map_err(|_| "commit")?,
        Sha256Digest::from_hex("8fcda58d824b4fea8f98e036083f398f497941af4b8c15de5dac02dd900576fd")
            .map_err(|_| "digest")?,
    )
    .map_err(|_| "workflow")?;
    let bundles: Vec<&[u8]> = V1.lines().map(str::as_bytes).collect();
    verifier.verify_attested(&bundles, &expected)?;
    Ok(())
}

#[test]
fn bootstrap_roots_are_the_pinned_files() {
    use crate::cas::Sha256Digest;
    assert_eq!(
        Sha256Digest::of(TufInstance::GitHub.bootstrap_root()).to_hex(),
        "eb303461e0109458144b6ebcbfd62aaa6f6d7481e9ca77504b85f17761661462"
    );
    assert_eq!(
        Sha256Digest::of(TufInstance::PublicGood.bootstrap_root()).to_hex(),
        "73747011d0857ada15479a16c4cae0f3ed03aac698b523b97e1de314ac9d9ca8"
    );
}

#[test]
fn a_refresh_walks_the_root_chain_and_yields_working_roots() -> TestResult {
    let cache = TempDir::new()?;
    let (roots, sources) = runtime()?.block_on(refresh_trusted_roots(
        Fixture::load(TufInstance::GitHub)?,
        Fixture::load(TufInstance::PublicGood)?,
        &cache.0,
        recorded()?,
    ))?;
    assert_eq!(sources, [RootSource::Refreshed, RootSource::Refreshed]);
    verifies_pchi_test(&roots)?;
    // The public-good chain moved from the pinned version 15 to 16.
    let cached_root = std::fs::read(cache.0.join("public-good/root.json"))?;
    let version =
        serde_json::from_slice::<serde_json::Value>(&cached_root)?["signed"]["version"].as_u64();
    assert_eq!(version, Some(16));
    Ok(())
}

#[test]
fn without_network_the_unexpired_cache_is_used_and_expiry_stops_it() -> TestResult {
    let cache = TempDir::new()?;
    let runtime = runtime()?;
    let now = recorded()?;
    runtime.block_on(refresh_trusted_roots(
        Fixture::load(TufInstance::GitHub)?,
        Fixture::load(TufInstance::PublicGood)?,
        &cache.0,
        now,
    ))?;
    let (roots, sources) = runtime.block_on(refresh_trusted_roots(
        Fixture::down(),
        Fixture::down(),
        &cache.0,
        now,
    ))?;
    assert_eq!(sources, [RootSource::Cache, RootSource::Cache]);
    verifies_pchi_test(&roots)?;
    // A year later the cached metadata has expired: no silent use.
    let later = now + jiff::SignedDuration::from_hours(24 * 365);
    match runtime.block_on(refresh_trusted_roots(
        Fixture::down(),
        Fixture::down(),
        &cache.0,
        later,
    )) {
        Err(RefreshError::Root(RootError::Stale { instance, .. })) => {
            assert_eq!(instance, TufInstance::GitHub);
        }
        other => {
            return Err(format!("expected stale roots, got {:?}", other.map(|(_, s)| s)).into());
        }
    }
    Ok(())
}

#[test]
fn without_network_or_cache_the_root_is_unreachable() -> TestResult {
    let cache = TempDir::new()?;
    let result = runtime()?.block_on(fetch_trusted_root(
        TufInstance::PublicGood,
        Fixture::down(),
        &cache.0,
        recorded()?,
    ));
    assert!(
        matches!(
            result,
            Err(RootError::Unreachable {
                instance: TufInstance::PublicGood,
                ..
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn expired_metadata_from_the_network_is_stale_not_accepted() -> TestResult {
    // A frozen repository that keeps serving old metadata (freeze attack).
    let cache = TempDir::new()?;
    let later = recorded()? + jiff::SignedDuration::from_hours(24 * 30);
    let result = runtime()?.block_on(fetch_trusted_root(
        TufInstance::GitHub,
        Fixture::load(TufInstance::GitHub)?,
        &cache.0,
        later,
    ));
    assert!(matches!(result, Err(RootError::Stale { .. })), "{result:?}");
    Ok(())
}

fn flip_last_hex_digit(text: &mut [u8], marker: &str) -> Result<(), String> {
    let start = String::from_utf8_lossy(text)
        .find(marker)
        .ok_or(format!("no {marker}"))?
        + marker.len();
    let byte = text.get_mut(start).ok_or("short")?;
    *byte = if *byte == b'0' { b'1' } else { b'0' };
    Ok(())
}

#[test]
fn tampered_metadata_or_target_is_invalid_and_never_replaced_by_the_cache() -> TestResult {
    let runtime = runtime()?;
    let now = recorded()?;
    let cache = TempDir::new()?;
    // A valid cache exists.
    runtime.block_on(fetch_trusted_root(
        TufInstance::GitHub,
        Fixture::load(TufInstance::GitHub)?,
        &cache.0,
        now,
    ))?;
    let target = Fixture::load(TufInstance::GitHub)?
        .files
        .keys()
        .find(|name| name.ends_with(".trusted_root.json"))
        .cloned()
        .ok_or("no target")?;
    let tampered_signature =
        Fixture::load(TufInstance::GitHub)?.with("timestamp.json", |bytes| {
            let _ = flip_last_hex_digit(bytes, "\"sig\": \"");
            let _ = flip_last_hex_digit(bytes, "\"sig\":\"");
        })?;
    let tampered_target = Fixture::load(TufInstance::GitHub)?.with(&target, |bytes| {
        if let Some(last) = bytes.iter().rposition(|byte| *byte == b'}') {
            bytes.insert(last, b' ');
        }
    })?;
    for fixture in [tampered_signature, tampered_target] {
        // A fresh cache, so the cached target cannot short-circuit the download.
        let fresh = TempDir::new()?;
        let result = runtime.block_on(fetch_trusted_root(
            TufInstance::GitHub,
            fixture,
            &fresh.0,
            now,
        ));
        assert!(
            matches!(result, Err(RootError::Invalid { .. })),
            "{result:?}"
        );
    }
    // With the valid cache present, a bad signature from the network is
    // still refused rather than answered from the cache.
    let tampered = Fixture::load(TufInstance::GitHub)?.with("timestamp.json", |bytes| {
        let _ = flip_last_hex_digit(bytes, "\"sig\": \"");
        let _ = flip_last_hex_digit(bytes, "\"sig\":\"");
    })?;
    let result = runtime.block_on(fetch_trusted_root(
        TufInstance::GitHub,
        tampered,
        &cache.0,
        now,
    ));
    assert!(
        matches!(result, Err(RootError::Invalid { .. })),
        "{result:?}"
    );
    Ok(())
}

// ------------------------------------------------------------ the transport

mod transport {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::super::super::tuf_http::{TufHttp, TufRepository};
    use crate::github::{HttpConfig, Resolve, SecureConnector, TransportError};
    use sigstore_tuf::transport::Repository;

    struct Loopback(SocketAddr);

    impl Resolve for Loopback {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Vec<SocketAddr>, TransportError> {
            Ok(vec![self.0])
        }
    }

    /// Plain TCP stand-in for the TLS connector.
    struct Plain;

    impl SecureConnector for Plain {
        type Stream = TcpStream;

        async fn connect(
            &self,
            _host: &str,
            address: SocketAddr,
        ) -> Result<TcpStream, TransportError> {
            TcpStream::connect(address)
                .await
                .map_err(|_| TransportError::Connect)
        }
    }

    /// Answers every connection with `response` and records the request.
    async fn server(
        response: &'static str,
    ) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<String>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return String::new();
            };
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap_or(0);
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
            String::from_utf8_lossy(&request[..read]).into_owned()
        });
        Ok((address, task))
    }

    fn http(address: SocketAddr) -> TufHttp<Plain, Loopback> {
        TufHttp::with_resolver(Plain, Loopback(address), HttpConfig::default())
            .allowing_loopback_for_tests()
    }

    #[tokio::test]
    async fn gets_metadata_and_targets_from_the_fixed_host()
    -> Result<(), Box<dyn std::error::Error>> {
        let (address, request) = server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").await?;
        let repository = TufRepository::new(Arc::new(http(address)), "tuf-repo.github.com");
        assert_eq!(
            repository
                .fetch_target("abc.trusted_root.json", 100)
                .await?,
            Some(b"{}".to_vec())
        );
        let request = request.await?;
        assert!(
            request.starts_with("GET /targets/abc.trusted_root.json HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("host: tuf-repo.github.com"),
            "{request}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn not_found_ends_a_root_chain_and_other_statuses_fail()
    -> Result<(), Box<dyn std::error::Error>> {
        let (address, _) = server("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await?;
        assert_eq!(
            http(address)
                .get("tuf-repo.github.com", "10.root.json", 100)
                .await?,
            None
        );
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            let (address, _) = server(response).await?;
            assert!(matches!(
                http(address)
                    .get("tuf-repo.github.com", "timestamp.json", 100)
                    .await,
                Err(TransportError::Protocol(_))
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn limits_hosts_paths_addresses_and_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let (address, _) =
            server("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789").await?;
        assert!(matches!(
            http(address)
                .get("tuf-repo.github.com", "timestamp.json", 5)
                .await,
            Err(TransportError::BodyTooLarge { limit: 5 })
        ));
        let local = http(address);
        for (host, path) in [
            ("api.github.com", "timestamp.json"),
            ("tuf-repo.github.com", "../etc/passwd"),
            ("tuf-repo.github.com", "/timestamp.json"),
            ("tuf-repo.github.com", "a//b"),
            ("tuf-repo.github.com", "a b"),
        ] {
            assert!(
                matches!(
                    local.get(host, path, 100).await,
                    Err(TransportError::InvalidRequest)
                ),
                "{host} {path}"
            );
        }
        // Without the test allowance a loopback answer is refused.
        let strict = TufHttp::with_resolver(Plain, Loopback(address), HttpConfig::default());
        assert!(matches!(
            strict
                .get("tuf-repo.github.com", "timestamp.json", 100)
                .await,
            Err(TransportError::AddressRefused)
        ));
        Ok(())
    }
}
