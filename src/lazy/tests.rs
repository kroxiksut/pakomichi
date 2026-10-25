// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lazy fetch against a real CAS and generation store, with a loopback
//! stand-in for GitHub (plain TCP for TLS, a table for DNS).

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use super::*;
use crate::cas::{Sha256Digest, StoreConfig};
use crate::github::{AssetId, DownloadConfig, RepositoryId, TransportError};
use crate::publish::{
    Backend, GenerationMeta, GenerationStore, RepoName, RepoPath, SourceId, Timestamp,
};
use crate::reader::{DEFAULT_RETENTION, Lookup, Repositories};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PACKAGE: &[u8] = b"netwatch 0.35.4 package bytes";
const REPO: &str = "pakomichi-netwatch-strict";

struct Table(BTreeMap<String, Vec<SocketAddr>>);

impl Resolve for Table {
    async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, TransportError> {
        self.0.get(host).cloned().ok_or(TransportError::Resolve)
    }
}

struct Plain;

impl SecureConnector for Plain {
    type Stream = TcpStream;

    async fn connect(&self, _host: &str, address: SocketAddr) -> Result<TcpStream, TransportError> {
        TcpStream::connect(address)
            .await
            .map_err(|_| TransportError::Connect)
    }
}

/// The digest → asset pins, as the state owner would answer them.
struct Pins(BTreeMap<Sha256Digest, AssetLocator>);

impl Locate for Pins {
    fn locate(&self, object: &ExpectedObject) -> Option<AssetLocator> {
        self.0.get(&object.sha256).copied()
    }
}

/// A current-thread runtime on its own thread, as the reader process has
/// one; blocking fetches run on other threads and wait for it.
struct Background {
    runtime: Option<Runtime>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<Runtime>>,
}

impl Background {
    fn start() -> Result<(Self, Handle), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            runtime.block_on(async {
                let _ = stopped.await;
            });
            runtime
        });
        Ok((
            Self {
                runtime: None,
                stop: Some(stop),
                thread: Some(thread),
            },
            handle,
        ))
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take()
            && let Ok(runtime) = thread.join()
        {
            self.runtime = Some(runtime);
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Answers every connection with `response`, counting requests.
fn upstream(
    handle: &Handle,
    response: Vec<u8>,
) -> Result<(SocketAddr, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let listener = handle.block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))?;
    let address = listener.local_addr()?;
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    handle.spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            let response = response.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0_u8; 2048];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buffer[..read]),
                    }
                }
                // Slow enough that parallel requests overlap.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = socket.write_all(&response).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    Ok((address, count))
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn locator() -> Result<AssetLocator, Box<dyn std::error::Error>> {
    Ok(AssetLocator {
        repository: RepositoryId::new(1_107_372_470)?,
        asset: AssetId::new(664_783_235)?,
    })
}

struct World {
    _dir: TempDir,
    cas_root: std::path::PathBuf,
    publish_root: std::path::PathBuf,
    cas: Arc<Store>,
    package: ExpectedObject,
    pool: String,
}

/// A published generation whose package was stored, then lost from the CAS.
fn world() -> Result<World, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let cas_root = dir.join("cas");
    fs::create_dir(&cas_root)?;
    fs::set_permissions(&cas_root, fs::Permissions::from_mode(0o750))?;
    let cas = Arc::new(Store::open(&cas_root, StoreConfig::default())?);
    let publish_root = dir.join("publish");
    let (mut store, _) = GenerationStore::open(&publish_root)?;
    let mut objects = Vec::new();
    let mut put =
        |path: String, bytes: &[u8]| -> Result<ExpectedObject, Box<dyn std::error::Error>> {
            let stored = cas.insert(bytes)?;
            let object = ExpectedObject::new(stored.digest(), stored.size());
            objects.push((RepoPath::new(&path)?, object));
            Ok(object)
        };
    put(format!("dists/{REPO}/InRelease"), b"signed release")?;
    let index = b"Package: netwatch\n";
    let digest = Sha256Digest::of(index).to_hex();
    put(format!("dists/{REPO}/main/binary-amd64/Packages"), index)?;
    put(
        format!("dists/{REPO}/main/binary-amd64/by-hash/SHA256/{digest}"),
        index,
    )?;
    let pool = format!(
        "pool/{}/netwatch_0.35.4_amd64.deb",
        Sha256Digest::of(PACKAGE).to_hex()
    );
    let package = put(pool.clone(), PACKAGE)?;
    store.publish(
        GenerationMeta {
            repo: RepoName::new(REPO)?,
            source: SourceId::new("src-1")?,
            backend: Backend::Apt,
            valid_from: Timestamp::new("2026-10-23T10:00:00Z")?,
            valid_until: Timestamp::new("2099-10-30T10:00:00Z")?,
        },
        objects,
        &cas,
        SystemTime::now(),
    )?;
    fs::remove_file(cas.object_path(&package.sha256))?;
    Ok(World {
        _dir: dir,
        cas_root,
        publish_root,
        cas,
        package,
        pool,
    })
}

fn reader(
    world: &World,
    handle: &Handle,
    api: SocketAddr,
    pinned: bool,
) -> Result<Repositories, Box<dyn std::error::Error>> {
    let table = Table(BTreeMap::from([("api.github.com".to_owned(), vec![api])]));
    let config = DownloadConfig {
        idle_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(10),
        ..DownloadConfig::default()
    };
    let downloader = Arc::new(
        AssetDownloader::with_resolver(Plain, table, config, None)
            .allowing_test_servers(vec![api], api.port()),
    );
    let pins = if pinned {
        Pins(BTreeMap::from([(world.package.sha256, locator()?)]))
    } else {
        Pins(BTreeMap::new())
    };
    let fetcher = LazyFetcher::new(Arc::clone(&world.cas), downloader, pins, handle.clone());
    Ok(
        Repositories::open(&world.publish_root, &world.cas_root, DEFAULT_RETENTION)?
            .with_fetcher(Arc::new(fetcher)),
    )
}

fn lookup(repositories: &Repositories, world: &World) -> Lookup {
    repositories.lookup(&format!("/{REPO}/{}", world.pool), SystemTime::now())
}

fn served(lookup: Lookup) -> Result<Vec<u8>, String> {
    match lookup {
        Lookup::Found { object, .. } => {
            let mut bytes = Vec::new();
            object
                .into_file()
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            Ok(bytes)
        }
        other => Err(format!("{other:?}")),
    }
}

#[test]
fn a_package_lost_from_the_store_is_fetched_by_its_pin_and_served_verified() -> TestResult {
    let (_background, handle) = Background::start()?;
    let world = world()?;
    let (api, requests) = upstream(&handle, ok(PACKAGE))?;
    let repositories = reader(&world, &handle, api, true)?;
    assert_eq!(served(lookup(&repositories, &world))?, PACKAGE);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    // Stored now: the next request does not go upstream.
    assert_eq!(served(lookup(&repositories, &world))?, PACKAGE);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn n014_a_package_deleted_upstream_is_an_error_and_nothing_else_is_served() -> TestResult {
    let (_background, handle) = Background::start()?;
    let world = world()?;
    let gone = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    let (api, _) = upstream(&handle, gone)?;
    let repositories = reader(&world, &handle, api, true)?;
    match lookup(&repositories, &world) {
        Lookup::FetchFailed(error @ FetchError::Download(DownloadError::Gone { status: 404 })) => {
            assert_eq!(error.http_status(), 502, "{error}");
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert!(!world.cas.object_path(&world.package.sha256).exists());
    Ok(())
}

#[test]
fn substituted_bytes_from_upstream_never_enter_the_store() -> TestResult {
    let (_background, handle) = Background::start()?;
    let world = world()?;
    // Same size, other bytes: a replaced asset or a hostile mirror.
    let mut other = PACKAGE.to_vec();
    other[0] ^= 1;
    let (api, _) = upstream(&handle, ok(&other))?;
    let repositories = reader(&world, &handle, api, true)?;
    match lookup(&repositories, &world) {
        Lookup::FetchFailed(error @ FetchError::Store(CasError::DigestMismatch { .. })) => {
            assert_eq!(error.http_status(), 502);
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert!(!world.cas.object_path(&world.package.sha256).exists());
    let staging = fs::read_dir(world.cas_root.join("staging"))?.count();
    assert_eq!(staging, 0, "no partial file is left behind");
    Ok(())
}

#[test]
fn a_corrupt_copy_is_quarantined_and_the_pinned_bytes_are_fetched_again() -> TestResult {
    let (_background, handle) = Background::start()?;
    let world = world()?;
    let path = world.cas.object_path(&world.package.sha256);
    let mut corrupt = PACKAGE.to_vec();
    corrupt[3] ^= 0x20;
    fs::write(&path, &corrupt)?; // the copy was removed by world()
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
    let (api, requests) = upstream(&handle, ok(PACKAGE))?;
    let repositories = reader(&world, &handle, api, true)?;
    assert_eq!(served(lookup(&repositories, &world))?, PACKAGE);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let quarantined = fs::read_dir(world.cas_root.join("quarantine"))?.count();
    assert_eq!(quarantined, 1, "the corrupt copy is kept, not deleted");
    Ok(())
}

#[test]
fn parallel_requests_for_one_missing_package_download_it_once() -> TestResult {
    let (_background, handle) = Background::start()?;
    let world = world()?;
    let (api, requests) = upstream(&handle, ok(PACKAGE))?;
    let repositories = Arc::new(reader(&world, &handle, api, true)?);
    let target = format!("/{REPO}/{}", world.pool);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let repositories = Arc::clone(&repositories);
            let target = target.clone();
            std::thread::spawn(move || served(repositories.lookup(&target, SystemTime::now())))
        })
        .collect();
    for thread in threads {
        let bytes = thread.join().map_err(|_| "thread panicked")??;
        assert_eq!(bytes, PACKAGE);
    }
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn an_object_without_a_pin_is_never_fetched() -> TestResult {
    let (_background, handle) = Background::start()?;
    let world = world()?;
    let (api, requests) = upstream(&handle, ok(PACKAGE))?;
    let repositories = reader(&world, &handle, api, false)?;
    match lookup(&repositories, &world) {
        Lookup::FetchFailed(FetchError::NotPinned) => {}
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn every_fetch_failure_has_the_gateway_status_a_package_manager_understands() {
    let quota = CasError::QuotaExceeded {
        requested: 10,
        available: 0,
    };
    let mismatch = CasError::DigestMismatch {
        expected: Sha256Digest::of(b"a"),
        actual: Sha256Digest::of(b"b"),
    };
    for (error, status) in [
        (
            FetchError::Download(DownloadError::Gone { status: 404 }),
            502,
        ),
        (FetchError::Download(DownloadError::InsecureRedirect), 502),
        (
            FetchError::Download(DownloadError::Transport(TransportError::AddressRefused)),
            502,
        ),
        (FetchError::Download(DownloadError::Timeout), 504),
        (
            FetchError::Download(DownloadError::Transport(TransportError::Timeout)),
            504,
        ),
        (FetchError::Store(mismatch), 502),
        (FetchError::Store(quota), 507),
        (FetchError::NotPinned, 500),
    ] {
        assert_eq!(error.http_status(), status, "{error}");
    }
}

struct Answers(FetchError);

impl Fetch for Answers {
    fn fetch(&self, _object: ExpectedObject) -> Result<(), FetchError> {
        Err(match &self.0 {
            FetchError::Remote { status, message } => FetchError::Remote {
                status: *status,
                message: message.clone(),
            },
            _ => FetchError::NotPinned,
        })
    }
}

#[test]
fn the_reader_gets_the_state_owners_status_over_the_fetch_channel() -> TestResult {
    use crate::ipc::oneshot::{FETCH_LIMITS, serve_channel};
    use crate::ipc::server::PeerRule;
    let dir = TempDir::new()?;
    let object = ExpectedObject::new(Sha256Digest::of(PACKAGE), PACKAGE.len() as u64);
    for (status, seen) in [(502, 502), (504, 504), (507, 507), (418, 500)] {
        let path = dir.join(&format!("fetch-{status}.sock"));
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        let answers = Answers(FetchError::Remote {
            status,
            message: "upstream".to_owned(),
        });
        serve_channel(
            listener,
            PeerRule::AnyUser,
            FETCH_LIMITS,
            move |request, _uid| answer_fetch(&answers, request),
        )?;
        let error = FetchClient::new(&path, Duration::from_secs(5))
            .fetch(object)
            .err()
            .ok_or("no error")?;
        assert_eq!(error.http_status(), seen, "{status}: {error}");
    }
    // Nobody listens: the repository is unavailable, not the package gone.
    let missing = FetchClient::new(&dir.join("absent.sock"), Duration::from_secs(1));
    assert_eq!(
        missing.fetch(object).err().map(|e| e.http_status()),
        Some(503)
    );
    Ok(())
}

#[test]
fn a_stored_answer_for_another_object_is_not_taken_as_this_one() -> TestResult {
    // The reader would serve "fetched" for a package that is still missing,
    // and the client would get a 404 or other bytes instead of a 502.
    use crate::ipc::channels::{FetchResponse, Stored};
    use crate::ipc::oneshot::{FETCH_LIMITS, serve_channel};
    use crate::ipc::server::PeerRule;
    let dir = TempDir::new()?;
    let object = ExpectedObject::new(Sha256Digest::of(PACKAGE), PACKAGE.len() as u64);
    let path = dir.join("fetch.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    serve_channel(
        listener,
        PeerRule::AnyUser,
        FETCH_LIMITS,
        |_request: crate::ipc::channels::FetchRequest, _uid| {
            FetchResponse::Stored(Stored {
                sha256: Sha256Digest::of(b"another package").to_hex(),
            })
        },
    )?;
    let result = FetchClient::new(&path, Duration::from_secs(5)).fetch(object);
    assert_eq!(result.err().map(|error| error.http_status()), Some(500));
    Ok(())
}

#[test]
fn a_lost_generated_index_is_never_fetched_from_upstream() -> TestResult {
    // Only a package has a pinned upstream asset; a missing InRelease is the
    // publisher's fault. Fetching it would serve a release file that the
    // publisher did not sign in this generation.
    let (_background, handle) = Background::start()?;
    let world = world()?;
    let release = Sha256Digest::of(b"signed release");
    fs::remove_file(world.cas.object_path(&release))?;
    let (api, requests) = upstream(&handle, ok(b"signed release"))?;
    let table = Table(BTreeMap::from([("api.github.com".to_owned(), vec![api])]));
    let downloader = Arc::new(
        AssetDownloader::with_resolver(Plain, table, DownloadConfig::default(), None)
            .allowing_test_servers(vec![api], api.port()),
    );
    // Even with a pin for those bytes.
    let pins = Pins(BTreeMap::from([(release, locator()?)]));
    let fetcher = LazyFetcher::new(Arc::clone(&world.cas), downloader, pins, handle.clone());
    let repositories = Repositories::open(&world.publish_root, &world.cas_root, DEFAULT_RETENTION)?
        .with_fetcher(Arc::new(fetcher));
    let lookup = repositories.lookup(
        &format!("/{REPO}/dists/{REPO}/InRelease"),
        SystemTime::now(),
    );
    assert!(matches!(lookup, Lookup::ObjectRefused(_)), "{lookup:?}");
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "nothing was asked upstream"
    );
    Ok(())
}
