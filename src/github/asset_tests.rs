// SPDX-License-Identifier: MIT OR Apache-2.0

//! Asset download tests on loopback only: plain TCP stands in for TLS and
//! a table stands in for DNS. No external network.

use std::collections::BTreeMap;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

const CDN: &str = "release-assets.githubusercontent.com";
const LOCATOR: AssetLocator = AssetLocator {
    repository: match RepositoryId::new(1_107_372_470) {
        Ok(id) => id,
        Err(_) => panic!("id"),
    },
    asset: match AssetId::new(664_783_235) {
        Ok(id) => id,
        Err(_) => panic!("id"),
    },
};

/// Host name to addresses, as a hostile or broken DNS might answer.
struct TableResolver(BTreeMap<String, Vec<SocketAddr>>);

impl Resolve for TableResolver {
    async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, TransportError> {
        self.0.get(host).cloned().ok_or(TransportError::Resolve)
    }
}

/// Plain TCP; records every address it connects to.
#[derive(Clone, Default)]
struct RecordingConnector(Arc<Mutex<Vec<(String, SocketAddr)>>>);

impl RecordingConnector {
    fn connections(&self) -> Vec<(String, SocketAddr)> {
        self.0.lock().map(|list| list.clone()).unwrap_or_default()
    }
}

impl SecureConnector for RecordingConnector {
    type Stream = TcpStream;

    async fn connect(&self, host: &str, address: SocketAddr) -> Result<TcpStream, TransportError> {
        if let Ok(mut list) = self.0.lock() {
            list.push((host.to_owned(), address));
        }
        TcpStream::connect(address)
            .await
            .map_err(|_| TransportError::Connect)
    }
}

/// Serves each accepted connection with the next canned response and
/// keeps every request head.
struct Server {
    address: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

async fn server(responses: Vec<Vec<u8>>) -> Result<Server, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let heads = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&heads);
    tokio::spawn(async move {
        for response in responses {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            let mut buffer = [0_u8; 2048];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => head.extend_from_slice(&buffer[..read]),
                }
            }
            if let Ok(mut list) = kept.lock() {
                list.push(String::from_utf8_lossy(&head).into_owned());
            }
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        }
    });
    Ok(Server { address, heads })
}

fn redirect(location: &str) -> Vec<u8> {
    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn downloader(
    hosts: &[(&str, Vec<SocketAddr>)],
    servers: Vec<SocketAddr>,
    port: u16,
    connector: RecordingConnector,
) -> AssetDownloader<RecordingConnector, TableResolver> {
    let table = hosts
        .iter()
        .map(|(host, addresses)| ((*host).to_owned(), addresses.clone()))
        .collect();
    let config = DownloadConfig {
        idle_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(10),
        ..DownloadConfig::default()
    };
    let token = Token::new("ghp_TESTONLYnotarealtoken".to_owned()).ok();
    AssetDownloader::with_resolver(connector, TableResolver(table), config, token)
        .allowing_test_servers(servers, port)
}

async fn fetch(
    downloader: &AssetDownloader<RecordingConnector, TableResolver>,
    size: u64,
) -> (Result<u64, DownloadError>, Vec<u8>) {
    let mut bytes = Vec::new();
    let result = downloader
        .download(LOCATOR, size, &mut |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
        .await;
    (result, bytes)
}

#[tokio::test(flavor = "current_thread")]
async fn the_asset_comes_through_the_api_redirect_and_only_the_api_sees_the_token() -> TestResult {
    let cdn = server(vec![ok(b"package bytes")]).await?;
    let port = cdn.address.port();
    let api = server(vec![redirect(&format!(
        "https://{CDN}:443/github-production-release-asset/1?sp=r&sig=abc%3D&rscd=attachment%3B+filename%3Dx.deb"
    ))])
    .await?;
    let connector = RecordingConnector::default();
    let downloader = downloader(
        &[(API_HOST, vec![api.address]), (CDN, vec![cdn.address])],
        vec![api.address, cdn.address],
        port,
        connector.clone(),
    );
    let (result, bytes) = fetch(&downloader, 13).await;
    assert_eq!(result?, 13);
    assert_eq!(bytes, b"package bytes");
    let api_head = api.heads.lock().map(|h| h.join("")).unwrap_or_default();
    let cdn_head = cdn.heads.lock().map(|h| h.join("")).unwrap_or_default();
    assert!(
        api_head.starts_with("GET /repositories/1107372470/releases/assets/664783235 HTTP/1.1")
    );
    assert!(
        api_head
            .to_ascii_lowercase()
            .contains("authorization: bearer ghp_testonly")
    );
    assert!(api_head.contains("application/octet-stream"));
    assert!(cdn_head.starts_with("GET /github-production-release-asset/1?sp=r&sig=abc%3D"));
    assert!(
        !cdn_head.to_ascii_lowercase().contains("authorization"),
        "{cdn_head}"
    );
    assert_eq!(
        connector
            .connections()
            .iter()
            .map(|(host, _)| host.as_str())
            .collect::<Vec<_>>(),
        [API_HOST, CDN]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn n019_a_redirect_to_a_local_or_metadata_address_is_never_connected() -> TestResult {
    // The asset host resolves to loopback, metadata, or private addresses:
    // a poisoned or hostile DNS answer for an allowed name.
    for forbidden in [
        "127.0.0.1:22",
        "169.254.169.254:443",
        "10.0.0.1:443",
        "[::1]:22",
    ] {
        let forbidden: SocketAddr = forbidden.parse()?;
        let api = server(vec![redirect(&format!("https://{CDN}/asset"))]).await?;
        let connector = RecordingConnector::default();
        let downloader = downloader(
            &[(API_HOST, vec![api.address]), (CDN, vec![forbidden])],
            vec![api.address],
            api.address.port(),
            connector.clone(),
        );
        let (result, bytes) = fetch(&downloader, 13).await;
        assert!(
            matches!(
                result,
                Err(DownloadError::Transport(TransportError::AddressRefused))
            ),
            "{forbidden}: {result:?}"
        );
        assert!(bytes.is_empty());
        assert!(
            connector
                .connections()
                .iter()
                .all(|(_, address)| *address != forbidden),
            "connected to {forbidden}"
        );
    }
    // One forbidden address among public ones refuses the whole answer.
    let api = server(vec![redirect(&format!("https://{CDN}/asset"))]).await?;
    let mixed = vec!["140.82.112.3:443".parse()?, "127.0.0.1:443".parse()?];
    let connector = RecordingConnector::default();
    let downloader = downloader(
        &[(API_HOST, vec![api.address]), (CDN, mixed)],
        vec![api.address],
        api.address.port(),
        connector.clone(),
    );
    assert!(matches!(
        fetch(&downloader, 13).await.0,
        Err(DownloadError::Transport(TransportError::AddressRefused))
    ));
    assert_eq!(connector.connections().len(), 1, "only the API hop");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_redirect_off_https_or_off_the_asset_hosts_is_refused() -> TestResult {
    type Check = fn(&DownloadError) -> bool;
    let cases: [(&str, Check); 8] = [
        ("http://release-assets.githubusercontent.com/a", |e| {
            matches!(e, DownloadError::InsecureRedirect)
        }),
        ("https://evil.example/a", |e| {
            matches!(e, DownloadError::HostRefused(_))
        }),
        ("https://127.0.0.1/a", |e| {
            matches!(e, DownloadError::BadLocation)
        }),
        (
            "https://user:pass@release-assets.githubusercontent.com/a",
            |e| matches!(e, DownloadError::BadLocation),
        ),
        ("https://release-assets.githubusercontent.com:8443/a", |e| {
            matches!(e, DownloadError::BadLocation)
        }),
        ("https://release-assets.githubusercontent.com/a#frag", |e| {
            matches!(e, DownloadError::BadLocation)
        }),
        ("//release-assets.githubusercontent.com/a", |e| {
            matches!(e, DownloadError::BadLocation)
        }),
        ("file:///etc/passwd", |e| {
            matches!(e, DownloadError::InsecureRedirect)
        }),
    ];
    for (location, expected) in cases {
        let api = server(vec![redirect(location)]).await?;
        let connector = RecordingConnector::default();
        let downloader = downloader(
            &[(API_HOST, vec![api.address]), (CDN, vec![api.address])],
            vec![api.address],
            api.address.port(),
            connector.clone(),
        );
        let (result, _) = fetch(&downloader, 13).await;
        assert!(
            result.as_ref().is_err_and(expected),
            "{location}: {result:?}"
        );
        assert_eq!(
            connector.connections().len(),
            1,
            "{location}: no second hop"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_redirect_loop_ends_after_the_limit() -> TestResult {
    let api = server(vec![redirect("/again"); 5]).await?;
    let downloader = downloader(
        &[(API_HOST, vec![api.address])],
        vec![api.address],
        api.address.port(),
        RecordingConnector::default(),
    );
    assert!(matches!(
        fetch(&downloader, 13).await.0,
        Err(DownloadError::TooManyRedirects)
    ));
    assert_eq!(
        api.heads.lock().map(|h| h.len()).unwrap_or_default(),
        4,
        "1 + 3 redirects"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn bytes_of_another_size_never_reach_the_sink_as_complete() -> TestResult {
    // Announced size differs: refused before any body byte.
    let api = server(vec![ok(b"fourteen bytes")]).await?;
    let one = downloader(
        &[(API_HOST, vec![api.address])],
        vec![api.address],
        api.address.port(),
        RecordingConnector::default(),
    );
    let (result, bytes) = fetch(&one, 13).await;
    assert!(
        matches!(
            result,
            Err(DownloadError::SizeMismatch {
                expected: 13,
                announced: 14
            })
        ),
        "{result:?}"
    );
    assert!(bytes.is_empty());
    // No length announced, and the body runs past the pinned size.
    let long =
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nthis body is longer than pinned".to_vec();
    let api = server(vec![long]).await?;
    let two = downloader(
        &[(API_HOST, vec![api.address])],
        vec![api.address],
        api.address.port(),
        RecordingConnector::default(),
    );
    let (result, bytes) = fetch(&two, 13).await;
    assert!(
        matches!(result, Err(DownloadError::TooLong { expected: 13 })),
        "{result:?}"
    );
    assert!(
        bytes.len() <= 13,
        "nothing past the pinned size is passed on"
    );
    // The connection closes early.
    let short = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nshort".to_vec();
    let api = server(vec![short]).await?;
    let three = downloader(
        &[(API_HOST, vec![api.address])],
        vec![api.address],
        api.address.port(),
        RecordingConnector::default(),
    );
    assert!(matches!(
        fetch(&three, 13).await.0,
        Err(DownloadError::Truncated { received: 5, .. })
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn n014_a_deleted_asset_is_gone_and_a_stalled_one_times_out() -> TestResult {
    let api = server(vec![
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    ])
    .await?;
    let gone = downloader(
        &[(API_HOST, vec![api.address])],
        vec![api.address],
        api.address.port(),
        RecordingConnector::default(),
    );
    assert!(matches!(
        fetch(&gone, 13).await.0,
        Err(DownloadError::Gone { status: 404 })
    ));
    // Headers arrive, then the body stalls.
    let stall = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\npart".to_vec();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buffer = [0_u8; 2048];
            let _ = socket.read(&mut buffer).await;
            let _ = socket.write_all(&stall).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    let stalled = downloader(
        &[(API_HOST, vec![address])],
        vec![address],
        address.port(),
        RecordingConnector::default(),
    );
    let started = std::time::Instant::now();
    assert!(matches!(
        fetch(&stalled, 13).await.0,
        Err(DownloadError::Timeout)
    ));
    // The idle deadline (2 s) fires, not the total one (10 s).
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

#[test]
fn host_names_and_targets_are_checked_before_any_lookup() {
    for host in ["release-assets.githubusercontent.com", "a.b"] {
        assert!(is_host_name(host), "{host}");
    }
    for host in [
        "127.0.0.1",
        "localhost",
        "Example.COM",
        "a..b",
        "-a.b",
        "a.b-",
        "[::1]",
        "",
    ] {
        assert!(!is_host_name(host), "{host}");
    }
    assert!(is_safe_target("/a?b=c%3D&d=e+f"));
    for target in ["a", "//x", "/a b", "/a#b", "/a\\b", "/a\"b"] {
        assert!(!is_safe_target(target), "{target:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_fake_ip_range_is_used_only_when_the_operator_allows_it() -> TestResult {
    // A fake-IP DNS (a local proxy or traffic router) answers asset hosts
    // from 198.18.0.0/15. Refused by default; allowed only when listed.
    let fake: SocketAddr = "198.18.1.177:443".parse()?;
    let api = server(vec![redirect(&format!("https://{CDN}/asset"))]).await?;
    let connector = RecordingConnector::default();
    let refused = downloader(
        &[(API_HOST, vec![api.address]), (CDN, vec![fake])],
        vec![api.address],
        api.address.port(),
        connector.clone(),
    );
    assert!(matches!(
        fetch(&refused, 13).await.0,
        Err(DownloadError::Transport(TransportError::AddressRefused))
    ));
    assert!(
        connector
            .connections()
            .iter()
            .all(|(_, address)| *address != fake)
    );
    let api = server(vec![redirect(&format!("https://{CDN}/asset"))]).await?;
    let connector = RecordingConnector::default();
    let mut allowed = downloader(
        &[(API_HOST, vec![api.address]), (CDN, vec![fake])],
        vec![api.address],
        api.address.port(),
        connector.clone(),
    );
    allowed.config.extra_ranges = vec![AddressRange::parse("198.18.0.0/15")?];
    // Nothing listens there; what matters is that it is dialled.
    let _ = fetch(&allowed, 13).await;
    assert!(
        connector
            .connections()
            .iter()
            .any(|(_, address)| *address == fake)
    );
    Ok(())
}

#[test]
fn a_range_that_reaches_local_or_metadata_addresses_cannot_be_allowed() {
    for range in [
        "169.254.0.0/16",
        "169.254.169.254/32",
        "127.0.0.0/8",
        "0.0.0.0/0",
        "128.0.0.0/1",
        "224.0.0.0/4",
        "::1/128",
        "fe80::/10",
        "::/0",
        "198.18.0.0/33",
        "198.18.0.1/15",
        "nonsense",
    ] {
        assert!(AddressRange::parse(range).is_err(), "{range}");
    }
    for range in ["198.18.0.0/15", "100.64.0.0/10", "fd00::/8"] {
        assert!(AddressRange::parse(range).is_ok(), "{range}");
    }
}
