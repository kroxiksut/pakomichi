// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS tests on loopback only. Every certificate is a TEST ONLY throwaway
//! generated in memory by `rcgen`; nothing is written to disk. The server is
//! rustls itself, so these tests check our client configuration (roots,
//! SNI, name check, ALPN, versions) rather than interoperability, which the
//! ignored live test in `tests/github_live.rs` covers.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::github::http::{HttpConfig, HttpTransport, Resolve};
use crate::github::transport::{API_HOST, ApiRequest, Transport};

type TestResult = Result<(), Box<dyn Error>>;

/// A TEST ONLY certificate authority.
struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    fn new(common_name: &str) -> Result<Self, Box<dyn Error>> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, format!("TEST ONLY {common_name}"));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Ok(Self {
            issuer: CertifiedIssuer::self_signed(params, KeyPair::generate()?)?,
        })
    }

    fn roots(&self) -> Result<RootCertStore, Box<dyn Error>> {
        let mut roots = RootCertStore::empty();
        roots.add(self.issuer.der().clone())?;
        Ok(roots)
    }

    /// A server certificate for `name`; `expired` puts its validity in 2000.
    fn leaf(&self, name: &str, expired: bool) -> Result<Leaf, Box<dyn Error>> {
        let mut params = CertificateParams::new(vec![name.to_owned()])?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2000, 12, 31);
        }
        let key = KeyPair::generate()?;
        let certificate = params.signed_by(&key, &self.issuer)?;
        Ok(Leaf {
            chain: vec![certificate.der().clone(), self.issuer.der().clone()],
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
        })
    }
}

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
}

/// What the server saw from the client.
#[derive(Debug)]
struct Seen {
    server_name: Option<String>,
    alpn: Option<Vec<u8>>,
    version: Option<rustls::ProtocolVersion>,
    request_head: String,
}

struct FixedResolver(SocketAddr);

impl Resolve for FixedResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, TransportError> {
        Ok(vec![self.0])
    }
}

fn server_config(
    leaf: Leaf,
    versions: &[&'static SupportedProtocolVersion],
) -> Result<Arc<ServerConfig>, Box<dyn Error>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .with_no_client_auth()
        .with_single_cert(leaf.chain, PrivateKeyDer::Pkcs8(leaf.key))?;
    // Prefers h2: the client must still end up on HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts one TLS connection, records what the client sent, and answers
/// one request with a small JSON body. `None` when the handshake failed.
async fn serve_tls_once(
    config: Arc<ServerConfig>,
) -> Result<(SocketAddr, JoinHandle<Option<Seen>>), Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.ok()?;
        let mut stream = TlsAcceptor::from(config).accept(socket).await.ok()?;
        let (_, connection) = stream.get_ref();
        let mut seen = Seen {
            server_name: connection.server_name().map(str::to_owned),
            alpn: connection.alpn_protocol().map(<[u8]>::to_vec),
            version: connection.protocol_version(),
            request_head: String::new(),
        };
        let mut head = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.ok()?;
            if read == 0 {
                break;
            }
            head.extend_from_slice(&buffer[..read]);
        }
        seen.request_head = String::from_utf8_lossy(&head).into_owned();
        let body = br#"{"ok":true}"#;
        let mut response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        response.extend_from_slice(body);
        stream.write_all(&response).await.ok()?;
        let _ = stream.shutdown().await;
        Some(seen)
    });
    Ok((address, handle))
}

/// Accepts one TCP connection and answers in plain text, not TLS.
async fn serve_plaintext_once() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer).await;
            let _ = socket
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    Ok(address)
}

fn transport(
    roots: RootCertStore,
    address: SocketAddr,
) -> Result<HttpTransport<RustlsConnector, FixedResolver>, Box<dyn Error>> {
    let config = HttpConfig {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        ..HttpConfig::default()
    };
    Ok(HttpTransport::with_resolver(
        RustlsConnector::with_test_only_roots(roots)?,
        FixedResolver(address),
        config,
    )
    .allowing_loopback_for_tests())
}

fn request() -> Result<ApiRequest, TransportError> {
    ApiRequest::new("/repositories/1".to_owned(), None, None)
}

#[test]
fn an_empty_or_unusable_root_store_is_an_error() {
    assert_eq!(
        root_store(Vec::new(), 0).err(),
        Some(TlsSetupError::NoRootCertificates {
            load_errors: 0,
            unparsable: 0
        })
    );
    let garbage = CertificateDer::from(b"not a certificate".to_vec());
    assert_eq!(
        root_store(vec![garbage], 2).err(),
        Some(TlsSetupError::NoRootCertificates {
            load_errors: 2,
            unparsable: 1
        })
    );
}

#[test]
fn a_usable_root_is_accepted() -> TestResult {
    let ca = TestCa::new("root")?;
    let roots = root_store(vec![ca.issuer.der().clone()], 0)?;
    assert_eq!(roots.len(), 1);
    Ok(())
}

#[test]
fn the_client_offers_only_http_1_1_and_keeps_sni() -> TestResult {
    let ca = TestCa::new("root")?;
    let connector = RustlsConnector::with_test_only_roots(ca.roots()?)?;
    let config = connector.tls.config();
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    assert!(config.enable_sni);
    assert!(!config.enable_early_data);
    assert!(!config.key_log.will_log("CLIENT_RANDOM"));
    Ok(())
}

#[tokio::test]
async fn a_trusted_server_is_reached_over_tls_1_3_with_sni() -> TestResult {
    let ca = TestCa::new("root")?;
    let config = server_config(ca.leaf(API_HOST, false)?, rustls::ALL_VERSIONS)?;
    let (address, server) = serve_tls_once(config).await?;

    let reply = transport(ca.roots()?, address)?
        .send(request()?, 1024)
        .await?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, br#"{"ok":true}"#);

    let seen = server.await?.ok_or("server handshake failed")?;
    assert_eq!(seen.server_name.as_deref(), Some(API_HOST));
    assert_eq!(seen.alpn.as_deref(), Some(&b"http/1.1"[..]));
    assert_eq!(seen.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert!(
        seen.request_head
            .starts_with("GET /repositories/1 HTTP/1.1\r\n"),
        "{}",
        seen.request_head
    );
    Ok(())
}

#[tokio::test]
async fn a_tls_1_2_only_server_is_accepted() -> TestResult {
    let ca = TestCa::new("root")?;
    let config = server_config(ca.leaf(API_HOST, false)?, &[&rustls::version::TLS12])?;
    let (address, server) = serve_tls_once(config).await?;

    let reply = transport(ca.roots()?, address)?
        .send(request()?, 1024)
        .await?;
    assert_eq!(reply.status, 200);
    let seen = server.await?.ok_or("server handshake failed")?;
    assert_eq!(seen.version, Some(rustls::ProtocolVersion::TLSv1_2));
    Ok(())
}

#[tokio::test]
async fn an_untrusted_issuer_is_rejected() -> TestResult {
    let trusted = TestCa::new("trusted")?;
    let other = TestCa::new("intercepting proxy")?;
    let config = server_config(other.leaf(API_HOST, false)?, rustls::ALL_VERSIONS)?;
    let (address, server) = serve_tls_once(config).await?;

    let result = transport(trusted.roots()?, address)?
        .send(request()?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::Certificate));
    assert!(server.await?.is_none());
    Ok(())
}

#[tokio::test]
async fn a_certificate_for_another_name_is_rejected() -> TestResult {
    let ca = TestCa::new("root")?;
    let config = server_config(
        ca.leaf("api.github.com.evil.example", false)?,
        rustls::ALL_VERSIONS,
    )?;
    let (address, _server) = serve_tls_once(config).await?;

    let result = transport(ca.roots()?, address)?
        .send(request()?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::Certificate));
    Ok(())
}

#[tokio::test]
async fn an_expired_certificate_is_rejected() -> TestResult {
    let ca = TestCa::new("root")?;
    let config = server_config(ca.leaf(API_HOST, true)?, rustls::ALL_VERSIONS)?;
    let (address, _server) = serve_tls_once(config).await?;

    let result = transport(ca.roots()?, address)?
        .send(request()?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::Certificate));
    Ok(())
}

#[tokio::test]
async fn a_server_without_http_1_1_alpn_fails_the_handshake() -> TestResult {
    let ca = TestCa::new("root")?;
    let shared = server_config(ca.leaf(API_HOST, false)?, rustls::ALL_VERSIONS)?;
    let mut config = Arc::try_unwrap(shared).map_err(|_| "server config is shared")?;
    // A server that speaks only h2 must not get an HTTP/1.1 request.
    config.alpn_protocols = vec![b"h2".to_vec()];
    let (address, server) = serve_tls_once(Arc::new(config)).await?;

    let result = transport(ca.roots()?, address)?
        .send(request()?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::Tls));
    assert!(server.await?.is_none());
    Ok(())
}

#[tokio::test]
async fn a_plaintext_server_fails_the_handshake() -> TestResult {
    let ca = TestCa::new("root")?;
    let address = serve_plaintext_once().await?;

    let result = transport(ca.roots()?, address)?
        .send(request()?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::Tls));
    Ok(())
}
