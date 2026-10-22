// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport tests on loopback only: a plain-TCP test connector stands in
//! for TLS, and a fixed resolver stands in for DNS. No external network.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::github::token::Token;

type TestResult = Result<(), Box<dyn Error>>;

struct FixedResolver(Vec<SocketAddr>);

impl Resolve for FixedResolver {
    async fn resolve(
        &self,
        _host: &'static str,
        _port: u16,
    ) -> Result<Vec<SocketAddr>, TransportError> {
        Ok(self.0.clone())
    }
}

/// TEST ONLY: plain TCP in place of TLS.
#[derive(Default)]
struct PlainConnector {
    calls: AtomicUsize,
}

impl SecureConnector for PlainConnector {
    type Stream = TcpStream;

    async fn connect(
        &self,
        _host: &'static str,
        address: SocketAddr,
    ) -> Result<TcpStream, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        TcpStream::connect(address)
            .await
            .map_err(|_| TransportError::Connect)
    }
}

fn loopback_transport(
    address: SocketAddr,
    config: HttpConfig,
) -> HttpTransport<PlainConnector, FixedResolver> {
    let mut transport = HttpTransport::with_resolver(
        PlainConnector::default(),
        FixedResolver(vec![address]),
        config,
    );
    transport.policy = AddressPolicy::AllowLoopback;
    transport
}

/// Accepts one connection, captures the request head, and writes `response`
/// (or stalls when `None`).
async fn serve_once(
    response: Option<Vec<u8>>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<Option<String>>), Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.ok()?;
        let mut head = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.ok()?;
            if read == 0 {
                break;
            }
            head.extend_from_slice(&buffer[..read]);
        }
        match response {
            Some(response) => {
                socket.write_all(&response).await.ok()?;
                let _ = socket.shutdown().await;
            }
            None => tokio::time::sleep(Duration::from_secs(30)).await,
        }
        Some(String::from_utf8_lossy(&head).into_owned())
    });
    Ok((address, handle))
}

fn request(
    path: &str,
    etag: Option<&str>,
    token: Option<Token>,
) -> Result<ApiRequest, TransportError> {
    ApiRequest::new(path.to_owned(), etag.map(str::to_owned), token)
}

#[test]
fn only_public_addresses_are_allowed() -> TestResult {
    for text in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "198.18.0.1",
        "192.0.2.1",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "::1",
        "::",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a9fe:a9fe",
        "2001:db8::1",
    ] {
        assert!(!is_public_address(text.parse()?), "{text}");
    }
    for text in ["140.82.112.6", "2606:50c0:8000::154", "64:ff9b::8c52:7006"] {
        assert!(is_public_address(text.parse()?), "{text}");
    }
    Ok(())
}

#[tokio::test]
async fn a_mixed_or_private_answer_is_refused_before_connecting() -> TestResult {
    for addresses in [
        vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 443))],
        vec![
            SocketAddr::from((Ipv4Addr::new(140, 82, 112, 6), 443)),
            SocketAddr::from((Ipv4Addr::new(169, 254, 169, 254), 443)),
        ],
    ] {
        let transport = HttpTransport::with_resolver(
            PlainConnector::default(),
            FixedResolver(addresses),
            HttpConfig::default(),
        );
        let result = transport
            .send(request("/repositories/1", None, None)?, 1024)
            .await;
        assert_eq!(result, Err(TransportError::AddressRefused));
        assert_eq!(transport.connector.calls.load(Ordering::SeqCst), 0);
    }
    let empty = HttpTransport::with_resolver(
        PlainConnector::default(),
        FixedResolver(Vec::new()),
        HttpConfig::default(),
    );
    assert_eq!(
        empty
            .send(request("/repositories/1", None, None)?, 1024)
            .await,
        Err(TransportError::Resolve)
    );
    Ok(())
}

#[tokio::test]
async fn request_headers_and_kept_response_headers() -> TestResult {
    let body = br#"{"id":1}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: W/\"abc\"\r\nLink: <https://api.github.com/x?page=2>; rel=\"next\"\r\nX-RateLimit-Remaining: 59\r\nX-RateLimit-Reset: 1792485303\r\nSet-Cookie: dropped=1\r\n\r\n",
        body.len()
    );
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);
    let (address, server) = serve_once(Some(bytes)).await?;
    let transport = loopback_transport(address, HttpConfig::default());
    let token = Token::new("sample-credential-value".to_owned())?;

    let reply = transport
        .send(
            request("/repositories/1", Some("W/\"abc\""), Some(token))?,
            1024,
        )
        .await?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, body);
    assert_eq!(reply.headers.etag.as_deref(), Some("W/\"abc\""));
    assert_eq!(reply.headers.ratelimit_remaining.as_deref(), Some("59"));
    assert!(reply.headers.link.is_some());

    let head = server.await?.ok_or("server failed")?.to_ascii_lowercase();
    assert!(
        head.starts_with("get /repositories/1 http/1.1\r\n"),
        "{head}"
    );
    for line in [
        "host: api.github.com",
        "user-agent: pakomichi/",
        "accept: application/vnd.github+json",
        "x-github-api-version: 2022-11-28",
        "accept-encoding: identity",
        "if-none-match: w/\"abc\"",
        "authorization: bearer sample-credential-value",
    ] {
        assert!(head.contains(line), "missing {line:?} in {head}");
    }
    Ok(())
}

#[tokio::test]
async fn anonymous_requests_carry_no_authorization() -> TestResult {
    let (address, server) = serve_once(Some(
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ))
    .await?;
    let transport = loopback_transport(address, HttpConfig::default());
    let reply = transport
        .send(request("/repositories/1", None, None)?, 1024)
        .await?;
    assert_eq!(reply.status, 404);
    let head = server.await?.ok_or("server failed")?.to_ascii_lowercase();
    assert!(!head.contains("authorization"));
    assert!(!head.contains("if-none-match"));
    Ok(())
}

#[tokio::test]
async fn declared_oversized_bodies_are_refused_before_reading() -> TestResult {
    let (address, _server) = serve_once(Some(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n".to_vec(),
    ))
    .await?;
    let transport = loopback_transport(address, HttpConfig::default());
    let result = transport
        .send(request("/repositories/1", None, None)?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::BodyTooLarge { limit: 1024 }));
    Ok(())
}

#[tokio::test]
async fn chunked_bodies_stop_at_the_limit() -> TestResult {
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..4 {
        response.extend_from_slice(b"200\r\n");
        response.extend_from_slice(&[b'x'; 0x200]);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\n\r\n");
    let (address, _server) = serve_once(Some(response)).await?;
    let transport = loopback_transport(address, HttpConfig::default());
    let result = transport
        .send(request("/repositories/1", None, None)?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::BodyTooLarge { limit: 1024 }));
    Ok(())
}

#[tokio::test]
async fn compressed_bodies_are_refused() -> TestResult {
    let (address, _server) = serve_once(Some(
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
    ))
    .await?;
    let transport = loopback_transport(address, HttpConfig::default());
    let result = transport
        .send(request("/repositories/1", None, None)?, 1024)
        .await;
    assert_eq!(
        result,
        Err(TransportError::Protocol("unrequested content encoding"))
    );
    Ok(())
}

#[tokio::test]
async fn a_stalled_server_hits_the_deadline() -> TestResult {
    let (address, server) = serve_once(None).await?;
    let config = HttpConfig {
        request_timeout: Duration::from_millis(300),
        ..HttpConfig::default()
    };
    let transport = loopback_transport(address, config);
    let result = transport
        .send(request("/repositories/1", None, None)?, 1024)
        .await;
    assert_eq!(result, Err(TransportError::Timeout));
    server.abort();
    Ok(())
}
