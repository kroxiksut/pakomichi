// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP/1.1 transport for the API origin over hyper.
//!
//! Each request resolves `api.github.com` once, refuses the whole answer
//! when any address is not public (R-004 conclusion 11), connects to a
//! vetted address through a [`SecureConnector`], sends one GET, and reads
//! the body up to the limit. There is no connection pool, no redirect
//! following, no proxy, no decompression, and no retry; the whole exchange
//! runs under one deadline.
//!
//! The TLS layer is the [`SecureConnector`] seam; the production
//! implementation is `RustlsConnector` (`tls`), and the loopback tests here
//! use a plain-TCP stand-in (see `docs/en/architecture/overview.md`, "HTTP
//! and TLS stack").

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use http_body_util::{BodyExt as _, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST,
    HeaderValue, IF_NONE_MATCH, USER_AGENT,
};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::transport::{
    API_HOST, API_VERSION, ApiRequest, ApiResponse, ResponseHeaders, Transport, TransportError,
};

/// HTTPS port of the API origin.
const API_PORT: u16 = 443;

/// At most this many resolved addresses are tried.
const MAX_ADDRESSES: usize = 4;

/// Longest response header value kept.
const MAX_HEADER_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConfig {
    pub connect_timeout: Duration,
    /// Deadline for resolution, connection, TLS, request, and the whole body.
    pub request_timeout: Duration,
    pub user_agent: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            user_agent: concat!("pakomichi/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }
}

/// Resolves a host name to socket addresses.
pub trait Resolve: Send + Sync {
    fn resolve(
        &self,
        host: &'static str,
        port: u16,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, TransportError>> + Send;
}

/// The operating system resolver through Tokio.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    async fn resolve(
        &self,
        host: &'static str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, TransportError> {
        tokio::net::lookup_host((host, port))
            .await
            .map(Iterator::collect)
            .map_err(|_| TransportError::Resolve)
    }
}

/// Opens a TCP connection to exactly `address` and authenticates the server
/// as `host` with TLS. Implementations must verify the certificate chain and
/// the host name and must not resolve `host` again.
pub trait SecureConnector: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn connect(
        &self,
        host: &'static str,
        address: SocketAddr,
    ) -> impl Future<Output = Result<Self::Stream, TransportError>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressPolicy {
    PublicOnly,
    #[cfg(test)]
    AllowLoopback,
}

pub struct HttpTransport<C, R = SystemResolver> {
    connector: C,
    resolver: R,
    config: HttpConfig,
    policy: AddressPolicy,
}

impl<C: SecureConnector> HttpTransport<C, SystemResolver> {
    pub fn new(connector: C, config: HttpConfig) -> Self {
        Self::with_resolver(connector, SystemResolver, config)
    }
}

impl<C: SecureConnector, R: Resolve> HttpTransport<C, R> {
    pub fn with_resolver(connector: C, resolver: R, config: HttpConfig) -> Self {
        Self {
            connector,
            resolver,
            config,
            policy: AddressPolicy::PublicOnly,
        }
    }

    /// TEST ONLY: also accepts loopback addresses, for local test servers.
    #[cfg(test)]
    pub(crate) fn allowing_loopback_for_tests(mut self) -> Self {
        self.policy = AddressPolicy::AllowLoopback;
        self
    }

    async fn send_within_deadline(
        &self,
        request: ApiRequest,
        max_body_bytes: usize,
    ) -> Result<ApiResponse, TransportError> {
        let addresses = self.resolver.resolve(API_HOST, API_PORT).await?;
        let addresses = vet_addresses(&addresses, self.policy)?;
        let mut failure = TransportError::Connect;
        for address in addresses {
            match timeout(
                self.config.connect_timeout,
                self.connector.connect(API_HOST, address),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    return exchange(stream, &request, &self.config.user_agent, max_body_bytes)
                        .await;
                }
                Ok(Err(error)) => failure = error,
                Err(_) => failure = TransportError::Timeout,
            }
        }
        Err(failure)
    }
}

impl<C: SecureConnector, R: Resolve> Transport for HttpTransport<C, R> {
    async fn send(
        &self,
        request: ApiRequest,
        max_body_bytes: usize,
    ) -> Result<ApiResponse, TransportError> {
        timeout(
            self.config.request_timeout,
            self.send_within_deadline(request, max_body_bytes),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
    }
}

/// Every resolved address must pass; a mixed answer is refused as a whole.
fn vet_addresses(
    addresses: &[SocketAddr],
    policy: AddressPolicy,
) -> Result<Vec<SocketAddr>, TransportError> {
    if addresses.is_empty() {
        return Err(TransportError::Resolve);
    }
    let allowed = |address: &SocketAddr| match policy {
        AddressPolicy::PublicOnly => is_public_address(address.ip()),
        #[cfg(test)]
        AddressPolicy::AllowLoopback => {
            address.ip().is_loopback() || is_public_address(address.ip())
        }
    };
    if !addresses.iter().all(allowed) {
        return Err(TransportError::AddressRefused);
    }
    Ok(addresses.iter().copied().take(MAX_ADDRESSES).collect())
}

/// Whether an address may be contacted on behalf of an untrusted source:
/// not loopback, private, link-local (including cloud metadata), shared,
/// benchmarking, documentation, multicast, reserved, or unspecified; IPv4
/// mapped and NAT64 forms are judged as IPv4.
pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_multicast()
                || address.is_documentation()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0))
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_address(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            if segments[0] == 0x64 && segments[1] == 0xff9b {
                let embedded = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                );
                return is_public_address(IpAddr::V4(embedded));
            }
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || segments[0] == 0x2002
                || (segments[0] == 0x2001 && segments[1] == 0))
        }
    }
}

/// Aborts the connection task when the exchange ends or is cancelled.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One request/response exchange on an established (TLS) stream.
pub(crate) async fn exchange<S>(
    stream: S,
    request: &ApiRequest,
    user_agent: &str,
    max_body_bytes: usize,
) -> Result<ApiResponse, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(|_| TransportError::Protocol("handshake"))?;
    let _driver = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));

    let mut builder = Request::get(request.path())
        .header(HOST, API_HOST)
        .header(USER_AGENT, user_agent)
        .header(ACCEPT, "application/vnd.github+json")
        .header("x-github-api-version", API_VERSION)
        .header(ACCEPT_ENCODING, "identity")
        .header(CONNECTION, "close");
    if let Some(etag) = request.if_none_match() {
        builder = builder.header(IF_NONE_MATCH, etag);
    }
    let mut http_request = builder
        .body(Empty::new())
        .map_err(|_| TransportError::InvalidRequest)?;
    if let Some(token) = request.token() {
        let mut value = HeaderValue::try_from(format!("Bearer {}", token.expose_secret()))
            .map_err(|_| TransportError::InvalidRequest)?;
        value.set_sensitive(true);
        http_request.headers_mut().insert(AUTHORIZATION, value);
    }

    let response = sender
        .send_request(http_request)
        .await
        .map_err(|_| TransportError::Protocol("no response"))?;
    let status = response.status().as_u16();
    let header_map = response.headers();

    if let Some(encoding) = header_map.get(CONTENT_ENCODING)
        && encoding.as_bytes() != b"identity"
    {
        return Err(TransportError::Protocol("unrequested content encoding"));
    }
    if let Some(length) = header_map.get(CONTENT_LENGTH) {
        let length: u64 = length
            .to_str()
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or(TransportError::Protocol("invalid content length"))?;
        if length > max_body_bytes as u64 {
            return Err(TransportError::BodyTooLarge {
                limit: max_body_bytes,
            });
        }
    }
    let mut headers = ResponseHeaders::default();
    for name in ResponseHeaders::NAMES {
        if let Some(value) = header_map.get(name) {
            if value.len() > MAX_HEADER_BYTES {
                return Err(TransportError::Protocol("oversized header"));
            }
            let text = value
                .to_str()
                .map_err(|_| TransportError::Protocol("non-ASCII header"))?;
            headers.set(name, text.to_owned());
        }
    }

    let mut body_stream = response.into_body();
    let mut body = Vec::new();
    while let Some(frame) = body_stream.frame().await {
        let frame = frame.map_err(|_| TransportError::Protocol("body"))?;
        if let Ok(data) = frame.into_data() {
            if body.len() + data.len() > max_body_bytes {
                return Err(TransportError::BodyTooLarge {
                    limit: max_body_bytes,
                });
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(ApiResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
