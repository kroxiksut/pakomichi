// SPDX-License-Identifier: MIT OR Apache-2.0

//! Downloading the bytes of a pinned release asset (P3-005b,
//! `architecture/delivery-recovery.md` "Lazy fetch", R-004 conclusion 11).
//!
//! The first request goes to the API origin by numeric IDs
//! (`/repositories/<id>/releases/assets/<id>`, `Accept:
//! application/octet-stream`), so a renamed or transferred repository
//! cannot redirect it, and it is the only request that carries the token.
//! GitHub answers with a redirect to a signed URL on its asset host. Every
//! hop:
//!
//! - must be `https`, without credentials in the URL, on port 443, to the
//!   API origin or one of the configured asset hosts (no IP literals);
//! - resolves the host once, refuses the hop when any resolved address is
//!   not public (loopback, private, link-local and metadata, …), and
//!   connects only to a vetted address with TLS for that host name;
//! - counts towards at most `max_redirects` redirects.
//!
//! The final body must have exactly the pinned size: a `Content-Length`
//! that differs is refused before the body, and reading stops at the first
//! byte past the size. Every chunk goes to the caller's sink as it
//! arrives; the sink (the CAS staging file) checks the digest, and nothing
//! is trusted before that check. Each read has an idle deadline, and the
//! whole download has a total one.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use http_body_util::{BodyExt as _, Empty};
use hyper::Request;
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST,
    HeaderValue, LOCATION, USER_AGENT,
};
use hyper_util::rt::TokioIo;
use tokio::time::{Instant, timeout, timeout_at};

use super::http::{AbortOnDrop, Resolve, SecureConnector, SystemResolver, is_public_address};
use super::identity::{AssetId, RepositoryId};
use super::token::Token;
use super::transport::{API_HOST, API_VERSION, TransportError};

/// GitHub's hosts for release asset downloads, as of 2026.
pub const ASSET_HOSTS: [&str; 2] = [
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
const HTTPS_PORT: u16 = 443;
const MAX_ADDRESSES: usize = 4;
const MAX_TARGET_BYTES: usize = 8 * 1024;

/// Where a pinned asset lives, by IDs only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetLocator {
    pub repository: RepositoryId,
    pub asset: AssetId,
}

/// A network range the operator explicitly allows besides public
/// addresses, for example `198.18.0.0/15` when a fake-IP DNS of a local
/// proxy answers the asset hosts. A range that reaches loopback,
/// link-local (cloud metadata), unspecified, or multicast addresses is
/// refused, whatever the operator asks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    network: IpAddr,
    prefix: u8,
}

/// Why a range cannot be allowed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeRefused(pub String);

impl fmt::Display for RangeRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "address range {:?} cannot be allowed", self.0)
    }
}

impl std::error::Error for RangeRefused {}

fn bits(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(address) => (u128::from(u32::from(address)), 32),
        IpAddr::V6(address) => (u128::from(address), 128),
    }
}

fn mask(prefix: u8, width: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        (u128::MAX << (width - prefix)) & (u128::MAX >> (128 - width))
    }
}

impl AddressRange {
    /// `a.b.c.d/n` or an IPv6 prefix, canonical (no host bits set).
    pub fn parse(text: &str) -> Result<Self, RangeRefused> {
        let refused = || RangeRefused(text.to_owned());
        let (network, prefix) = text.split_once('/').ok_or_else(refused)?;
        let network: IpAddr = network.parse().map_err(|_| refused())?;
        let prefix: u8 = prefix.parse().map_err(|_| refused())?;
        let (value, width) = bits(network);
        if prefix > width || value & !mask(prefix, width) != 0 {
            return Err(refused());
        }
        let range = Self { network, prefix };
        // Two aligned prefixes overlap exactly when one holds the other's
        // network address.
        let forbidden = [
            "127.0.0.0/8",
            "169.254.0.0/16",
            "0.0.0.0/8",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "::1/128",
            "::/128",
            "fe80::/10",
            "ff00::/8",
        ];
        let overlaps = forbidden.iter().any(|block| {
            let Some((address, length)) = block.split_once('/') else {
                return true;
            };
            match (address.parse::<IpAddr>(), length.parse::<u8>()) {
                (Ok(address), Ok(length)) => {
                    let block = Self {
                        network: address,
                        prefix: length,
                    };
                    block.contains(range.network) || range.contains(block.network)
                }
                _ => true,
            }
        });
        if overlaps {
            return Err(refused());
        }
        Ok(range)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (network, width) = bits(self.network);
        let (value, ip_width) = bits(ip);
        width == ip_width && value & mask(self.prefix, width) == network
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadConfig {
    /// Ranges allowed besides public addresses; empty by default.
    pub extra_ranges: Vec<AddressRange>,
    /// Hosts a redirect may lead to, besides the API origin.
    pub asset_hosts: Vec<String>,
    pub max_redirects: usize,
    pub connect_timeout: Duration,
    /// Longest wait for the response head or for the next body chunk.
    pub idle_timeout: Duration,
    /// Deadline for the whole download, every hop included.
    pub total_timeout: Duration,
    pub user_agent: String,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            extra_ranges: Vec::new(),
            asset_hosts: ASSET_HOSTS.iter().map(|host| (*host).to_owned()).collect(),
            max_redirects: 3,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(30 * 60),
            user_agent: concat!("pakomichi/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }
}

/// Why the asset was not downloaded. Messages carry no URL query (signed
/// URLs are credentials) and no token.
#[derive(Debug)]
pub enum DownloadError {
    /// 404 or 410: the asset is gone (N-014).
    Gone {
        status: u16,
    },
    /// 401 or 403 without a rate-limit signal.
    Refused {
        status: u16,
    },
    RateLimited {
        status: u16,
    },
    Upstream {
        status: u16,
    },
    UnexpectedStatus {
        status: u16,
    },
    /// A redirect without a usable `Location`, or with credentials, a
    /// fragment, an IP literal, another port, or an unsafe target.
    BadLocation,
    /// A redirect to anything but `https` (R-004 conclusion 11).
    InsecureRedirect,
    /// A redirect to a host that is not an asset host.
    HostRefused(String),
    TooManyRedirects,
    /// The server announced another size than the pinned one.
    SizeMismatch {
        expected: u64,
        announced: u64,
    },
    /// The body went past the pinned size.
    TooLong {
        expected: u64,
    },
    /// The body ended before the pinned size.
    Truncated {
        expected: u64,
        received: u64,
    },
    Transport(TransportError),
    Timeout,
    /// The sink refused a chunk (for example, the disk is full).
    Sink(std::io::Error),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone { status } => write!(formatter, "asset is gone (HTTP {status})"),
            Self::Refused { status } => write!(formatter, "asset refused (HTTP {status})"),
            Self::RateLimited { status } => write!(formatter, "rate limited (HTTP {status})"),
            Self::Upstream { status } => write!(formatter, "upstream error (HTTP {status})"),
            Self::UnexpectedStatus { status } => write!(formatter, "unexpected HTTP {status}"),
            Self::BadLocation => formatter.write_str("unusable redirect location"),
            Self::InsecureRedirect => formatter.write_str("redirect to a non-https URL"),
            Self::HostRefused(host) => write!(
                formatter,
                "redirect to a host that is not an asset host: {host}"
            ),
            Self::TooManyRedirects => formatter.write_str("too many redirects"),
            Self::SizeMismatch {
                expected,
                announced,
            } => write!(formatter, "announced {announced} bytes, pinned {expected}"),
            Self::TooLong { expected } => {
                write!(formatter, "body longer than the pinned {expected} bytes")
            }
            Self::Truncated { expected, received } => {
                write!(formatter, "body ended after {received} of {expected} bytes")
            }
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Timeout => formatter.write_str("download timed out"),
            Self::Sink(error) => write!(formatter, "storing the download failed: {error}"),
        }
    }
}

impl std::error::Error for DownloadError {}

impl From<TransportError> for DownloadError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AddressPolicy {
    PublicOnly,
    /// TEST ONLY: these exact loopback test servers are also allowed.
    #[cfg(test)]
    AlsoAllow(Vec<SocketAddr>),
}

/// One hop: a host and an origin-form target.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Hop {
    host: String,
    target: String,
}

pub struct AssetDownloader<C, R = SystemResolver> {
    connector: C,
    resolver: R,
    config: DownloadConfig,
    token: Option<Token>,
    policy: AddressPolicy,
    port: u16,
}

impl<C: SecureConnector> AssetDownloader<C, SystemResolver> {
    pub fn new(connector: C, config: DownloadConfig, token: Option<Token>) -> Self {
        Self::with_resolver(connector, SystemResolver, config, token)
    }
}

impl<C: SecureConnector, R: Resolve> AssetDownloader<C, R> {
    pub fn with_resolver(
        connector: C,
        resolver: R,
        config: DownloadConfig,
        token: Option<Token>,
    ) -> Self {
        Self {
            connector,
            resolver,
            config,
            token,
            policy: AddressPolicy::PublicOnly,
            port: HTTPS_PORT,
        }
    }

    /// TEST ONLY: also connect to these loopback servers, on `port`.
    #[cfg(test)]
    pub(crate) fn allowing_test_servers(mut self, servers: Vec<SocketAddr>, port: u16) -> Self {
        self.policy = AddressPolicy::AlsoAllow(servers);
        self.port = port;
        self
    }

    /// Downloads the asset, handing every chunk to `sink`; returns the
    /// number of bytes, which equals `expected_size`.
    pub async fn download(
        &self,
        locator: AssetLocator,
        expected_size: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> Result<u64, DownloadError> {
        let deadline = Instant::now() + self.config.total_timeout;
        timeout_at(deadline, self.follow(locator, expected_size, sink))
            .await
            .map_err(|_| DownloadError::Timeout)?
    }

    async fn follow(
        &self,
        locator: AssetLocator,
        expected_size: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> Result<u64, DownloadError> {
        let mut hop = Hop {
            host: API_HOST.to_owned(),
            target: format!(
                "/repositories/{}/releases/assets/{}",
                locator.repository, locator.asset
            ),
        };
        for _ in 0..=self.config.max_redirects {
            let (response, _driver) = self.open(&hop).await?;
            let status = response.status().as_u16();
            match status {
                200 => return self.receive(response, expected_size, sink).await,
                301 | 302 | 303 | 307 | 308 => {
                    let location = response
                        .headers()
                        .get(LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .ok_or(DownloadError::BadLocation)?;
                    hop = self.next_hop(&hop, location)?;
                }
                404 | 410 => return Err(DownloadError::Gone { status }),
                429 => return Err(DownloadError::RateLimited { status }),
                401 | 403 => {
                    let exhausted = response
                        .headers()
                        .get("x-ratelimit-remaining")
                        .is_some_and(|value| value.as_bytes() == b"0");
                    return Err(if exhausted {
                        DownloadError::RateLimited { status }
                    } else {
                        DownloadError::Refused { status }
                    });
                }
                500..=599 => return Err(DownloadError::Upstream { status }),
                _ => return Err(DownloadError::UnexpectedStatus { status }),
            }
        }
        Err(DownloadError::TooManyRedirects)
    }

    /// The next hop from a `Location`: absolute `https` URLs to an allowed
    /// host, or an origin-form path on the current host.
    fn next_hop(&self, current: &Hop, location: &str) -> Result<Hop, DownloadError> {
        let (host, target) = if location.starts_with('/') && !location.starts_with("//") {
            (current.host.clone(), location.to_owned())
        } else {
            let Some((scheme, rest)) = location.split_once("://") else {
                return Err(DownloadError::BadLocation);
            };
            if !scheme.eq_ignore_ascii_case("https") {
                return Err(DownloadError::InsecureRedirect);
            }
            let (authority, target) = match rest.find('/') {
                Some(index) => (&rest[..index], rest[index..].to_owned()),
                None => (rest, "/".to_owned()),
            };
            // Credentials (`user:pass@`) fail the port or host-name check.
            let host = match authority.rsplit_once(':') {
                Some((host, "443")) => host,
                Some(_) => return Err(DownloadError::BadLocation),
                None => authority,
            };
            let host = host.to_ascii_lowercase();
            if !is_host_name(&host) {
                return Err(DownloadError::BadLocation);
            }
            if host != API_HOST && !self.config.asset_hosts.contains(&host) {
                return Err(DownloadError::HostRefused(host));
            }
            (host, target)
        };
        if !is_safe_target(&target) {
            return Err(DownloadError::BadLocation);
        }
        Ok(Hop { host, target })
    }

    fn allowed(&self, address: &SocketAddr) -> bool {
        if self
            .config
            .extra_ranges
            .iter()
            .any(|range| range.contains(address.ip()))
        {
            return true;
        }
        match &self.policy {
            AddressPolicy::PublicOnly => is_public_address(address.ip()),
            #[cfg(test)]
            AddressPolicy::AlsoAllow(servers) => {
                servers.contains(address) || is_public_address(address.ip())
            }
        }
    }

    /// Resolves once, vets every address, connects to a vetted one, and
    /// sends the GET. The returned guard keeps the connection running.
    async fn open(
        &self,
        hop: &Hop,
    ) -> Result<(hyper::Response<Incoming>, AbortOnDrop), DownloadError> {
        let addresses = self.resolver.resolve(&hop.host, self.port).await?;
        if addresses.is_empty() {
            return Err(TransportError::Resolve.into());
        }
        if !addresses.iter().all(|address| self.allowed(address)) {
            return Err(TransportError::AddressRefused.into());
        }
        let mut failure = TransportError::Connect;
        let mut stream = None;
        for address in addresses.iter().take(MAX_ADDRESSES) {
            match timeout(
                self.config.connect_timeout,
                self.connector.connect(&hop.host, *address),
            )
            .await
            {
                Ok(Ok(connected)) => {
                    stream = Some(connected);
                    break;
                }
                Ok(Err(error)) => failure = error,
                Err(_) => failure = TransportError::Timeout,
            }
        }
        let stream = stream.ok_or(failure)?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(|_| TransportError::Protocol("handshake"))?;
        let driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let api = hop.host == API_HOST;
        let mut request = Request::get(hop.target.as_str())
            .header(HOST, hop.host.as_str())
            .header(USER_AGENT, self.config.user_agent.as_str())
            .header(ACCEPT, "application/octet-stream")
            .header(ACCEPT_ENCODING, "identity")
            .header(CONNECTION, "close");
        if api {
            request = request.header("x-github-api-version", API_VERSION);
        }
        let mut request = request
            .body(Empty::new())
            .map_err(|_| DownloadError::BadLocation)?;
        // The token goes to the API origin only, never to the asset host.
        if api && let Some(token) = &self.token {
            let mut value = HeaderValue::try_from(format!("Bearer {}", token.expose_secret()))
                .map_err(|_| TransportError::InvalidRequest)?;
            value.set_sensitive(true);
            request.headers_mut().insert(AUTHORIZATION, value);
        }
        let response = timeout(self.config.idle_timeout, sender.send_request(request))
            .await
            .map_err(|_| DownloadError::Timeout)?
            .map_err(|_| TransportError::Protocol("no response"))?;
        Ok((response, driver))
    }

    async fn receive(
        &self,
        response: hyper::Response<Incoming>,
        expected: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> Result<u64, DownloadError> {
        let headers = response.headers();
        if let Some(encoding) = headers.get(CONTENT_ENCODING)
            && encoding.as_bytes() != b"identity"
        {
            return Err(TransportError::Protocol("unrequested content encoding").into());
        }
        if let Some(length) = headers.get(CONTENT_LENGTH) {
            let announced: u64 = length
                .to_str()
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or(TransportError::Protocol("invalid content length"))?;
            if announced != expected {
                return Err(DownloadError::SizeMismatch {
                    expected,
                    announced,
                });
            }
        }
        let mut body = response.into_body();
        let mut received: u64 = 0;
        loop {
            let frame = timeout(self.config.idle_timeout, body.frame())
                .await
                .map_err(|_| DownloadError::Timeout)?;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|_| TransportError::Protocol("body"))?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            received = received.saturating_add(data.len() as u64);
            if received > expected {
                return Err(DownloadError::TooLong { expected });
            }
            sink(&data).map_err(DownloadError::Sink)?;
        }
        if received != expected {
            return Err(DownloadError::Truncated { expected, received });
        }
        Ok(received)
    }
}

/// A DNS host name: lowercase labels of letters, digits and inner `-`;
/// never an IP literal.
fn is_host_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.bytes().any(|byte| byte.is_ascii_lowercase()))
}

/// An origin-form target: a path and query of visible ASCII, without a
/// fragment, a backslash, or characters a URI may not carry.
fn is_safe_target(target: &str) -> bool {
    target.len() <= MAX_TARGET_BYTES
        && target.starts_with('/')
        && !target.starts_with("//")
        && target
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"#\\\"<>`{}|^".contains(&byte))
}

#[cfg(test)]
#[path = "asset_tests.rs"]
mod tests;
