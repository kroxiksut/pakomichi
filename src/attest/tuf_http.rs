// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTPS GET for the two TUF repositories (ADR-030 point 8).
//!
//! The same rules as the GitHub API client (`github::http`): the host is
//! resolved once per request, the whole answer is refused when any address
//! is not public, a vetted address is connected through the TLS
//! [`SecureConnector`] (certificate chain and host name verified), one GET is
//! sent, and the body is read up to the caller's limit. No redirects, proxy,
//! decompression, retries, or connection pool; one deadline covers the
//! exchange. 404 and 403 mean "not found" (the end of a root chain, as
//! `python-tuf` treats object stores).

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt as _, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper::header::{
    ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, USER_AGENT,
};
use hyper_util::rt::TokioIo;
use sigstore_tuf::transport::{FetchFuture, Repository};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::github::{
    HttpConfig, Resolve, SecureConnector, SystemResolver, TransportError, is_public_address,
};

/// The TUF repositories Pakomichi talks to; nothing else is reachable.
pub const TUF_HOSTS: [&str; 2] = ["tuf-repo.github.com", "tuf-repo-cdn.sigstore.dev"];

const HTTPS_PORT: u16 = 443;
const MAX_ADDRESSES: usize = 4;

/// HTTPS GET to the TUF hosts.
pub struct TufHttp<C, R = SystemResolver> {
    connector: C,
    resolver: R,
    config: HttpConfig,
    allow_loopback: bool,
}

impl<C: SecureConnector> TufHttp<C, SystemResolver> {
    pub fn new(connector: C, config: HttpConfig) -> Self {
        Self::with_resolver(connector, SystemResolver, config)
    }
}

impl<C: SecureConnector, R: Resolve> TufHttp<C, R> {
    pub fn with_resolver(connector: C, resolver: R, config: HttpConfig) -> Self {
        Self {
            connector,
            resolver,
            config,
            allow_loopback: false,
        }
    }

    /// TEST ONLY: also accepts loopback addresses, for local test servers.
    #[cfg(test)]
    pub(crate) fn allowing_loopback_for_tests(mut self) -> Self {
        self.allow_loopback = true;
        self
    }

    /// GETs `https://<host>/<path>`. `Ok(None)` for 404/403.
    pub async fn get(
        &self,
        host: &'static str,
        path: &str,
        max_length: u64,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        if !TUF_HOSTS.contains(&host) || !valid_path(path) {
            return Err(TransportError::InvalidRequest);
        }
        let limit = usize::try_from(max_length).unwrap_or(usize::MAX);
        timeout(
            self.config.request_timeout,
            self.get_within_deadline(host, path, limit),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    async fn get_within_deadline(
        &self,
        host: &'static str,
        path: &str,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let addresses = self.resolver.resolve(host, HTTPS_PORT).await?;
        let addresses = self.vet(&addresses)?;
        let mut failure = TransportError::Connect;
        for address in addresses {
            match timeout(
                self.config.connect_timeout,
                self.connector.connect(host, address),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    return exchange(stream, host, path, &self.config.user_agent, limit).await;
                }
                Ok(Err(error)) => failure = error,
                Err(_) => failure = TransportError::Timeout,
            }
        }
        Err(failure)
    }

    fn vet(&self, addresses: &[SocketAddr]) -> Result<Vec<SocketAddr>, TransportError> {
        if addresses.is_empty() {
            return Err(TransportError::Resolve);
        }
        let allowed = |address: &SocketAddr| {
            is_public_address(address.ip()) || (self.allow_loopback && address.ip().is_loopback())
        };
        if !addresses.iter().all(allowed) {
            return Err(TransportError::AddressRefused);
        }
        Ok(addresses.iter().copied().take(MAX_ADDRESSES).collect())
    }
}

/// A repository-relative path: metadata names and `targets/<hash>.<name>`.
fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

async fn exchange<S>(
    stream: S,
    host: &'static str,
    path: &str,
    user_agent: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(|_| TransportError::Protocol("handshake"))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let result = async {
        let request = Request::get(format!("/{path}"))
            .header(HOST, host)
            .header(USER_AGENT, user_agent)
            .header(ACCEPT_ENCODING, "identity")
            .header(CONNECTION, "close")
            .body(Empty::new())
            .map_err(|_| TransportError::InvalidRequest)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| TransportError::Protocol("no response"))?;
        match response.status().as_u16() {
            200 => {}
            403 | 404 => return Ok(None),
            _ => return Err(TransportError::Protocol("unexpected status")),
        }
        if let Some(encoding) = response.headers().get(CONTENT_ENCODING)
            && encoding.as_bytes() != b"identity"
        {
            return Err(TransportError::Protocol("unrequested content encoding"));
        }
        if let Some(length) = response.headers().get(CONTENT_LENGTH) {
            let length: u64 = length
                .to_str()
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or(TransportError::Protocol("invalid content length"))?;
            if length > limit as u64 {
                return Err(TransportError::BodyTooLarge { limit });
            }
        }
        let mut body = Vec::new();
        let mut stream = response.into_body();
        while let Some(frame) = stream.frame().await {
            let frame = frame.map_err(|_| TransportError::Protocol("body"))?;
            if let Ok(data) = frame.into_data() {
                if body.len() + data.len() > limit {
                    return Err(TransportError::BodyTooLarge { limit });
                }
                body.extend_from_slice(&data);
            }
        }
        Ok(Some(body))
    }
    .await;
    driver.abort();
    result
}

/// One TUF repository over [`TufHttp`]: metadata at `/<name>`, targets at
/// `/targets/<path>`.
pub struct TufRepository<C, R = SystemResolver> {
    http: Arc<TufHttp<C, R>>,
    host: &'static str,
}

impl<C, R> TufRepository<C, R> {
    pub fn new(http: Arc<TufHttp<C, R>>, host: &'static str) -> Self {
        Self { http, host }
    }
}

fn transport_error(error: TransportError) -> sigstore_tuf::Error {
    sigstore_tuf::Error::transport(format!("TUF request failed: {error}"))
}

impl<C, R> Repository for TufRepository<C, R>
where
    C: SecureConnector + 'static,
    R: Resolve + 'static,
{
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        Box::pin(async move {
            self.http
                .get(self.host, name, max_length)
                .await
                .map_err(transport_error)
        })
    }

    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
        Box::pin(async move {
            self.http
                .get(self.host, &format!("targets/{path}"), max_length)
                .await
                .map_err(transport_error)
        })
    }
}
