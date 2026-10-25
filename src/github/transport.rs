// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boundary between the GitHub client logic and the network.
//!
//! The client builds an [`ApiRequest`] (a path on the fixed API origin, an
//! optional conditional header, an optional token) and receives an
//! [`ApiResponse`] with only the headers it uses. A fake transport makes the
//! client logic testable without a network or root.

use std::fmt;
use std::future::Future;

use super::token::Token;

/// The only origin the client talks to. GitHub Enterprise Server is out of
/// scope for 0.1.
pub const API_ORIGIN: &str = "https://api.github.com";

/// Host of [`API_ORIGIN`].
pub const API_HOST: &str = "api.github.com";

/// REST API version requested with `X-GitHub-Api-Version`.
pub const API_VERSION: &str = "2022-11-28";

/// Longest request path the client builds.
const MAX_PATH_BYTES: usize = 2048;

/// One GET request to [`API_ORIGIN`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiRequest {
    path: String,
    if_none_match: Option<String>,
    token: Option<Token>,
}

impl ApiRequest {
    /// `path` is a path and query on the API origin built by the client from
    /// validated parts; anything else is refused.
    pub(crate) fn new(
        path: String,
        if_none_match: Option<String>,
        token: Option<Token>,
    ) -> Result<Self, TransportError> {
        if !is_safe_path(&path) {
            return Err(TransportError::InvalidRequest);
        }
        Ok(Self {
            path,
            if_none_match,
            token,
        })
    }

    /// Path and query, for example `/repositories/1/releases?per_page=100`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The stored ETag sent as `If-None-Match`, when the client has one for
    /// this URL and credential.
    pub fn if_none_match(&self) -> Option<&str> {
        self.if_none_match.as_deref()
    }

    pub fn token(&self) -> Option<&Token> {
        self.token.as_ref()
    }
}

fn is_safe_path(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            // `:` only for `sha256:<hex>` subjects; the origin is fixed, and
            // a path that starts with one `/` cannot name another host.
            .all(|byte| byte.is_ascii_alphanumeric() || b"/-._~%?&=:".contains(&byte))
}

/// The response headers the client uses; every other header is dropped by
/// the transport.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResponseHeaders {
    pub etag: Option<String>,
    pub link: Option<String>,
    pub location: Option<String>,
    pub retry_after: Option<String>,
    pub ratelimit_limit: Option<String>,
    pub ratelimit_remaining: Option<String>,
    pub ratelimit_reset: Option<String>,
    pub ratelimit_resource: Option<String>,
}

impl ResponseHeaders {
    /// Names the transport copies, lowercase.
    pub const NAMES: [&'static str; 8] = [
        "etag",
        "link",
        "location",
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
    ];

    /// Stores a header by its lowercase name; unknown names are ignored.
    pub fn set(&mut self, name: &str, value: String) {
        let slot = match name {
            "etag" => &mut self.etag,
            "link" => &mut self.link,
            "location" => &mut self.location,
            "retry-after" => &mut self.retry_after,
            "x-ratelimit-limit" => &mut self.ratelimit_limit,
            "x-ratelimit-remaining" => &mut self.ratelimit_remaining,
            "x-ratelimit-reset" => &mut self.ratelimit_reset,
            "x-ratelimit-resource" => &mut self.ratelimit_resource,
            _ => return,
        };
        *slot = Some(value);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiResponse {
    pub status: u16,
    pub headers: ResponseHeaders,
    pub body: Vec<u8>,
}

/// A network-level failure. Messages never contain credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The client tried to build a request outside its fixed path shape.
    InvalidRequest,
    /// Name resolution failed or returned nothing.
    Resolve,
    /// A resolved address is not public (R-004 conclusion 11).
    AddressRefused,
    Connect,
    /// The TLS handshake failed for a reason other than the certificate,
    /// or the server negotiated something other than HTTP/1.1.
    Tls,
    /// The server certificate chain or host name did not verify against
    /// the trusted roots (for example a TLS-intercepting proxy).
    Certificate,
    Timeout,
    /// The peer did not speak the expected HTTP.
    Protocol(&'static str),
    /// The body exceeded the limit; reading stopped at the limit.
    BodyTooLarge {
        limit: usize,
    },
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("request path refused"),
            Self::Resolve => formatter.write_str("name resolution failed"),
            Self::AddressRefused => formatter.write_str("resolved address is not public"),
            Self::Connect => formatter.write_str("connection failed"),
            Self::Tls => formatter.write_str("TLS handshake failed"),
            Self::Certificate => formatter.write_str("server certificate rejected"),
            Self::Timeout => formatter.write_str("request timed out"),
            Self::Protocol(problem) => write!(formatter, "HTTP protocol error: {problem}"),
            Self::BodyTooLarge { limit } => {
                write!(formatter, "response body exceeds {limit} bytes")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// Sends one request and returns the complete response.
///
/// Implementations must not follow redirects, must not retry, and must stop
/// reading a body at `max_body_bytes` with [`TransportError::BodyTooLarge`].
pub trait Transport: Send + Sync {
    fn send(
        &self,
        request: ApiRequest,
        max_body_bytes: usize,
    ) -> impl Future<Output = Result<ApiResponse, TransportError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_client_shaped_paths_are_accepted() {
        assert!(
            ApiRequest::new(
                "/repositories/1/releases?per_page=100&page=2".to_owned(),
                None,
                None
            )
            .is_ok()
        );
        assert!(ApiRequest::new("/repos/a/b/releases/tags/v1%2F2".to_owned(), None, None).is_ok());
        for path in [
            "repositories/1",
            "//evil.example/x",
            "/a b",
            "/a\r\nHost: x",
            "/@evil",
            "/#x",
        ] {
            assert_eq!(
                ApiRequest::new(path.to_owned(), None, None),
                Err(TransportError::InvalidRequest),
                "{path:?}"
            );
        }
    }
}
