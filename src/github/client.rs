// SPDX-License-Identifier: MIT OR Apache-2.0

//! The GitHub REST client: identity pinning, conditional requests, rate
//! limits, and pagination over an abstract [`Transport`].
//!
//! Endpoints are limited to one repository: by name (only to pin or check
//! an address), by repository ID, and its releases and tag references by
//! repository ID. There
//! is no search, fork, or owner listing endpoint and no HTML parsing
//! (specification item 2).

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::conditional::{CacheKey, CachedResponse, EtagCache, weak_match};
use super::identity::{
    IdentityOutcome, OwnerLogin, PinnedRepository, RepositoryId, RepositoryIdentity, RepositoryName,
};
use super::pagination::{PaginationError, next_page, page_path};
use super::rate_limit::{Clock, QuotaSnapshot, RateLimitGate, RateLimited, SystemClock};
use super::release_pin::GitObjectId;
use super::token::{CredentialId, Token};
use super::transport::{API_ORIGIN, ApiRequest, Transport, TransportError};
use super::wire::{
    self, MAX_RELEASES_PER_PAGE, MAX_RESPONSE_BYTES, Release, TagObjectKind, TagRef, WireError,
    parse_release, parse_release_page, parse_repository, parse_tag_object, parse_tag_ref,
};
use crate::error::ReasonCode;

/// Longest stored ETag.
const MAX_ETAG_BYTES: usize = 256;

/// Longest tag accepted by [`GitHubClient::release_by_tag`].
const MAX_TAG_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    /// Responses above this are refused before parsing.
    pub max_body_bytes: usize,
    /// Releases per page, at most 100.
    pub per_page: u32,
    /// Hard cap on pages per listing; the listing is marked truncated when a
    /// further page exists.
    pub max_pages: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_RESPONSE_BYTES,
            per_page: 100,
            max_pages: 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    /// A 200 response, parsed and validated now.
    Modified,
    /// A 304 for our stored ETag; the value is the stored verified body.
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fetched<T> {
    pub value: T,
    pub freshness: Freshness,
}

/// The result of a lookup by owner and name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRepository {
    pub identity: RepositoryIdentity,
    /// GitHub redirected the old name to `/repositories/{id}`, which it does
    /// after a rename or transfer.
    pub redirected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseListing {
    /// Newest first, as GitHub returns them.
    pub releases: Vec<Release>,
    /// More pages exist beyond [`ClientConfig::max_pages`].
    pub truncated: bool,
    /// Every page was confirmed unchanged by a 304.
    pub unchanged: bool,
}

/// Why a request failed. All variants map to `E_FORGE_UNAVAILABLE`;
/// identity changes are not errors but [`IdentityOutcome`]s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitHubError {
    Transport(TransportError),
    /// No request was sent, or GitHub refused; nothing is retried.
    RateLimited(RateLimited),
    /// 404: missing, deleted, or not visible with these credentials.
    NotFound,
    /// 401: the token was refused.
    Unauthorized,
    /// 403 that is not a rate limit.
    Forbidden,
    Server {
        status: u16,
    },
    UnexpectedStatus {
        status: u16,
    },
    BodyTooLarge {
        length: usize,
        limit: usize,
    },
    Wire(WireError),
    Pagination(PaginationError),
    /// A 304 that does not answer our own `If-None-Match` for this URL and
    /// credential; it confirms nothing.
    UnexpectedNotModified,
    /// A redirect outside the one allowed shape.
    RedirectRefused,
    InvalidArgument(&'static str),
}

impl GitHubError {
    /// The stable reason code. The catalogue has no separate code for a
    /// protocol violation by the forge, so malformed responses also use
    /// `E_FORGE_UNAVAILABLE`.
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Transport(_)
            | Self::RateLimited(_)
            | Self::NotFound
            | Self::Unauthorized
            | Self::Forbidden
            | Self::Server { .. }
            | Self::UnexpectedStatus { .. }
            | Self::BodyTooLarge { .. }
            | Self::Wire(_)
            | Self::Pagination(_)
            | Self::UnexpectedNotModified
            | Self::RedirectRefused
            | Self::InvalidArgument(_) => ReasonCode::EForgeUnavailable,
        }
    }
}

impl fmt::Display for GitHubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport: {error}"),
            Self::RateLimited(limited) => write!(formatter, "rate limited ({:?})", limited.kind),
            Self::NotFound => formatter.write_str("not found"),
            Self::Unauthorized => formatter.write_str("credentials refused"),
            Self::Forbidden => formatter.write_str("forbidden"),
            Self::Server { status } => write!(formatter, "server error {status}"),
            Self::UnexpectedStatus { status } => write!(formatter, "unexpected status {status}"),
            Self::BodyTooLarge { length, limit } => {
                write!(
                    formatter,
                    "response is {length} bytes; the limit is {limit}"
                )
            }
            Self::Wire(error) => write!(formatter, "invalid response: {error}"),
            Self::Pagination(error) => write!(formatter, "pagination: {error}"),
            Self::UnexpectedNotModified => {
                formatter.write_str("304 without a matching conditional request")
            }
            Self::RedirectRefused => formatter.write_str("redirect refused"),
            Self::InvalidArgument(problem) => write!(formatter, "invalid argument: {problem}"),
        }
    }
}

impl std::error::Error for GitHubError {}

impl From<WireError> for GitHubError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<PaginationError> for GitHubError {
    fn from(error: PaginationError) -> Self {
        Self::Pagination(error)
    }
}

/// A 200 response waiting for validation before its ETag is stored.
struct FreshReply {
    key: CacheKey,
    etag: Option<String>,
    link: Option<String>,
    body: Vec<u8>,
}

enum Reply {
    Fresh(FreshReply),
    Unchanged(CachedResponse),
    Redirect(String),
}

pub struct GitHubClient<T> {
    transport: T,
    token: Option<Token>,
    credential: CredentialId,
    etags: Arc<EtagCache>,
    gate: Mutex<RateLimitGate>,
    clock: Arc<dyn Clock>,
    config: ClientConfig,
}

impl<T> fmt::Debug for GitHubClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubClient")
            .field("credential", &self.credential)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T: Transport> GitHubClient<T> {
    pub fn new(transport: T, token: Option<Token>) -> Self {
        Self {
            transport,
            credential: CredentialId::of(token.as_ref()),
            token,
            etags: Arc::new(EtagCache::default()),
            gate: Mutex::new(RateLimitGate::default()),
            clock: Arc::new(SystemClock),
            config: ClientConfig::default(),
        }
    }

    /// `per_page` is clamped to 1..=100 and `max_pages` to at least 1.
    pub fn with_config(mut self, config: ClientConfig) -> Self {
        self.config = ClientConfig {
            max_body_bytes: config.max_body_bytes.min(MAX_RESPONSE_BYTES),
            per_page: config.per_page.clamp(1, MAX_RELEASES_PER_PAGE as u32),
            max_pages: config.max_pages.max(1),
        };
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Shares one store between clients; entries stay bound to each
    /// client's credential.
    pub fn with_etag_cache(mut self, cache: Arc<EtagCache>) -> Self {
        self.etags = cache;
        self
    }

    pub fn quota(&self) -> QuotaSnapshot {
        self.gate().quota().clone()
    }

    /// Resolves `owner/name` for `source add`, following only GitHub's
    /// redirect to `/repositories/{id}`. The caller pins the result.
    pub async fn resolve_by_name(
        &self,
        owner: &OwnerLogin,
        name: &RepositoryName,
    ) -> Result<ResolvedRepository, GitHubError> {
        match self.get(format!("/repos/{owner}/{name}"), true).await? {
            Reply::Fresh(fresh) => {
                let identity = parse_repository(&fresh.body)?;
                self.remember(fresh);
                Ok(ResolvedRepository {
                    identity,
                    redirected: false,
                })
            }
            Reply::Unchanged(cached) => Ok(ResolvedRepository {
                identity: parse_repository(&cached.body)?,
                redirected: false,
            }),
            Reply::Redirect(location) => {
                let target = redirect_target(&location)?;
                let fetched = self.repository_by_id(target).await?;
                if fetched.value.repository_id() != target {
                    return Err(GitHubError::Wire(WireError::Invalid {
                        field: "id",
                        problem: "does not match the redirect target",
                    }));
                }
                Ok(ResolvedRepository {
                    identity: fetched.value,
                    redirected: true,
                })
            }
        }
    }

    /// `GET /repositories/{id}`: immune to a new repository under an old name.
    pub async fn repository_by_id(
        &self,
        id: RepositoryId,
    ) -> Result<Fetched<RepositoryIdentity>, GitHubError> {
        self.fetch(format!("/repositories/{id}"), parse_repository)
            .await
    }

    /// Pins a new source: the first resolution fixes the repository ID and
    /// owner ID.
    pub async fn pin_source(
        &self,
        owner: &OwnerLogin,
        name: &RepositoryName,
    ) -> Result<PinnedRepository, GitHubError> {
        Ok(PinnedRepository::pin(
            self.resolve_by_name(owner, name).await?.identity,
        ))
    }

    /// The per-synchronization check by repository ID.
    pub async fn reconcile(
        &self,
        pinned: &PinnedRepository,
    ) -> Result<IdentityOutcome, GitHubError> {
        let fetched = self.repository_by_id(pinned.repository_id()).await?;
        Ok(pinned.compare(&fetched.value))
    }

    /// Checks what an address (for example the one in the user's
    /// configuration) points to now. A different repository under the old
    /// name yields [`IdentityOutcome::Replaced`].
    pub async fn check_address(
        &self,
        pinned: &PinnedRepository,
        owner: &OwnerLogin,
        name: &RepositoryName,
    ) -> Result<IdentityOutcome, GitHubError> {
        let resolved = self.resolve_by_name(owner, name).await?;
        Ok(pinned.compare(&resolved.identity))
    }

    /// Lists releases of the pinned repository by its ID, newest first, up
    /// to [`ClientConfig::max_pages`] pages.
    pub async fn list_releases(
        &self,
        pinned: &PinnedRepository,
    ) -> Result<ReleaseListing, GitHubError> {
        let base = format!("/repositories/{}/releases", pinned.repository_id());
        let per_page = self.config.per_page;
        let mut releases = Vec::new();
        let mut unchanged = true;
        let mut page = 1;
        loop {
            let reply = self.get(page_path(&base, per_page, page), false).await?;
            let (body, link) = match &reply {
                Reply::Fresh(fresh) => (&fresh.body, fresh.link.as_deref()),
                Reply::Unchanged(cached) => (&cached.body, cached.link.as_deref()),
                Reply::Redirect(_) => return Err(GitHubError::RedirectRefused),
            };
            releases.extend(parse_release_page(body)?);
            // The link is validated before the page's ETag is stored.
            let next = next_page(link, &base, per_page, page)?;
            if let Reply::Fresh(fresh) = reply {
                unchanged = false;
                self.remember(fresh);
            }
            match next {
                None => {
                    return Ok(ReleaseListing {
                        releases,
                        truncated: false,
                        unchanged,
                    });
                }
                Some(_) if page >= self.config.max_pages => {
                    return Ok(ReleaseListing {
                        releases,
                        truncated: true,
                        unchanged,
                    });
                }
                Some(next) => page = next,
            }
        }
    }

    /// `None` when the repository has no published release.
    pub async fn latest_release(
        &self,
        pinned: &PinnedRepository,
    ) -> Result<Option<Fetched<Release>>, GitHubError> {
        let path = format!("/repositories/{}/releases/latest", pinned.repository_id());
        not_found_as_none(self.fetch(path, parse_release).await)
    }

    /// `None` when no release has this tag.
    pub async fn release_by_tag(
        &self,
        pinned: &PinnedRepository,
        tag: &str,
    ) -> Result<Option<Fetched<Release>>, GitHubError> {
        if tag.is_empty() || tag.len() > MAX_TAG_BYTES || tag.chars().any(char::is_control) {
            return Err(GitHubError::InvalidArgument("tag"));
        }
        let path = format!(
            "/repositories/{}/releases/tags/{}",
            pinned.repository_id(),
            percent_encode(tag)
        );
        not_found_as_none(self.fetch(path, parse_release).await)
    }

    /// `GET /repositories/{id}/git/ref/tags/{tag}` exactly as returned, never
    /// peeled: the Strict check compares the release attestation's `sha1`
    /// subject with [`TagRef::object`]. `None` when no such tag exists. The
    /// returned `ref` must equal `refs/tags/{tag}`, because GitHub matches
    /// some ref paths by prefix.
    pub async fn tag_ref(
        &self,
        repository: RepositoryId,
        tag: &str,
    ) -> Result<Option<Fetched<TagRef>>, GitHubError> {
        let path = format!(
            "/repositories/{repository}/git/ref/tags/{}",
            encode_ref_path(tag)?
        );
        let Some(fetched) = not_found_as_none(self.fetch(path, parse_tag_ref).await)? else {
            return Ok(None);
        };
        if fetched
            .value
            .ref_name
            .strip_prefix("refs/tags/")
            .is_none_or(|name| name != tag)
        {
            return Err(GitHubError::Wire(WireError::Invalid {
                field: "ref",
                problem: "does not name the requested tag",
            }));
        }
        Ok(Some(fetched))
    }

    /// The commit a tag names, for the Attested path: a lightweight tag's
    /// object, or the target of one annotated tag object whose `tag` field is
    /// the requested tag. A tag of a tag is refused. `None` when the tag
    /// reference does not exist; a missing tag object is
    /// [`GitHubError::NotFound`], since the reference named it.
    pub async fn peeled_commit(
        &self,
        repository: RepositoryId,
        tag: &str,
    ) -> Result<Option<GitObjectId>, GitHubError> {
        let Some(reference) = self.tag_ref(repository, tag).await? else {
            return Ok(None);
        };
        let reference = reference.value;
        if reference.kind == TagObjectKind::Commit {
            return Ok(Some(reference.object));
        }
        let path = format!("/repositories/{repository}/git/tags/{}", reference.object);
        let annotated = self.fetch(path, parse_tag_object).await?.value;
        let problem = if annotated.sha != reference.object {
            Some(("sha", "does not match the tag reference"))
        } else if annotated.tag != tag {
            Some(("tag", "does not name the requested tag"))
        } else if annotated.target_kind != TagObjectKind::Commit {
            Some(("object.type", "a tag of a tag is not peeled further"))
        } else {
            None
        };
        match problem {
            Some((field, problem)) => Err(GitHubError::Wire(WireError::Invalid { field, problem })),
            None => Ok(Some(annotated.target)),
        }
    }

    async fn fetch<V>(
        &self,
        path: String,
        parse: fn(&[u8]) -> Result<V, WireError>,
    ) -> Result<Fetched<V>, GitHubError> {
        match self.get(path, false).await? {
            Reply::Fresh(fresh) => {
                let value = parse(&fresh.body)?;
                self.remember(fresh);
                Ok(Fetched {
                    value,
                    freshness: Freshness::Modified,
                })
            }
            Reply::Unchanged(cached) => Ok(Fetched {
                value: parse(&cached.body)?,
                freshness: Freshness::Unchanged,
            }),
            Reply::Redirect(_) => Err(GitHubError::RedirectRefused),
        }
    }

    /// One request: rate-limit gate, conditional header, size bound, status
    /// mapping. Nothing here retries.
    async fn get(&self, path: String, allow_redirect: bool) -> Result<Reply, GitHubError> {
        self.gate()
            .check(self.clock.now())
            .map_err(GitHubError::RateLimited)?;

        let key = CacheKey::new(path.clone(), self.credential);
        let cached = self.etags.get(&key);
        let sent_etag = cached.as_ref().map(|entry| entry.etag.clone());
        let request = ApiRequest::new(path, sent_etag.clone(), self.token.clone())
            .map_err(GitHubError::Transport)?;
        let response = self
            .transport
            .send(request, self.config.max_body_bytes)
            .await
            .map_err(GitHubError::Transport)?;

        // Bounded before any parsing, including the error-message probe.
        if response.body.len() > self.config.max_body_bytes {
            return Err(GitHubError::BodyTooLarge {
                length: response.body.len(),
                limit: self.config.max_body_bytes,
            });
        }
        let message = matches!(response.status, 403 | 429)
            .then(|| wire::error_message(&response.body))
            .flatten();
        let refusal = self.gate().observe(
            self.clock.now(),
            response.status,
            &response.headers,
            message.as_deref(),
        );
        if let Some(limited) = refusal {
            return Err(GitHubError::RateLimited(limited));
        }

        let headers = response.headers;
        match response.status {
            200 => Ok(Reply::Fresh(FreshReply {
                key,
                etag: headers.etag,
                link: headers.link,
                body: response.body,
            })),
            304 => match (cached, sent_etag) {
                (Some(cached), Some(sent))
                    if headers
                        .etag
                        .as_deref()
                        .is_none_or(|etag| weak_match(etag, &sent)) =>
                {
                    Ok(Reply::Unchanged(cached))
                }
                _ => Err(GitHubError::UnexpectedNotModified),
            },
            301 | 302 | 307 | 308 if allow_redirect => headers
                .location
                .map(Reply::Redirect)
                .ok_or(GitHubError::RedirectRefused),
            300..=399 => Err(GitHubError::RedirectRefused),
            401 => Err(GitHubError::Unauthorized),
            403 => Err(GitHubError::Forbidden),
            404 => Err(GitHubError::NotFound),
            500..=599 => Err(GitHubError::Server {
                status: response.status,
            }),
            status => Err(GitHubError::UnexpectedStatus { status }),
        }
    }

    /// Stores the ETag of a 200 whose body has just been validated.
    fn remember(&self, fresh: FreshReply) {
        let Some(etag) = fresh.etag else {
            self.etags.remove(&fresh.key);
            return;
        };
        if etag.is_empty()
            || etag.len() > MAX_ETAG_BYTES
            || !etag.bytes().all(|byte| byte.is_ascii_graphic())
        {
            self.etags.remove(&fresh.key);
            return;
        }
        self.etags.put(
            fresh.key,
            CachedResponse {
                etag,
                body: fresh.body,
                link: fresh.link,
            },
        );
    }

    fn gate(&self) -> MutexGuard<'_, RateLimitGate> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn not_found_as_none<V>(result: Result<V, GitHubError>) -> Result<Option<V>, GitHubError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(GitHubError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The only redirect followed: `https://api.github.com/repositories/{id}`,
/// which GitHub returns for a renamed or transferred repository.
fn redirect_target(location: &str) -> Result<RepositoryId, GitHubError> {
    let digits = location
        .strip_prefix(API_ORIGIN)
        .and_then(|rest| rest.strip_prefix("/repositories/"))
        .filter(|digits| {
            !digits.is_empty()
                && digits.len() <= 20
                && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
        .ok_or(GitHubError::RedirectRefused)?;
    digits
        .parse()
        .ok()
        .and_then(|id| RepositoryId::new(id).ok())
        .ok_or(GitHubError::RedirectRefused)
}

/// A tag as the path after `git/ref/tags/`: each `/`-separated segment is
/// percent-encoded on its own and the separators stay literal, since the
/// endpoint takes a ref path. Empty segments, which Git refuses in a ref
/// name, are refused here too.
fn encode_ref_path(tag: &str) -> Result<String, GitHubError> {
    if tag.is_empty()
        || tag.len() > MAX_TAG_BYTES
        || tag.chars().any(char::is_control)
        || tag.split('/').any(str::is_empty)
    {
        return Err(GitHubError::InvalidArgument("tag"));
    }
    Ok(tag
        .split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/"))
}

/// Percent-encodes everything except RFC 3986 unreserved characters; a
/// whole `.` or `..` segment is encoded too, so it cannot be normalised away.
fn percent_encode(value: &str) -> String {
    let dot_segment = value == "." || value == "..";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_~".contains(&byte) || (byte == b'.' && !dot_segment)
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_repository_id_redirect_is_followed() {
        assert_eq!(
            redirect_target("https://api.github.com/repositories/42").map(RepositoryId::get),
            Ok(42)
        );
        for location in [
            "http://api.github.com/repositories/42",
            "https://api.github.com.evil.example/repositories/42",
            "https://evil.example/repositories/42",
            "https://api.github.com/repositories/42/releases",
            "https://api.github.com/repositories/0",
            "https://api.github.com/repos/alice/tool",
            "/repositories/42",
        ] {
            assert_eq!(
                redirect_target(location),
                Err(GitHubError::RedirectRefused),
                "{location}"
            );
        }
    }

    #[test]
    fn tags_are_encoded_as_one_path_segment() {
        assert_eq!(percent_encode("v1.2.3"), "v1.2.3");
        assert_eq!(percent_encode("release/1.0+build"), "release%2F1.0%2Bbuild");
        assert_eq!(percent_encode("../x"), "..%2Fx");
        assert_eq!(percent_encode(".."), "%2E%2E");
    }

    #[test]
    fn tag_ref_paths_keep_separators_and_refuse_empty_segments() {
        assert_eq!(
            encode_ref_path("release/1.0+b"),
            Ok("release/1.0%2Bb".to_owned())
        );
        assert_eq!(encode_ref_path("a/../b"), Ok("a/%2E%2E/b".to_owned()));
        for tag in ["", "/v1", "v1/", "a//b", "bad\ntag"] {
            assert_eq!(
                encode_ref_path(tag),
                Err(GitHubError::InvalidArgument("tag")),
                "{tag:?}"
            );
        }
    }
}
