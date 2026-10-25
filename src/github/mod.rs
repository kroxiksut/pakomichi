// SPDX-License-Identifier: MIT OR Apache-2.0

//! GitHub Releases adapter: identity pinning and the REST client (P2-001).
//!
//! Contract: `docs/en/specifications/github.md`. A source is pinned to its
//! numeric repository ID and every confirmed owner ID (`identity`); admitted
//! assets are pinned as (release ID, asset ID, SHA-256) and release
//! attestation claims are checked against the expected release
//! (`release_pin`, R-003); responses are parsed
//! into validated types (`wire`, ADR-019 point 3); the client handles
//! conditional requests (`conditional`, R-004 conclusion 14), rate limits
//! (`rate_limit`), and pagination (`pagination`) over a [`Transport`]. The
//! hyper-based transport (`http`) runs in the long-lived network process
//! (ADR-017) over rustls with the system CA store (`tls`).

mod address;
mod asset;
mod client;
mod conditional;
mod http;
mod identity;
mod pagination;
mod rate_limit;
mod release_pin;
mod tls;
mod token;
mod transport;
mod wire;

pub use address::{AddressError, parse_repository_address};
pub use asset::{
    ASSET_HOSTS, AddressRange, AssetDownloader, AssetLocator, DownloadConfig, DownloadError,
    RangeRefused,
};
pub use client::{
    ClientConfig, Fetched, Freshness, GitHubClient, GitHubError, ReleaseListing, ResolvedRepository,
};
pub use conditional::{CacheKey, CachedResponse, DEFAULT_CACHE_BYTES, EtagCache, weak_match};
pub use http::{
    HttpConfig, HttpTransport, Resolve, SecureConnector, SystemResolver, is_public_address,
};
pub use identity::{
    AssetId, FORGE, IdentityError, IdentityOutcome, OwnerId, OwnerLogin, PinnedRepository,
    ReleaseId, RepositoryId, RepositoryIdentity, RepositoryName, WEB_ORIGIN,
};
pub use pagination::PaginationError;
pub use rate_limit::{
    Clock, MAX_WAIT, QuotaSnapshot, RateLimitKind, RateLimited, SECONDARY_BASE_WAIT, SystemClock,
};
pub use release_pin::{
    AssetCheck, AssetPin, BytesMutated, CurrentAssetError, ExpectedRelease, GitObjectId,
    InvalidObjectId, NamedSubject, ReleaseClaims, ReleaseMismatch, current_asset,
};
pub use tls::{RustlsConnector, TlsSetupError};
pub use token::{CredentialId, MAX_TOKEN_BYTES, Token, TokenError};
pub use transport::{
    API_HOST, API_ORIGIN, API_VERSION, ApiRequest, ApiResponse, ResponseHeaders, Transport,
    TransportError,
};
pub use wire::{
    AnnotatedTag, MAX_ASSETS_PER_RELEASE, MAX_RELEASES_PER_PAGE, MAX_RESPONSE_BYTES, Release,
    ReleaseAsset, TagObjectKind, TagRef, WireError, parse_release, parse_release_page,
    parse_repository, parse_tag_object, parse_tag_ref,
};
