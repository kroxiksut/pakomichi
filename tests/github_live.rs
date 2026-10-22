// SPDX-License-Identifier: MIT OR Apache-2.0

//! LIVE, ignored by default: the production transport (rustls, system CA
//! store, public-address policy) against the anonymous public GitHub API.
//!
//! Run explicitly, once, from a host with direct Internet access:
//!
//! ```text
//! cargo test --test github_live -- --ignored --nocapture
//! ```
//!
//! It sends six anonymous read-only requests (the anonymous limit is 60 per
//! hour) and prints the headers that matter for pagination and caching. It
//! needs no token and must never be given one. A resolver that answers with
//! a non-public address (for example a fake-IP proxy in 198.18.0.0/15) makes
//! it fail with `AddressRefused`; that is the policy working, not a defect.

use std::error::Error;
use std::sync::{Arc, Mutex, PoisonError};

use pakomichi::github::{
    ApiRequest, ApiResponse, ClientConfig, Freshness, GitHubClient, HttpConfig, HttpTransport,
    MAX_RESPONSE_BYTES, OwnerLogin, PinnedRepository, RepositoryName, RustlsConnector, Transport,
    TransportError,
};
use pakomichi::inventory::{Ecosystem, InventoryPolicy, TargetPlatform, inventory_release};
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

/// Wraps the real transport and keeps what each exchange returned.
struct Recording<T> {
    inner: T,
    exchanges: Arc<Mutex<Vec<(String, ApiResponse)>>>,
}

impl<T: Transport> Transport for Recording<T> {
    async fn send(
        &self,
        request: ApiRequest,
        max_body_bytes: usize,
    ) -> Result<ApiResponse, TransportError> {
        let path = request.path().to_owned();
        let response = self.inner.send(request, max_body_bytes).await?;
        self.exchanges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((path, response.clone()));
        Ok(response)
    }
}

#[tokio::test]
#[ignore = "live: anonymous requests to api.github.com"]
async fn anonymous_public_api_round_trip() -> TestResult {
    let connector = RustlsConnector::with_native_roots()?;
    let exchanges = Arc::new(Mutex::new(Vec::new()));
    let transport = Recording {
        inner: HttpTransport::new(connector, HttpConfig::default()),
        exchanges: Arc::clone(&exchanges),
    };
    // Five releases per page and two pages: pagination is exercised with
    // two requests, and the listing must come back truncated.
    let client = GitHubClient::new(transport, None).with_config(ClientConfig {
        max_body_bytes: MAX_RESPONSE_BYTES,
        per_page: 5,
        max_pages: 2,
    });

    // 1. Resolve by name and pin.
    let pinned: PinnedRepository = client
        .pin_source(&OwnerLogin::new("cli")?, &RepositoryName::new("cli")?)
        .await?;
    let identity = pinned.identity().clone();
    println!(
        "resolved {} -> repository id {}, owner id {}",
        identity.full_name(),
        identity.repository_id(),
        identity.owner_id()
    );

    // 2. The same repository by ID, then 3. again with the stored ETag.
    let by_id = client.repository_by_id(identity.repository_id()).await?;
    assert_eq!(by_id.value, identity);
    assert_eq!(by_id.freshness, Freshness::Modified);
    let again = client.repository_by_id(identity.repository_id()).await?;
    assert_eq!(again.value, identity);
    println!("conditional repeat by id: {:?}", again.freshness);

    // 4-5. Two pages of releases through the real Link header.
    let listing = client.list_releases(&pinned).await?;
    assert_eq!(listing.releases.len(), 10);
    assert!(listing.truncated, "cli/cli has more than ten releases");

    // 6. The latest release and its asset digests.
    let latest = client
        .latest_release(&pinned)
        .await?
        .ok_or("cli/cli has a latest release")?
        .value;
    let parsed_digests = latest
        .assets
        .iter()
        .filter(|asset| asset.api_digest.is_some())
        .count();
    println!(
        "latest {}: immutable {:?}, {} assets, {} with a parsed SHA-256 digest",
        latest.tag,
        latest.immutable,
        latest.assets.len(),
        parsed_digests
    );

    let exchanges = exchanges
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    for (path, response) in &exchanges {
        println!(
            "{path} -> {} etag={:?} link={:?} remaining={:?} resource={:?}",
            response.status,
            response.headers.etag,
            response.headers.link,
            response.headers.ratelimit_remaining,
            response.headers.ratelimit_resource
        );
    }
    assert_eq!(exchanges.len(), 6);

    // Every asset whose raw digest claims SHA-256 parsed; nothing else did.
    let (_, latest_response) = exchanges.last().ok_or("no exchange")?;
    let raw: Value = serde_json::from_slice(&latest_response.body)?;
    let raw_sha256 = raw["assets"]
        .as_array()
        .ok_or("assets")?
        .iter()
        .filter(|asset| {
            asset["digest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:"))
        })
        .count();
    assert_eq!(parsed_digests, raw_sha256);

    // P2-002: the inventory of the same release for both first ecosystems,
    // without further requests. cli/cli publishes .deb and .rpm for several
    // CPUs next to archives and checksums.
    for (ecosystem, arch) in [(Ecosystem::Deb, "amd64"), (Ecosystem::Rpm, "x86_64")] {
        let target = TargetPlatform::new(ecosystem, arch)?;
        let inventory = inventory_release(&latest, &target, &InventoryPolicy::default());
        let candidates: Vec<&str> = inventory
            .candidates()
            .map(|entry| entry.name.as_str())
            .collect();
        let review: Vec<&str> = inventory
            .needs_review()
            .map(|entry| entry.name.as_str())
            .collect();
        println!(
            "inventory {ecosystem}/{arch}: channel {:?}, excluded {:?}, candidates {candidates:?}, review {review:?}",
            inventory.channel, inventory.excluded
        );
        assert_eq!(candidates.len(), 1, "one {ecosystem} package for {arch}");
    }
    Ok(())
}
