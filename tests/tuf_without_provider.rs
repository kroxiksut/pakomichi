// SPDX-License-Identifier: MIT OR Apache-2.0

//! A process that skipped `ensure_crypto_provider` must get an error from
//! the TUF refresh, not a panic: `sigstore-tuf` verifies the pinned root's
//! signatures before it touches the network, and `sigstore-crypto` panics
//! when no provider is installed (ADR-030 point 2).
//!
//! This file is a test binary of its own, so nothing in its process ever
//! installs the provider, under `cargo test` and under nextest alike.

use std::error::Error;

use pakomichi::attest::{RootError, TufInstance, fetch_trusted_root};
use sigstore_tuf::transport::{FetchFuture, Repository};

/// A TUF repository that is down.
struct Down;

impl Repository for Down {
    fn fetch_metadata<'a>(&'a self, _name: &'a str, _max_length: u64) -> FetchFuture<'a> {
        Box::pin(async { Err(sigstore_tuf::Error::transport("connection refused (test)")) })
    }

    fn fetch_target<'a>(&'a self, _path: &'a str, _max_length: u64) -> FetchFuture<'a> {
        Box::pin(async { Err(sigstore_tuf::Error::transport("connection refused (test)")) })
    }
}

#[test]
fn without_a_crypto_provider_the_refresh_fails_closed_without_a_panic() -> Result<(), Box<dyn Error>>
{
    assert!(
        sigstore_crypto::try_default_provider().is_none(),
        "this test needs a process without a provider"
    );
    let cache =
        std::env::temp_dir().join(format!("pakomichi-tuf-no-provider-{}", std::process::id()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let now: jiff::Timestamp = "2026-10-24T00:00:00Z".parse()?;
    let result = runtime.block_on(fetch_trusted_root(TufInstance::GitHub, Down, &cache, now));
    // The refusal comes before any cache access.
    let touched = cache.exists();
    let _ = std::fs::remove_dir_all(&cache);
    assert!(
        matches!(
            result,
            Err(RootError::ProviderMissing {
                instance: TufInstance::GitHub
            })
        ),
        "{result:?}"
    );
    assert!(!touched, "the cache directory was created");
    Ok(())
}
