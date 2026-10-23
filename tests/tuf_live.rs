// SPDX-License-Identifier: MIT OR Apache-2.0

//! LIVE, ignored by default: refreshes the trusted roots through TUF with
//! the production transport (rustls, system CA store, public-address
//! policy) from `tuf-repo.github.com` and `tuf-repo-cdn.sigstore.dev`
//! (ADR-030 point 8).
//!
//! Run explicitly from a host with direct Internet access:
//!
//! ```text
//! cargo test --test tuf_live -- --ignored --nocapture
//! ```
//!
//! Each test downloads a few small public metadata files, verifies them from
//! the pinned TUF root, refreshes twice against one temporary cache, and
//! prints the TUF root version it reached. A resolver that answers with a
//! non-public address (for example a fake-IP proxy in 198.18.0.0/15, even
//! next to real addresses) makes a test fail with "resolved address is not
//! public"; that is the policy working, not a defect.

use std::error::Error;
use std::sync::Arc;

use pakomichi::attest::{
    RootSource, TrustedRoots, TufHttp, TufInstance, TufRepository, ensure_crypto_provider,
    fetch_trusted_root,
};
use pakomichi::github::{HttpConfig, RustlsConnector};

async fn refresh(instance: TufInstance) -> Result<(), Box<dyn Error>> {
    ensure_crypto_provider()?;
    let http = Arc::new(TufHttp::new(
        RustlsConnector::with_native_roots()?,
        HttpConfig::default(),
    ));
    let cache = std::env::temp_dir().join(format!(
        "pakomichi-tuf-live-{}-{}",
        instance.cache_name(),
        std::process::id()
    ));
    std::fs::create_dir_all(&cache)?;
    let result = async {
        for round in 1..=2 {
            let started = std::time::Instant::now();
            let (bytes, source) = fetch_trusted_root(
                instance,
                TufRepository::new(Arc::clone(&http), instance.host()),
                &cache,
                jiff::Timestamp::now(),
            )
            .await?;
            assert_eq!(source, RootSource::Refreshed);
            let text = String::from_utf8(bytes)?;
            TrustedRoots::from_json(&text, &text)?;
            println!(
                "{} round {round}: trusted_root.json {} bytes in {:?}",
                instance.as_str(),
                text.len(),
                started.elapsed()
            );
        }
        let root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(cache.join("root.json"))?)?;
        println!(
            "{}: TUF root version {} expires {}",
            instance.as_str(),
            root["signed"]["version"],
            root["signed"]["expires"]
        );
        Ok::<(), Box<dyn Error>>(())
    }
    .await;
    let _ = std::fs::remove_dir_all(&cache);
    result
}

#[tokio::test]
#[ignore = "live: TUF metadata from tuf-repo-cdn.sigstore.dev"]
async fn public_good_trusted_root_refreshes() -> Result<(), Box<dyn Error>> {
    refresh(TufInstance::PublicGood).await
}

#[tokio::test]
#[ignore = "live: TUF metadata from tuf-repo.github.com"]
async fn github_trusted_root_refreshes() -> Result<(), Box<dyn Error>> {
    refresh(TufInstance::GitHub).await
}
