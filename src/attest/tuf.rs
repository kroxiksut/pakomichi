// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trusted roots refreshed through TUF (ADR-030 point 8).
//!
//! Each instance starts from a TUF `root.json` shipped with Pakomichi and
//! pinned by SHA-256, walks the root chain, and verifies timestamp,
//! snapshot, targets and the `trusted_root.json` target with `sigstore-tuf`.
//! Verified metadata is written through to a cache directory. When the
//! repository cannot be reached, the cache alone is verified again from the
//! pinned root, so it is used only while its metadata has not expired. A
//! verification failure of data from the network (a bad signature, a
//! rollback, a wrong target hash) is never replaced by the cache.

use std::path::Path;

use sigstore_tuf::cache::{FileStore, StoreRepository};
use sigstore_tuf::client::Updater;
use sigstore_tuf::transport::Repository;

/// A Sigstore instance whose trusted root comes from TUF.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TufInstance {
    /// GitHub's instance (`tuf-repo.github.com`): release attestations and
    /// private-repository artifact attestations (Strict).
    GitHub,
    /// Sigstore's public-good instance (`tuf-repo-cdn.sigstore.dev`):
    /// public-repository provenance (Attested).
    PublicGood,
}

/// GitHub's TUF root, version 9 (expires 2027-01-28), as shipped by
/// `sigstore-trust-root` 0.15.0.
const GITHUB_TUF_ROOT: &[u8] = include_bytes!("tuf/github-root.json");
/// Sigstore's public-good TUF root, version 15 (expires 2026-11-20), as
/// shipped by `sigstore-trust-root` 0.15.0. Later versions are reached by
/// walking the root chain.
const PUBLIC_GOOD_TUF_ROOT: &[u8] = include_bytes!("tuf/public-good-root.json");

/// The target that holds a Sigstore instance's trusted root.
pub const TRUSTED_ROOT_TARGET: &str = "trusted_root.json";

impl TufInstance {
    pub const ALL: [Self; 2] = [Self::GitHub, Self::PublicGood];

    pub const fn host(self) -> &'static str {
        match self {
            Self::GitHub => "tuf-repo.github.com",
            Self::PublicGood => "tuf-repo-cdn.sigstore.dev",
        }
    }

    /// The pinned bootstrap `root.json`.
    pub const fn bootstrap_root(self) -> &'static [u8] {
        match self {
            Self::GitHub => GITHUB_TUF_ROOT,
            Self::PublicGood => PUBLIC_GOOD_TUF_ROOT,
        }
    }

    /// The cache subdirectory of this instance.
    pub const fn cache_name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::PublicGood => "public-good",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::PublicGood => "Sigstore public-good",
        }
    }
}

/// Where a trusted root came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootSource {
    /// Refreshed from the TUF repository now.
    Refreshed,
    /// The repository could not be reached; the cached metadata verified
    /// again from the pinned root and has not expired.
    Cache,
}

/// Why a trusted root is not available. Every variant names the instance.
#[derive(Debug)]
pub enum RootError {
    /// The metadata expired and could not be refreshed: verification must
    /// stop until the repository is reachable again.
    Stale {
        instance: TufInstance,
        detail: String,
    },
    /// The repository could not be reached and there is no usable cache.
    Unreachable {
        instance: TufInstance,
        detail: String,
    },
    /// The metadata or the target did not verify (signature threshold,
    /// rollback, hash or length, malformed data). Never replaced by a cache.
    Invalid {
        instance: TufInstance,
        detail: String,
    },
    /// `ensure_crypto_provider` has not run: `sigstore-crypto` would panic
    /// on the first signature check, so nothing is fetched or read.
    ProviderMissing { instance: TufInstance },
}

impl RootError {
    pub const fn instance(&self) -> TufInstance {
        match self {
            Self::Stale { instance, .. }
            | Self::Unreachable { instance, .. }
            | Self::Invalid { instance, .. }
            | Self::ProviderMissing { instance } => *instance,
        }
    }
}

impl std::fmt::Display for RootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stale { instance, detail } => write!(
                formatter,
                "the {} trusted root has expired and could not be refreshed: {detail}",
                instance.as_str()
            ),
            Self::Unreachable { instance, detail } => write!(
                formatter,
                "the {} TUF repository is unreachable and nothing is cached: {detail}",
                instance.as_str()
            ),
            Self::Invalid { instance, detail } => write!(
                formatter,
                "the {} TUF metadata did not verify: {detail}",
                instance.as_str()
            ),
            Self::ProviderMissing { instance } => write!(
                formatter,
                "no cryptography provider installed; the {} TUF metadata cannot be verified",
                instance.as_str()
            ),
        }
    }
}

impl std::error::Error for RootError {}

enum Kind {
    Unreachable,
    Expired,
    Invalid,
}

fn kind(error: &sigstore_tuf::Error) -> Kind {
    match error {
        sigstore_tuf::Error::Transport { .. } => Kind::Unreachable,
        sigstore_tuf::Error::Expired { .. } => Kind::Expired,
        _ => Kind::Invalid,
    }
}

/// Fetches and verifies the `trusted_root.json` of `instance`.
///
/// `online` is the repository over the network; `cache_dir` holds the
/// verified metadata of this instance (created if absent). `now` decides
/// expiry. Without the crypto provider it refuses before any fetch or cache
/// access.
pub async fn fetch_trusted_root(
    instance: TufInstance,
    online: impl Repository + 'static,
    cache_dir: &Path,
    now: jiff::Timestamp,
) -> Result<(Vec<u8>, RootSource), RootError> {
    if sigstore_crypto::try_default_provider().is_none() {
        return Err(RootError::ProviderMissing { instance });
    }
    let invalid = |error: sigstore_tuf::Error| RootError::Invalid {
        instance,
        detail: error.to_string(),
    };
    let online_result = async {
        let mut updater = Updater::new(online, instance.bootstrap_root())
            .map_err(|error| Ok(invalid(error)))?
            .with_store(FileStore::new(cache_dir));
        updater.refresh(now).await.map_err(Err)?;
        updater
            .get_target(TRUSTED_ROOT_TARGET, now)
            .await
            .map_err(Err)
    }
    .await;
    let network_error = match online_result {
        Ok(bytes) => return Ok((bytes, RootSource::Refreshed)),
        Err(Ok(root_error)) => return Err(root_error),
        Err(Err(error)) => match kind(&error) {
            Kind::Unreachable => error,
            Kind::Expired => {
                return Err(RootError::Stale {
                    instance,
                    detail: error.to_string(),
                });
            }
            Kind::Invalid => return Err(invalid(error)),
        },
    };
    // Unreachable: verify the cache alone, again from the pinned root.
    let cached = async {
        let mut updater = Updater::new(
            StoreRepository::new(FileStore::new(cache_dir)),
            instance.bootstrap_root(),
        )?
        .with_store(FileStore::new(cache_dir));
        updater.refresh(now).await?;
        updater.get_target(TRUSTED_ROOT_TARGET, now).await
    }
    .await;
    match cached {
        Ok(bytes) => Ok((bytes, RootSource::Cache)),
        Err(error) => match kind(&error) {
            Kind::Expired => Err(RootError::Stale {
                instance,
                detail: error.to_string(),
            }),
            // An empty or partial cache.
            _ => Err(RootError::Unreachable {
                instance,
                detail: network_error.to_string(),
            }),
        },
    }
}

/// Builds [`super::TrustedRoots`] from the two instances, each through
/// [`fetch_trusted_root`]. The first failure is returned.
pub async fn refresh_trusted_roots<G, P>(
    github: G,
    public_good: P,
    cache_dir: &Path,
    now: jiff::Timestamp,
) -> Result<(super::TrustedRoots, [RootSource; 2]), RefreshError>
where
    G: Repository + 'static,
    P: Repository + 'static,
{
    let (github_json, github_source) = fetch_trusted_root(
        TufInstance::GitHub,
        github,
        &cache_dir.join(TufInstance::GitHub.cache_name()),
        now,
    )
    .await
    .map_err(RefreshError::Root)?;
    let (public_good_json, public_good_source) = fetch_trusted_root(
        TufInstance::PublicGood,
        public_good,
        &cache_dir.join(TufInstance::PublicGood.cache_name()),
        now,
    )
    .await
    .map_err(RefreshError::Root)?;
    let text = |bytes: Vec<u8>, instance: TufInstance| {
        String::from_utf8(bytes).map_err(|_| {
            RefreshError::Root(RootError::Invalid {
                instance,
                detail: "trusted_root.json is not UTF-8".into(),
            })
        })
    };
    let roots = super::TrustedRoots::from_json(
        &text(github_json, TufInstance::GitHub)?,
        &text(public_good_json, TufInstance::PublicGood)?,
    )
    .map_err(RefreshError::Parse)?;
    Ok((roots, [github_source, public_good_source]))
}

/// Why the trusted roots could not be refreshed.
#[derive(Debug)]
pub enum RefreshError {
    Root(RootError),
    /// A verified target did not parse as a trusted root.
    Parse(super::AttestationFailure),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root(error) => write!(formatter, "{error}"),
            Self::Parse(failure) => write!(formatter, "trusted root: {failure}"),
        }
    }
}

impl std::error::Error for RefreshError {}

#[cfg(test)]
#[path = "tuf_tests.rs"]
mod tests;
