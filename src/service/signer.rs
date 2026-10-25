// SPDX-License-Identifier: MIT OR Apache-2.0

//! Finding the Attested signer of a new source (ADR-036 point 1).
//!
//! The latest release is asked for the attestations of each asset by the
//! pinned repository ID; every provenance passes all checks of ADR-030
//! except that its workflow and ref are read from the verified
//! certificate. The result is only shown: the administrator's confirmation
//! stores it.

use std::collections::BTreeSet;

use crate::attest::{AttestationFailure, AttestationVerifier, AttestedSigner};
use crate::github::{GitHubClient, GitHubError, PinnedRepository, Transport};

/// At most this many assets are asked for attestations: one API request
/// each, and a release with more assets is rare. The rest are not looked at.
pub const MAX_DISCOVERY_ASSETS: usize = 20;

/// What discovery found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Discovery {
    Found(AttestedSigner),
    /// Different signers in one release: the administrator chooses.
    Ambiguous(Vec<AttestedSigner>),
    /// Why nothing was found, for the plan.
    NotFound(String),
}

/// Looks for the signer of the latest release of `pinned`. A GitHub error
/// is returned as such: it says nothing about the signer.
pub async fn discover_signer<T: Transport>(
    github: &GitHubClient<T>,
    verifier: Option<&AttestationVerifier>,
    pinned: &PinnedRepository,
) -> Result<Discovery, GitHubError> {
    let Some(verifier) = verifier else {
        return Ok(Discovery::NotFound(
            "the trusted roots are not available, so no attestation was checked".into(),
        ));
    };
    let Some(release) = github.latest_release(pinned).await? else {
        return Ok(Discovery::NotFound(
            "the repository has no published release".into(),
        ));
    };
    let release = release.value;
    let repository = pinned.repository_id();
    let Some(commit) = github.peeled_commit(repository, &release.tag).await? else {
        return Ok(Discovery::NotFound(format!(
            "the tag {} of the latest release does not exist",
            release.tag
        )));
    };
    let mut signers = BTreeSet::new();
    let mut first_failure: Option<AttestationFailure> = None;
    let mut looked_at = 0_usize;
    for asset in release
        .assets
        .iter()
        .filter(|asset| asset.uploaded)
        .take(MAX_DISCOVERY_ASSETS)
    {
        // Without the API's digest the attestations cannot be asked for
        // without downloading the bytes; such an asset is skipped.
        let Some(sha256) = asset.api_digest else {
            continue;
        };
        looked_at += 1;
        let bundles = github.attestation_bundles(repository, &sha256).await?;
        if bundles.is_empty() {
            continue;
        }
        let slices: Vec<&[u8]> = bundles.iter().map(Vec::as_slice).collect();
        match verifier.discover_attested(&slices, pinned, &release.tag, commit, sha256) {
            Ok(found) => signers.extend(found),
            Err(failure) => {
                first_failure.get_or_insert(failure);
            }
        }
    }
    let mut signers: Vec<AttestedSigner> = signers.into_iter().collect();
    Ok(match signers.len() {
        0 => Discovery::NotFound(match first_failure {
            Some(failure) => format!(
                "no provenance of release {} verified: {failure}",
                release.tag
            ),
            None if looked_at == 0 => format!(
                "no asset of release {} has a digest to look attestations up by",
                release.tag
            ),
            None => format!("release {} has no attestations", release.tag),
        }),
        1 => Discovery::Found(signers.remove(0)),
        _ => Discovery::Ambiguous(signers),
    })
}
