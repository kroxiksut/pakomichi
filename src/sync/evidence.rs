// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provenance evidence for one asset through GitHub (ADR-030, ADR-034,
//! ADR-036 point 1).
//!
//! The attestations of the exact bytes are looked up by the pinned
//! repository ID. An immutable release is checked for a release
//! attestation first (Strict); then, when the source has a confirmed
//! signer, for an SLSA provenance of that signer (Attested). A failed
//! verification is never rescued by a weaker level: it is `Invalid`.

use std::sync::Arc;

use tokio::runtime::Handle;

use super::{Checked, EvidenceCheck, EvidenceRecord};
use crate::attest::{
    AttestationFailure, AttestationVerifier, AttestedSigner, ExpectedProvenance, RELEASE_PREDICATE,
    SLSA_PROVENANCE_V1,
};
use crate::cas::Sha256Digest;
use crate::github::{ExpectedRelease, GitHubClient, PinnedRepository, Release, Transport};
use crate::policy::level::{Level, Verified};

/// [`EvidenceCheck`] over the GitHub API and the production verifier.
pub struct GitHubEvidence<'a, T> {
    pub github: &'a GitHubClient<T>,
    /// `None` when the trusted roots are not available: nothing verifies.
    pub verifier: Option<Arc<AttestationVerifier>>,
    pub runtime: Handle,
}

fn record_json(fields: serde_json::Value) -> String {
    fields.to_string()
}

impl<T: Transport> EvidenceCheck for GitHubEvidence<'_, T> {
    fn check(
        &self,
        pinned: &PinnedRepository,
        release: &Release,
        asset_name: &str,
        sha256: Sha256Digest,
        signer: Option<&AttestedSigner>,
    ) -> Result<Checked, String> {
        let Some(verifier) = self.verifier.as_deref() else {
            return Ok(Checked::nothing("the trusted roots are not available"));
        };
        let repository = pinned.repository_id();
        let bundles = self
            .runtime
            .block_on(self.github.attestation_bundles(repository, &sha256))
            .map_err(|error| format!("GitHub: {error}"))?;
        let slices: Vec<&[u8]> = bundles.iter().map(Vec::as_slice).collect();
        let invalid = |failure: AttestationFailure| Checked {
            verified: Verified::Invalid,
            record: None,
            note: failure.to_string(),
        };
        if release.immutable == Some(true) {
            let tag_ref = self
                .runtime
                .block_on(self.github.tag_ref(repository, &release.tag))
                .map_err(|error| format!("GitHub: {error}"))?;
            if let Some(tag_ref) = tag_ref {
                let expected =
                    ExpectedRelease::new(pinned, release, tag_ref.value.object, asset_name, sha256);
                match verifier.verify_strict(&slices, &expected, release.immutable) {
                    Ok(evidence) => {
                        return Ok(Checked {
                            verified: Verified::Strict,
                            record: Some(EvidenceRecord {
                                level: Level::Strict,
                                signer_identity: crate::attest::RELEASE_SAN.to_owned(),
                                predicate_type: RELEASE_PREDICATE,
                                bundle_sha256: evidence.bundle_sha256,
                                record_json: record_json(serde_json::json!({
                                    "owner_id": evidence.owner_id,
                                    "signed_at": evidence.signed_at,
                                    "release_id": release.id.get(),
                                    "tag": release.tag,
                                })),
                            }),
                            note: "release attestation verified".to_owned(),
                        });
                    }
                    Err(AttestationFailure::Missing(_)) => {}
                    Err(failure) => return Ok(invalid(failure)),
                }
            }
        }
        let Some(signer) = signer else {
            return Ok(Checked::nothing(
                "no release attestation, and the source has no Attested signer",
            ));
        };
        let commit = self
            .runtime
            .block_on(self.github.peeled_commit(repository, &release.tag))
            .map_err(|error| format!("GitHub: {error}"))?;
        let Some(commit) = commit else {
            return Ok(Checked::nothing("the release tag does not exist"));
        };
        let expected = ExpectedProvenance::for_signer(pinned, signer, &release.tag, commit, sha256);
        match verifier.verify_attested(&slices, &expected) {
            Ok(evidence) => Ok(Checked {
                verified: Verified::Attested,
                record: Some(EvidenceRecord {
                    level: Level::Attested,
                    signer_identity: evidence.signer.clone(),
                    predicate_type: SLSA_PROVENANCE_V1,
                    bundle_sha256: evidence.bundle_sha256,
                    record_json: record_json(serde_json::json!({
                        "owner_id": evidence.owner_id,
                        "signed_at": evidence.signed_at,
                        "source_repository": evidence.source_repository,
                        "commit": commit.to_hex(),
                        "release_id": release.id.get(),
                        "tag": release.tag,
                    })),
                }),
                note: "provenance verified".to_owned(),
            }),
            Err(AttestationFailure::Missing(missing)) => Ok(Checked::nothing(
                &AttestationFailure::Missing(missing).to_string(),
            )),
            Err(failure) => Ok(invalid(failure)),
        }
    }
}
