// SPDX-License-Identifier: MIT OR Apache-2.0

//! GitHub Strict and Attested verification (P2-003, P2-004; ADR-030).
//!
//! `sigstore-verify` 0.15.0 checks the cryptography: the certificate chain
//! to the right root, the signing time, the DSSE signature, the digest
//! binding and, for Attested, the SCT and the transparency log. Everything
//! that binds an attestation to a source is Pakomichi's own and compares
//! immutable IDs, never names:
//!
//! - Strict: an immutable release; a release attestation from GitHub's
//!   authority (SAN `https://dotcom.releases.github.com`, RFC 3161 time)
//!   whose predicate names the pinned repository as `repositoryId` and
//!   `packageId`, a confirmed owner ID, this release's ID and tag, the tag
//!   commit, and the asset's name with its digest (`github::ExpectedRelease`).
//! - Attested: an SLSA provenance from public-good Sigstore whose Fulcio
//!   claims carry the pinned repository ID, a confirmed owner ID, the pinned
//!   workflow of the repository itself, the expected ref and the tag commit,
//!   built on a GitHub-hosted runner.
//!
//! A failure is `E_ATTESTATION_INVALID` with one sub-reason; missing
//! evidence is `E_EVIDENCE_DOWNGRADE`. [`ensure_crypto_provider`] must run
//! at process start.
//!
//! The trusted roots come from TUF ([`refresh_trusted_roots`], ADR-030
//! point 8) over [`TufHttp`]; without network an unexpired verified cache
//! is used, and expired metadata stops verification.
//! [`TrustedRoots::embedded`] gives the snapshots shipped with the library,
//! for tests and diagnostics.

mod bundle;
mod provider;
mod reason;
mod tuf;
mod tuf_http;
mod verifier;

pub use bundle::{MAX_BUNDLE_BYTES, MAX_BUNDLES, RELEASE_PREDICATE, SLSA_PROVENANCE_V1};
pub use provider::{ProviderConflict, ensure_crypto_provider};
pub use reason::{AttestationFailure, MissingEvidence, SubReason};
pub use tuf::{
    RefreshError, RootError, RootSource, TRUSTED_ROOT_TARGET, TufInstance, fetch_trusted_root,
    refresh_trusted_roots,
};
pub use tuf_http::{TUF_HOSTS, TufHttp, TufRepository};
pub use verifier::{
    AttestationVerifier, AttestedEvidence, ExpectedProvenance, GITHUB_ACTIONS_ISSUER,
    InvalidWorkflow, RELEASE_SAN, SetupError, SourceRef, StrictEvidence, TrustedRoots,
    VERIFIER_VERSION,
};

#[cfg(test)]
mod tests;
