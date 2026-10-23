// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict and Attested verification (ADR-030 points 3–6).

use sigstore_trust_root::{SigstoreInstance, TrustedRoot};
use sigstore_types::Sha256Hash;
use sigstore_verify::{IdentityMatcher, VerificationPolicy, VerificationResult, Verifier};

use super::bundle::{
    self, Candidate, RELEASE_PREDICATE, SLSA_PROVENANCE_V1, STATEMENT_V1, Statement,
};
use super::reason::{AttestationFailure, MissingEvidence, SubReason, from_library};
use crate::cas::Sha256Digest;
use crate::github::{
    ExpectedRelease, GitObjectId, NamedSubject, OwnerId, PinnedRepository, ReleaseClaims,
    ReleaseMismatch, RepositoryId,
};

/// The verifier recorded in trust evidence.
pub const VERIFIER_VERSION: &str = "sigstore-verify 0.15.0";

/// The only SAN of a github.com release attestation certificate.
pub const RELEASE_SAN: &str = "https://dotcom.releases.github.com";
/// The OIDC issuer of GitHub Actions workload identities.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The two trusted roots, never merged (ADR-030 point 4).
#[derive(Clone, Debug)]
pub struct TrustedRoots {
    github: TrustedRoot,
    public_good: TrustedRoot,
}

impl TrustedRoots {
    /// Roots from `trusted_root.json` documents (for example, refreshed
    /// through TUF).
    pub fn from_json(github: &str, public_good: &str) -> Result<Self, AttestationFailure> {
        let parse = |text: &str| {
            TrustedRoot::from_json(text).map_err(|error| {
                AttestationFailure::invalid(SubReason::TrustRootInvalid, error.to_string())
            })
        };
        Ok(Self {
            github: parse(github)?,
            public_good: parse(public_good)?,
        })
    }

    /// The snapshots shipped with `sigstore-trust-root` 0.15.0. They go
    /// stale as the authorities rotate; ADR-030 point 8 refreshes them
    /// through TUF.
    pub fn embedded() -> Result<Self, AttestationFailure> {
        Self::from_json(
            SigstoreInstance::GitHub.embedded_trusted_root_json(),
            SigstoreInstance::PublicGood.embedded_trusted_root_json(),
        )
    }
}

/// Why a verifier could not be built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetupError {
    /// `ensure_crypto_provider` has not run: verification would panic.
    ProviderMissing,
    TrustRoot(AttestationFailure),
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderMissing => formatter.write_str("no cryptography provider installed"),
            Self::TrustRoot(failure) => write!(formatter, "trusted root: {failure}"),
        }
    }
}

impl std::error::Error for SetupError {}

/// Where an Attested build must have come from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceRef {
    /// `refs/tags/<release tag>`.
    ReleaseTag(String),
    /// `refs/heads/<branch>`, pinned for the source.
    Branch(String),
}

impl SourceRef {
    fn full(&self) -> String {
        match self {
            Self::ReleaseTag(tag) => format!("refs/tags/{tag}"),
            Self::Branch(branch) => format!("refs/heads/{branch}"),
        }
    }
}

/// A workflow path that is not `.github/workflows/<file>.yml|yaml`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidWorkflow;

/// What an Attested provenance must state for one asset (ADR-030 point 5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedProvenance {
    repository_id: RepositoryId,
    accepted_owner_ids: Vec<OwnerId>,
    workflow: String,
    source_ref: SourceRef,
    commit: GitObjectId,
    asset_sha256: Sha256Digest,
}

impl ExpectedProvenance {
    /// `workflow` is the path inside the repository, compared exactly, for
    /// example `.github/workflows/release.yml`; `commit` is the commit the
    /// release tag points to (peeled, unlike the Strict `sha1` subject, which
    /// is the tag reference object as GitHub returns it); `asset_sha256` is
    /// the digest of the current asset (see `github::current_asset`).
    pub fn new(
        repository: &PinnedRepository,
        workflow: impl Into<String>,
        source_ref: SourceRef,
        commit: GitObjectId,
        asset_sha256: Sha256Digest,
    ) -> Result<Self, InvalidWorkflow> {
        let workflow = workflow.into();
        let file = workflow
            .strip_prefix(".github/workflows/")
            .ok_or(InvalidWorkflow)?;
        let valid = !file.is_empty()
            && (file.ends_with(".yml") || file.ends_with(".yaml"))
            && file
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && !file.starts_with('.');
        if !valid {
            return Err(InvalidWorkflow);
        }
        Ok(Self {
            repository_id: repository.repository_id(),
            accepted_owner_ids: repository.accepted_owner_ids().collect(),
            workflow,
            source_ref,
            commit,
            asset_sha256,
        })
    }
}

/// A verified release attestation (Strict).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictEvidence {
    pub owner_id: u64,
    /// Earliest verified RFC 3161 time, seconds since the epoch.
    pub signed_at: i64,
    pub bundle_sha256: Sha256Digest,
}

/// A verified SLSA provenance (Attested).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedEvidence {
    pub owner_id: u64,
    /// The signer, `https://github.com/<owner>/<repo>/<workflow>@<ref>`.
    pub signer: String,
    /// The repository URI at signing time; it differs from the current name
    /// after a rename, which is a notice, not a failure.
    pub source_repository: String,
    /// Earliest verified time, seconds since the epoch.
    pub signed_at: i64,
    pub bundle_sha256: Sha256Digest,
}

/// The production verifier: one `sigstore-verify` instance per root.
pub struct AttestationVerifier {
    strict: Verifier,
    attested: Verifier,
}

impl std::fmt::Debug for AttestationVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttestationVerifier")
            .finish_non_exhaustive()
    }
}

impl AttestationVerifier {
    pub fn new(roots: &TrustedRoots) -> Result<Self, SetupError> {
        if sigstore_crypto::try_default_provider().is_none() {
            return Err(SetupError::ProviderMissing);
        }
        let build = |root: &TrustedRoot| {
            Verifier::new(root).map_err(|error| {
                SetupError::TrustRoot(AttestationFailure::invalid(
                    from_library(&error),
                    error.to_string(),
                ))
            })
        };
        Ok(Self {
            strict: build(&roots.github)?,
            attested: build(&roots.public_good)?,
        })
    }

    /// Strict: an immutable release and a release attestation from
    /// GitHub's authority whose predicate names this release and asset.
    /// The `immutable` flag is required but is never evidence by itself.
    pub fn verify_strict(
        &self,
        bundles: &[&[u8]],
        expected: &ExpectedRelease,
        immutable: Option<bool>,
    ) -> Result<StrictEvidence, AttestationFailure> {
        if immutable != Some(true) {
            return Err(AttestationFailure::Missing(MissingEvidence::NotImmutable));
        }
        let policy = VerificationPolicy::any_identity()
            .require_identity(IdentityMatcher::Uri(RELEASE_SAN.into()))
            .skip_tlog_unsafe()
            .skip_sct();
        verify_set(
            bundles,
            RELEASE_PREDICATE,
            MissingEvidence::NoReleaseAttestation,
            |candidate, bytes| {
                let result =
                    verify_crypto(&self.strict, &candidate, expected.asset_sha256(), &policy)?;
                let claims = release_claims(&candidate.statement)?;
                expected.check_release_claims(&claims).map_err(|mismatch| {
                    AttestationFailure::invalid(release_sub_reason(&mismatch), mismatch.to_string())
                })?;
                Ok(StrictEvidence {
                    owner_id: claims.owner_id,
                    signed_at: earliest(&result)?,
                    bundle_sha256: Sha256Digest::of(bytes),
                })
            },
        )
    }

    /// Attested: an SLSA provenance from public-good Sigstore with a
    /// verified SCT and transparency-log inclusion, bound to the pinned
    /// repository and owner IDs, the workflow, the ref and the commit.
    pub fn verify_attested(
        &self,
        bundles: &[&[u8]],
        expected: &ExpectedProvenance,
    ) -> Result<AttestedEvidence, AttestationFailure> {
        let policy = VerificationPolicy::any_identity().require_issuer(GITHUB_ACTIONS_ISSUER);
        verify_set(
            bundles,
            SLSA_PROVENANCE_V1,
            MissingEvidence::NoProvenance,
            |candidate, bytes| {
                let result =
                    verify_crypto(&self.attested, &candidate, expected.asset_sha256, &policy)?;
                if !(result.sct_verified() && result.tlog_verified()) {
                    return Err(AttestationFailure::invalid(
                        SubReason::TlogInclusion,
                        "SCT or transparency-log inclusion not verified",
                    ));
                }
                let (owner_id, signer, source_repository) = check_provenance(&result, expected)?;
                Ok(AttestedEvidence {
                    owner_id,
                    signer,
                    source_repository,
                    signed_at: earliest(&result)?,
                    bundle_sha256: Sha256Digest::of(bytes),
                })
            },
        )
    }
}

/// Tries every bundle with the wanted predicate; the first that passes
/// wins, otherwise the first failure is reported. Bundles with another
/// predicate are skipped; no matching bundle is missing evidence.
fn verify_set<E>(
    bundles: &[&[u8]],
    predicate: &str,
    missing: MissingEvidence,
    mut check: impl FnMut(Candidate, &[u8]) -> Result<E, AttestationFailure>,
) -> Result<E, AttestationFailure> {
    bundle::check_count(bundles)?;
    let mut first_failure = None;
    for bytes in bundles {
        let candidate = match bundle::decode(bytes) {
            Ok(candidate) => candidate,
            Err(failure) => {
                first_failure.get_or_insert(failure);
                continue;
            }
        };
        if candidate.statement.predicate_type != predicate {
            continue;
        }
        match check(candidate, bytes) {
            Ok(evidence) => return Ok(evidence),
            Err(failure) => {
                first_failure.get_or_insert(failure);
            }
        }
    }
    Err(first_failure.unwrap_or(AttestationFailure::Missing(missing)))
}

/// Verifies the signature, certificate, times and digest binding, then the
/// statement type. The statement is interpreted only after this.
fn verify_crypto(
    verifier: &Verifier,
    candidate: &Candidate,
    sha256: Sha256Digest,
    policy: &VerificationPolicy,
) -> Result<VerificationResult, AttestationFailure> {
    let digest = Sha256Hash::from_hex(&sha256.to_hex()).map_err(|error| {
        AttestationFailure::invalid(SubReason::BundleMalformed, error.to_string())
    })?;
    let result = verifier
        .verify(digest, &candidate.bundle, policy)
        .map_err(|error| AttestationFailure::invalid(from_library(&error), error.to_string()))?;
    if !result.certificate_verified() || result.verified_timestamps().is_empty() {
        return Err(AttestationFailure::invalid(
            SubReason::NoVerifiedTime,
            "certificate or signing time not verified",
        ));
    }
    if candidate.statement.kind != STATEMENT_V1 {
        return Err(AttestationFailure::invalid(
            SubReason::StatementInvalid,
            "not an in-toto Statement v1",
        ));
    }
    Ok(result)
}

fn earliest(result: &VerificationResult) -> Result<i64, AttestationFailure> {
    result
        .verified_timestamps()
        .iter()
        .min()
        .map(|time| time.as_second())
        .ok_or_else(|| AttestationFailure::invalid(SubReason::NoVerifiedTime, "no verified time"))
}

fn release_sub_reason(mismatch: &ReleaseMismatch) -> SubReason {
    match mismatch {
        ReleaseMismatch::RepositoryId { .. } => SubReason::RepositoryIdMismatch,
        ReleaseMismatch::OwnerId { .. } => SubReason::OwnerIdMismatch,
        ReleaseMismatch::AssetSubject => SubReason::SubjectMismatch,
        _ => SubReason::ReleaseMismatch,
    }
}

/// The claims of a verified release attestation (predicate release v0.2).
fn release_claims(statement: &Statement) -> Result<ReleaseClaims, AttestationFailure> {
    let malformed = |field: &str| {
        AttestationFailure::invalid(
            SubReason::StatementInvalid,
            format!("release predicate: {field} missing or not a decimal ID"),
        )
    };
    let id = |field: &'static str| {
        statement
            .predicate
            .get(field)
            .and_then(serde_json::Value::as_str)
            .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| malformed(field))
    };
    let tag = statement
        .predicate
        .get("tag")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| malformed("tag"))?
        .to_owned();
    let mut tag_refs = Vec::new();
    let mut assets = Vec::new();
    for subject in &statement.subject {
        if subject
            .uri
            .as_deref()
            .is_some_and(|uri| uri.starts_with("pkg:github/"))
            && let Some(tag_ref) = subject.digest.get("sha1")
        {
            let tag_ref = GitObjectId::from_hex(tag_ref).map_err(|_| malformed("sha1 subject"))?;
            tag_refs.push(tag_ref);
        }
        if let (Some(name), Some(sha256)) = (&subject.name, subject.digest.get("sha256")) {
            let sha256 = Sha256Digest::from_hex(sha256).map_err(|_| malformed("sha256 subject"))?;
            assets.push(NamedSubject {
                name: name.clone(),
                sha256,
            });
        }
    }
    Ok(ReleaseClaims {
        repository_id: id("repositoryId")?,
        package_id: id("packageId")?,
        owner_id: id("ownerId")?,
        database_id: id("databaseId")?,
        tag,
        tag_refs,
        assets,
    })
}

/// Checks the Fulcio claims against the pin; returns the owner ID, the
/// signer, and the repository URI at signing time.
fn check_provenance(
    result: &VerificationResult,
    expected: &ExpectedProvenance,
) -> Result<(u64, String, String), AttestationFailure> {
    let claims = &result
        .certificate()
        .ok_or_else(|| {
            AttestationFailure::invalid(SubReason::CertificateUntrusted, "no certificate")
        })?
        .ci_claims;
    let mismatch =
        |sub_reason, what: &str| AttestationFailure::invalid(sub_reason, what.to_owned());
    if claims.source_repository_identifier.as_deref()
        != Some(expected.repository_id.get().to_string().as_str())
    {
        return Err(mismatch(
            SubReason::RepositoryIdMismatch,
            "source repository ID is not the pinned one",
        ));
    }
    let owner_id = claims
        .source_repository_owner_identifier
        .as_deref()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|owner| {
            expected
                .accepted_owner_ids
                .iter()
                .any(|accepted| accepted.get() == *owner)
        })
        .ok_or_else(|| {
            mismatch(
                SubReason::OwnerIdMismatch,
                "owner ID is not a confirmed owner",
            )
        })?;
    // build_signer_uri = <source repository URI>/<workflow path>@<ref>: the
    // signer must be the source repository itself (no reusable workflow
    // from another repository in 0.1), compared exactly.
    let source = claims.source_repository_uri.clone().unwrap_or_default();
    let signer = claims.build_signer_uri.clone().unwrap_or_default();
    let (path, signer_ref) = signer
        .strip_prefix(source.as_str())
        .filter(|_| !source.is_empty())
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.rsplit_once('@'))
        .ok_or_else(|| {
            mismatch(
                SubReason::WorkflowMismatch,
                "signer is not a workflow of the source repository",
            )
        })?;
    if path != expected.workflow {
        return Err(mismatch(
            SubReason::WorkflowMismatch,
            "signer workflow is not the pinned one",
        ));
    }
    let wanted_ref = expected.source_ref.full();
    if claims.source_repository_ref.as_deref() != Some(wanted_ref.as_str()) {
        return Err(mismatch(
            SubReason::RefMismatch,
            "source ref is not the expected one",
        ));
    }
    if signer_ref != wanted_ref {
        return Err(mismatch(
            SubReason::WorkflowMismatch,
            "signer workflow ran from another ref",
        ));
    }
    if claims.source_repository_digest.as_deref() != Some(expected.commit.to_hex().as_str()) {
        return Err(mismatch(
            SubReason::CommitMismatch,
            "source commit is not the commit the release tag points to",
        ));
    }
    if claims.runner_environment.as_deref() != Some("github-hosted") {
        return Err(mismatch(
            SubReason::RunnerNotHosted,
            "not built on a GitHub-hosted runner",
        ));
    }
    Ok((owner_id, signer, source))
}
