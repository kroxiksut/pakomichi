// SPDX-License-Identifier: MIT OR Apache-2.0

//! Why an attestation was not accepted (ADR-030 point 7).
//!
//! A failed verification is `E_ATTESTATION_INVALID` with one typed
//! sub-reason; missing evidence is `E_EVIDENCE_DOWNGRADE`. The detail text
//! comes from the verifier and the policy, never from network input.

use std::fmt;

use crate::error::{ObjectReference, Reason, ReasonCode, ReasonSubcode, SafeText, SafeValueError};

/// Sub-reasons under `E_ATTESTATION_INVALID`, named as in ADR-030 point 7.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SubReason {
    BundleTooLarge,
    TooManyBundles,
    BundleMalformed,
    BundleUnsupported,
    SignatureInvalid,
    ArtifactDigestMismatch,
    CertificateUntrusted,
    CertificateTime,
    SctInvalid,
    TlogInclusion,
    TlogCheckpoint,
    TlogPromise,
    TlogEntry,
    TimestampInvalid,
    NoVerifiedTime,
    IdentityMismatch,
    RepositoryIdMismatch,
    OwnerIdMismatch,
    ReleaseMismatch,
    SubjectMismatch,
    WorkflowMismatch,
    RefMismatch,
    CommitMismatch,
    RunnerNotHosted,
    StatementInvalid,
    TrustRootInvalid,
}

impl SubReason {
    pub const ALL: [Self; 26] = [
        Self::BundleTooLarge,
        Self::TooManyBundles,
        Self::BundleMalformed,
        Self::BundleUnsupported,
        Self::SignatureInvalid,
        Self::ArtifactDigestMismatch,
        Self::CertificateUntrusted,
        Self::CertificateTime,
        Self::SctInvalid,
        Self::TlogInclusion,
        Self::TlogCheckpoint,
        Self::TlogPromise,
        Self::TlogEntry,
        Self::TimestampInvalid,
        Self::NoVerifiedTime,
        Self::IdentityMismatch,
        Self::RepositoryIdMismatch,
        Self::OwnerIdMismatch,
        Self::ReleaseMismatch,
        Self::SubjectMismatch,
        Self::WorkflowMismatch,
        Self::RefMismatch,
        Self::CommitMismatch,
        Self::RunnerNotHosted,
        Self::StatementInvalid,
        Self::TrustRootInvalid,
    ];

    /// The wire name of the sub-reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BundleTooLarge => "bundle_too_large",
            Self::TooManyBundles => "too_many_bundles",
            Self::BundleMalformed => "bundle_malformed",
            Self::BundleUnsupported => "bundle_unsupported",
            Self::SignatureInvalid => "signature_invalid",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::CertificateUntrusted => "certificate_untrusted",
            Self::CertificateTime => "certificate_time",
            Self::SctInvalid => "sct_invalid",
            Self::TlogInclusion => "tlog_inclusion",
            Self::TlogCheckpoint => "tlog_checkpoint",
            Self::TlogPromise => "tlog_promise",
            Self::TlogEntry => "tlog_entry",
            Self::TimestampInvalid => "timestamp_invalid",
            Self::NoVerifiedTime => "no_verified_time",
            Self::IdentityMismatch => "identity_mismatch",
            Self::RepositoryIdMismatch => "repository_id_mismatch",
            Self::OwnerIdMismatch => "owner_id_mismatch",
            Self::ReleaseMismatch => "release_mismatch",
            Self::SubjectMismatch => "subject_mismatch",
            Self::WorkflowMismatch => "workflow_mismatch",
            Self::RefMismatch => "ref_mismatch",
            Self::CommitMismatch => "commit_mismatch",
            Self::RunnerNotHosted => "runner_not_hosted",
            Self::StatementInvalid => "statement_invalid",
            Self::TrustRootInvalid => "trust_root_invalid",
        }
    }
}

impl fmt::Display for SubReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Evidence that should be there and is not (`E_EVIDENCE_DOWNGRADE`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MissingEvidence {
    /// No attestation bundle at all.
    NoBundle,
    /// Strict: no release attestation among the bundles.
    NoReleaseAttestation,
    /// Strict: the release is not immutable (or the API did not say so).
    NotImmutable,
    /// Attested: no SLSA provenance among the bundles.
    NoProvenance,
}

impl MissingEvidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoBundle => "no attestation bundle",
            Self::NoReleaseAttestation => "no release attestation",
            Self::NotImmutable => "the release is not immutable",
            Self::NoProvenance => "no SLSA provenance",
        }
    }
}

/// Why verification did not accept the evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestationFailure {
    Invalid {
        sub_reason: SubReason,
        detail: String,
    },
    Missing(MissingEvidence),
}

impl AttestationFailure {
    pub(super) fn invalid(sub_reason: SubReason, detail: impl Into<String>) -> Self {
        Self::Invalid {
            sub_reason,
            detail: detail.into(),
        }
    }

    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Invalid { .. } => ReasonCode::EAttestationInvalid,
            Self::Missing(_) => ReasonCode::EEvidenceDowngrade,
        }
    }

    /// The reason event for `object` (ADR-031). The message is fixed text
    /// per sub-reason; the verifier's detail, which may quote certificate or
    /// bundle values from the network, never enters it.
    pub fn reason(&self, object: ObjectReference) -> Result<Reason, SafeValueError> {
        match self {
            Self::Invalid { sub_reason, .. } => Ok(Reason::attestation_invalid(
                object,
                SafeText::new(format!(
                    "attestation rejected: {}",
                    sub_reason.as_str().replace('_', " ")
                ))?,
                ReasonSubcode::new(sub_reason.as_str())?,
            )),
            Self::Missing(missing) => Ok(Reason::new(
                ReasonCode::EEvidenceDowngrade,
                object,
                SafeText::new(missing.as_str())?,
            )),
        }
    }

    /// The sub-reason of an invalid attestation; `None` for missing
    /// evidence.
    pub const fn sub_reason(&self) -> Option<SubReason> {
        match self {
            Self::Invalid { sub_reason, .. } => Some(*sub_reason),
            Self::Missing(_) => None,
        }
    }
}

impl fmt::Display for AttestationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { sub_reason, detail } => write!(formatter, "{sub_reason}: {detail}"),
            Self::Missing(missing) => formatter.write_str(missing.as_str()),
        }
    }
}

impl std::error::Error for AttestationFailure {}

/// Maps a library failure onto a sub-reason. The categories are matched by
/// type, never by message text.
pub(super) fn from_library(error: &sigstore_verify::Error) -> SubReason {
    use sigstore_verify::{CertificateError, Error, TimestampError, TransparencyLogError};
    match error {
        Error::IdentityMismatch { .. } | Error::IssuerMismatch { .. } => {
            SubReason::IdentityMismatch
        }
        Error::SignatureInvalid(_) => SubReason::SignatureInvalid,
        Error::ArtifactMismatch(_) => SubReason::ArtifactDigestMismatch,
        Error::Certificate(certificate) => match certificate {
            CertificateError::NoValidAuthority { .. }
            | CertificateError::NotYetValid { .. }
            | CertificateError::Expired { .. } => SubReason::CertificateTime,
            CertificateError::Sct(_) => SubReason::SctInvalid,
            _ => SubReason::CertificateUntrusted,
        },
        Error::TransparencyLog(log) => match log {
            TransparencyLogError::InclusionProof(_) => SubReason::TlogInclusion,
            TransparencyLogError::Checkpoint(_) => SubReason::TlogCheckpoint,
            TransparencyLogError::InclusionPromise(_) | TransparencyLogError::IntegratedTime(_) => {
                SubReason::TlogPromise
            }
            _ => SubReason::TlogEntry,
        },
        Error::Timestamp(timestamp) => match timestamp {
            TimestampError::NoVerifiedTimestamp(_) => SubReason::NoVerifiedTime,
            _ => SubReason::TimestampInvalid,
        },
        Error::InvalidTrustRoot(_) | Error::TrustRoot(_) | Error::TrustedCertificate(_) => {
            SubReason::TrustRootInvalid
        }
        Error::InvalidBundle(_) | Error::UnsupportedBundle(_) | Error::Bundle(_) => {
            SubReason::BundleUnsupported
        }
        // Malformed key material, an unsupported artifact form, and any
        // category a future library version adds: refused as a bundle the
        // verifier cannot accept.
        _ => SubReason::BundleMalformed,
    }
}
