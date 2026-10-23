// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks on attestation bundles before any cryptography (ADR-030 point 6).

use serde::Deserialize;
use sigstore_types::{Bundle, MediaType, SignatureContent};

use super::reason::{AttestationFailure, MissingEvidence, SubReason};

/// Largest bundle accepted, in bytes.
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024;
/// Most bundles accepted for one digest.
pub const MAX_BUNDLES: usize = 16;

pub(super) const IN_TOTO_PAYLOAD: &str = "application/vnd.in-toto+json";
pub(super) const STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const RELEASE_PREDICATE: &str = "https://in-toto.io/attestation/release/v0.2";
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// The in-toto statement of a bundle. Read before verification only to
/// choose which bundles to try, and interpreted only after the envelope
/// signature over these bytes has been verified. A foreign format: only the
/// used fields, unknown fields tolerated (ADR-019 point 3).
#[derive(Debug, Deserialize)]
pub(super) struct Statement {
    #[serde(rename = "_type")]
    pub kind: String,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub subject: Vec<Subject>,
    #[serde(default)]
    pub predicate: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub(super) struct Subject {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub digest: std::collections::BTreeMap<String, String>,
}

/// A bundle that passed the structural checks, with its statement.
pub(super) struct Candidate {
    pub bundle: Bundle,
    pub statement: Statement,
}

/// Checks the count of a bundle set; an empty set is missing evidence.
pub(super) fn check_count(bundles: &[&[u8]]) -> Result<(), AttestationFailure> {
    if bundles.is_empty() {
        return Err(AttestationFailure::Missing(MissingEvidence::NoBundle));
    }
    if bundles.len() > MAX_BUNDLES {
        return Err(AttestationFailure::invalid(
            SubReason::TooManyBundles,
            format!("{} bundles for one digest", bundles.len()),
        ));
    }
    Ok(())
}

/// Parses one bundle and refuses everything but a v0.3 DSSE bundle with one
/// signature over an in-toto statement.
pub(super) fn decode(bytes: &[u8]) -> Result<Candidate, AttestationFailure> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(AttestationFailure::invalid(
            SubReason::BundleTooLarge,
            format!("{} bytes", bytes.len()),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AttestationFailure::invalid(SubReason::BundleMalformed, "not UTF-8"))?;
    // The library refuses a DSSE envelope without exactly one signature
    // while parsing.
    let bundle = Bundle::from_json(text).map_err(|error| {
        AttestationFailure::invalid(SubReason::BundleMalformed, error.to_string())
    })?;
    if bundle.media_type != MediaType::Bundle0_3 {
        return Err(AttestationFailure::invalid(
            SubReason::BundleUnsupported,
            bundle.media_type.as_str(),
        ));
    }
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(AttestationFailure::invalid(
            SubReason::BundleUnsupported,
            "not a DSSE envelope",
        ));
    };
    if envelope.payload_type != IN_TOTO_PAYLOAD {
        return Err(AttestationFailure::invalid(
            SubReason::BundleUnsupported,
            "payload is not an in-toto statement",
        ));
    }
    let statement: Statement =
        serde_json::from_slice(envelope.payload.as_bytes()).map_err(|_| {
            AttestationFailure::invalid(SubReason::StatementInvalid, "statement does not parse")
        })?;
    Ok(Candidate { bundle, statement })
}
