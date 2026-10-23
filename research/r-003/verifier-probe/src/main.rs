// SPDX-License-Identifier: MIT OR Apache-2.0
//! P1-003c probe: verify GitHub attestation bundles offline with
//! `sigstore-verify` and apply the Pakomichi Strict/Attested policy.
//!
//! Usage:
//!   pakomichi-r003-verifier-probe --mode strict|attested --root FILE --bundle FILE
//!       (--artifact PATH | --sha256 HEX) [--expect key=value]... [--no-provider]
//!
//! Prints one TSV line `verdict reason notes detail` on stdout and one line
//! per candidate bundle on stderr. Exit code: 0 PASS, 1 INVALID, 2 DOWNGRADE
//! (evidence missing), 3 usage or internal error.

mod ring_provider;

use std::collections::BTreeMap;
use std::process::ExitCode;

use serde_json::Value;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, MediaType, Sha256Hash, SignatureContent};
use sigstore_verify::{
    CertificateError, Error as VerifyError, IdentityMatcher, TimestampError, TransparencyLogError,
    VerificationPolicy, VerificationResult, Verifier,
};

/// Proposed pre-checks (findings §Policy layer).
const MAX_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_BUNDLES: usize = 16;
const MAX_FILE_BYTES: usize = MAX_BUNDLES * (MAX_BUNDLE_BYTES + 1);

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const RELEASE_SAN: &str = "https://dotcom.releases.github.com";
const IN_TOTO_PAYLOAD: &str = "application/vnd.in-toto+json";
const STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
const RELEASE_PREDICATE: &str = "https://in-toto.io/attestation/release/v0.2";
const SLSA_PREDICATE: &str = "https://slsa.dev/provenance/v1";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Strict,
    Attested,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Invalid,
    Downgrade,
}

/// A Pakomichi sub-reason under `E_ATTESTATION_INVALID` (or, for missing
/// evidence, `E_EVIDENCE_DOWNGRADE`).
struct Failure {
    verdict: Verdict,
    reason: &'static str,
    detail: String,
}

fn invalid(reason: &'static str, detail: impl Into<String>) -> Failure {
    Failure {
        verdict: Verdict::Invalid,
        reason,
        detail: detail.into(),
    }
}

fn downgrade(reason: &'static str, detail: impl Into<String>) -> Failure {
    Failure {
        verdict: Verdict::Downgrade,
        reason,
        detail: detail.into(),
    }
}

struct Args {
    mode: Mode,
    root: String,
    bundle: String,
    artifact: Option<String>,
    sha256: Option<String>,
    expect: BTreeMap<String, String>,
    no_provider: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut mode = None;
    let (mut root, mut bundle, mut artifact, mut sha256) = (None, None, None, None);
    let mut expect = BTreeMap::new();
    let mut no_provider = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--mode" => {
                mode = Some(match value()?.as_str() {
                    "strict" => Mode::Strict,
                    "attested" => Mode::Attested,
                    other => return Err(format!("unknown mode {other}")),
                })
            }
            "--root" => root = Some(value()?),
            "--bundle" => bundle = Some(value()?),
            "--artifact" => artifact = Some(value()?),
            "--sha256" => sha256 = Some(value()?),
            "--expect" => {
                let pair = value()?;
                let (key, val) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("--expect {pair}: need key=value"))?;
                expect.insert(key.to_string(), val.to_string());
            }
            "--no-provider" => no_provider = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if artifact.is_some() == sha256.is_some() {
        return Err("give exactly one of --artifact and --sha256".into());
    }
    Ok(Args {
        mode: mode.ok_or("--mode is required")?,
        root: root.ok_or("--root is required")?,
        bundle: bundle.ok_or("--bundle is required")?,
        artifact,
        sha256,
        expect,
        no_provider,
    })
}

fn required<'a>(expect: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    expect
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("--expect {key}=... is required"))
}

fn read_limited(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut data = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("{path}: {e}"))?;
    Ok(data)
}

/// The artifact as the verifier sees it, plus its SHA-256 for our own checks.
enum Input {
    Blob(Vec<u8>),
    Digest(Sha256Hash),
}

impl Input {
    fn sha256_hex(&self) -> String {
        match self {
            Input::Blob(bytes) => hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref()),
            Input::Digest(hash) => hash.to_hex(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One candidate bundle with the statement decoded from the same envelope
/// that is verified.
struct Candidate {
    bundle: Bundle,
    statement: Value,
}

fn decode_candidate(line: &str) -> Result<Candidate, Failure> {
    if line.len() > MAX_BUNDLE_BYTES {
        return Err(invalid("BundleTooLarge", format!("{} bytes", line.len())));
    }
    let bundle = Bundle::from_json(line).map_err(|e| invalid("BundleMalformed", e.to_string()))?;
    if bundle.media_type != MediaType::Bundle0_3 {
        return Err(invalid(
            "UnsupportedBundleVersion",
            bundle.media_type.as_str(),
        ));
    }
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(invalid("UnsupportedContent", "not a DSSE envelope"));
    };
    if envelope.payload_type != IN_TOTO_PAYLOAD {
        return Err(invalid(
            "UnsupportedContent",
            format!("payloadType {}", envelope.payload_type),
        ));
    }
    let statement: Value = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|e| invalid("StatementMalformed", e.to_string()))?;
    Ok(Candidate { bundle, statement })
}

fn predicate_type(statement: &Value) -> &str {
    statement
        .get("predicateType")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn map_verify_error(error: VerifyError) -> Failure {
    let detail = error.to_string();
    let reason = match &error {
        VerifyError::IdentityMismatch { .. } => "CertificateIdentityMismatch",
        VerifyError::IssuerMismatch { .. } => "IssuerMismatch",
        VerifyError::SignatureInvalid(_) => "SignatureInvalid",
        VerifyError::ArtifactMismatch(_) => "ArtifactDigestMismatch",
        VerifyError::UnsupportedArtifact(_) => "UnsupportedArtifact",
        VerifyError::Certificate(e) => match e {
            CertificateError::Malformed(_) => "CertificateMalformed",
            CertificateError::ChainInvalid(_) => "UntrustedCertificateChain",
            CertificateError::NoValidAuthority { .. } => "NoValidAuthority",
            CertificateError::NotYetValid { .. } | CertificateError::Expired { .. } => {
                "CertificateOutsideValidity"
            }
            CertificateError::Sct(_) => "SctInvalid",
            _ => "CertificateOther",
        },
        VerifyError::TransparencyLog(e) => match e {
            TransparencyLogError::UnknownLog { .. } => "TlogUnknownLog",
            TransparencyLogError::InclusionProof(_) => "TlogInclusionProof",
            TransparencyLogError::Checkpoint(_) => "TlogCheckpoint",
            TransparencyLogError::InclusionPromise(_) => "TlogInclusionPromise",
            TransparencyLogError::EntryMismatch(_) => "TlogEntryMismatch",
            TransparencyLogError::IntegratedTime(_) => "TlogIntegratedTime",
            TransparencyLogError::MalformedEntry(_) => "TlogEntryMalformed",
            _ => "TlogOther",
        },
        VerifyError::Timestamp(e) => match e {
            TimestampError::Invalid(_) => "TimestampInvalid",
            TimestampError::OutsideAuthorityValidity { .. } => "TimestampOutsideAuthority",
            TimestampError::NoVerifiedTimestamp(_) => "NoVerifiedTime",
            _ => "TimestampOther",
        },
        VerifyError::InvalidBundle(_)
        | VerifyError::UnsupportedBundle(_)
        | VerifyError::Bundle(_) => "BundleInvalid",
        VerifyError::InvalidTrustRoot(_)
        | VerifyError::TrustRoot(_)
        | VerifyError::TrustedCertificate(_) => "TrustRootInvalid",
        VerifyError::Types(_) | VerifyError::Crypto(_) => "CryptoError",
        VerifyError::ArtifactRead(_) => "ArtifactRead",
        _ => "VerifierOther",
    };
    invalid(reason, detail)
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(value, |v, key| v.get(*key))?.as_str()
}

fn check_eq(reason: &'static str, actual: Option<&str>, expected: &str) -> Result<(), Failure> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(invalid(
            reason,
            format!("expected {expected}, got {}", actual.unwrap_or("none")),
        ))
    }
}

/// Strict: GitHub release attestation. Binding lives only in the signed
/// predicate, because every github.com release certificate has the same SAN.
fn strict_policy(
    statement: &Value,
    expect: &BTreeMap<String, String>,
    artifact_sha256: &str,
    notes: &mut Vec<String>,
) -> Result<(), Failure> {
    let usage = |e: String| invalid("Usage", e);
    let repo_id = required(expect, "repo-id").map_err(usage)?;
    let owner_id = required(expect, "owner-id").map_err(usage)?;
    let release_id = required(expect, "release-id").map_err(usage)?;
    let tag = required(expect, "tag").map_err(usage)?;
    let commit = required(expect, "commit").map_err(usage)?;
    let asset = required(expect, "asset-name").map_err(usage)?;
    let predicate = statement.get("predicate").unwrap_or(&Value::Null);
    let field = |name: &str| predicate.get(name).and_then(Value::as_str);
    check_eq("RepositoryIdMismatch", field("repositoryId"), repo_id)?;
    check_eq("PackageIdMismatch", field("packageId"), repo_id)?;
    check_eq("OwnerIdMismatch", field("ownerId"), owner_id)?;
    check_eq("ReleaseIdMismatch", field("databaseId"), release_id)?;
    check_eq("TagMismatch", field("tag"), tag)?;
    let subjects = statement
        .get("subject")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let commit_subject = subjects.iter().find(|s| {
        s.get("uri")
            .and_then(Value::as_str)
            .is_some_and(|u| u.starts_with("pkg:github/"))
    });
    check_eq(
        "CommitSubjectMismatch",
        commit_subject.and_then(|s| str_at(s, &["digest", "sha1"])),
        commit,
    )?;
    let named = subjects
        .iter()
        .find(|s| s.get("name").and_then(Value::as_str) == Some(asset));
    let named_digest = named.and_then(|s| str_at(s, &["digest", "sha256"]));
    if named_digest != Some(artifact_sha256) {
        return Err(invalid(
            "SubjectNameMismatch",
            format!("no subject named {asset} with sha256 {artifact_sha256}"),
        ));
    }
    if let Some(name) = expect.get("repo-name")
        && field("repository") != Some(name.as_str())
    {
        notes.push(format!(
            "name_changed:{}",
            field("repository").unwrap_or("none")
        ));
    }
    Ok(())
}

/// Attested: SLSA provenance from public-good Sigstore. Binding uses the
/// immutable Fulcio claims `.1.15`/`.1.17`, never the repository name.
fn attested_policy(
    result: &VerificationResult,
    expect: &BTreeMap<String, String>,
    notes: &mut Vec<String>,
) -> Result<(), Failure> {
    let usage = |e: String| invalid("Usage", e);
    let repo_id = required(expect, "repo-id").map_err(usage)?;
    let owner_id = required(expect, "owner-id").map_err(usage)?;
    let workflow = required(expect, "workflow").map_err(usage)?;
    let git_ref = required(expect, "ref").map_err(usage)?;
    let commit = required(expect, "commit").map_err(usage)?;
    let claims = &result
        .certificate()
        .ok_or_else(|| invalid("CertificateMalformed", "no certificate in result"))?
        .ci_claims;
    check_eq(
        "RepositoryIdMismatch",
        claims.source_repository_identifier.as_deref(),
        repo_id,
    )?;
    check_eq(
        "OwnerIdMismatch",
        claims.source_repository_owner_identifier.as_deref(),
        owner_id,
    )?;
    // build_signer_uri = https://github.com/OWNER/REPO/<workflow path>@<ref>;
    // compare the part after OWNER/REPO exactly (no prefix, regex or case
    // folding), and require the signer to be the source repository itself.
    let signer = claims.build_signer_uri.as_deref().unwrap_or("");
    let source = claims.source_repository_uri.as_deref().unwrap_or("");
    let signer_tail = signer
        .strip_prefix(source)
        .filter(|_| !source.is_empty())
        .and_then(|rest| rest.strip_prefix('/'));
    let Some(signer_tail) = signer_tail else {
        return Err(invalid(
            "WorkflowMismatch",
            format!("signer {signer} is not in {source}"),
        ));
    };
    let (signer_path, signer_ref) = signer_tail.rsplit_once('@').unwrap_or((signer_tail, ""));
    check_eq("WorkflowMismatch", Some(signer_path), workflow)?;
    check_eq(
        "RefMismatch",
        claims.source_repository_ref.as_deref(),
        git_ref,
    )?;
    check_eq("WorkflowRefMismatch", Some(signer_ref), git_ref)?;
    check_eq(
        "CommitMismatch",
        claims.source_repository_digest.as_deref(),
        commit,
    )?;
    check_eq(
        "RunnerNotHosted",
        claims.runner_environment.as_deref(),
        "github-hosted",
    )?;
    if let Some(name) = expect.get("repo-name")
        && source != format!("https://github.com/{name}")
    {
        notes.push(format!("name_changed:{source}"));
    }
    Ok(())
}

fn verify_candidate(
    verifier: &Verifier,
    mode: Mode,
    candidate: &Candidate,
    input: &Input,
    expect: &BTreeMap<String, String>,
    notes: &mut Vec<String>,
) -> Result<(), Failure> {
    // Probe-only override, so a test can provoke IssuerMismatch.
    let issuer = expect
        .get("issuer")
        .map_or(GITHUB_ACTIONS_ISSUER, String::as_str);
    let policy = match mode {
        Mode::Strict => VerificationPolicy::any_identity()
            .require_identity(IdentityMatcher::Uri(RELEASE_SAN.into()))
            .skip_tlog_unsafe()
            .skip_sct(),
        Mode::Attested => VerificationPolicy::any_identity().require_issuer(issuer),
    };
    let outcome = match input {
        Input::Blob(bytes) => verifier.verify(bytes.as_slice(), &candidate.bundle, &policy),
        Input::Digest(hash) => verifier.verify(hash, &candidate.bundle, &policy),
    };
    let result = outcome.map_err(map_verify_error)?;
    if !result.certificate_verified() || result.verified_timestamps().is_empty() {
        return Err(invalid(
            "EvidenceIncomplete",
            "certificate or time not verified",
        ));
    }
    if mode == Mode::Attested && !(result.sct_verified() && result.tlog_verified()) {
        return Err(invalid(
            "EvidenceIncomplete",
            "SCT or transparency log not verified",
        ));
    }
    // The statement is interpreted only after the envelope signature over it
    // has been verified; before that it only routed the candidate.
    if candidate.statement.get("_type").and_then(Value::as_str) != Some(STATEMENT_V1) {
        return Err(invalid(
            "StatementTypeMismatch",
            "not an in-toto Statement v1",
        ));
    }
    notes.push(format!("timestamps:{}", result.verified_timestamps().len()));
    notes.push(format!("tlog:{}", result.tlog_verified()));
    match mode {
        Mode::Strict => strict_policy(&candidate.statement, expect, &input.sha256_hex(), notes),
        Mode::Attested => attested_policy(&result, expect, notes),
    }
}

fn run(args: &Args) -> Result<Vec<String>, Failure> {
    let internal = |e: String| invalid("Usage", e);
    let root_json = String::from_utf8(read_limited(&args.root, 4 * 1024 * 1024).map_err(internal)?)
        .map_err(|e| invalid("TrustRootInvalid", e.to_string()))?;
    let root = TrustedRoot::from_json(&root_json)
        .map_err(|e| invalid("TrustRootInvalid", e.to_string()))?;
    let verifier = Verifier::new(&root).map_err(map_verify_error)?;

    let input = match (&args.artifact, &args.sha256) {
        (Some(path), _) => {
            Input::Blob(std::fs::read(path).map_err(|e| internal(format!("{path}: {e}")))?)
        }
        (_, Some(hex)) => Input::Digest(
            Sha256Hash::from_hex(hex).map_err(|e| internal(format!("--sha256: {e}")))?,
        ),
        _ => return Err(internal("no artifact".into())),
    };

    let raw = read_limited(&args.bundle, MAX_FILE_BYTES).map_err(internal)?;
    if raw.len() > MAX_FILE_BYTES {
        return Err(invalid("TooManyBundles", "bundle file over the size limit"));
    }
    let text = String::from_utf8(raw).map_err(|e| invalid("BundleMalformed", e.to_string()))?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return Err(downgrade("BundleMissing", "no attestation bundles"));
    }
    if lines.len() > MAX_BUNDLES {
        return Err(invalid(
            "TooManyBundles",
            format!("{} bundles", lines.len()),
        ));
    }
    let wanted = match args.mode {
        Mode::Strict => RELEASE_PREDICATE,
        Mode::Attested => SLSA_PREDICATE,
    };

    let mut first_failure = None;
    let mut considered = 0;
    for (index, line) in lines.iter().enumerate() {
        let candidate = match decode_candidate(line) {
            Ok(c) => c,
            Err(failure) => {
                eprintln!("candidate {index}\t{}\t{}", failure.reason, failure.detail);
                first_failure.get_or_insert(failure);
                considered += 1;
                continue;
            }
        };
        if predicate_type(&candidate.statement) != wanted {
            eprintln!(
                "candidate {index}\tskipped\tpredicateType {}",
                predicate_type(&candidate.statement)
            );
            continue;
        }
        considered += 1;
        let mut notes = Vec::new();
        match verify_candidate(
            &verifier,
            args.mode,
            &candidate,
            &input,
            &args.expect,
            &mut notes,
        ) {
            Ok(()) => {
                eprintln!("candidate {index}\tPASS\t{}", notes.join(","));
                return Ok(notes);
            }
            Err(failure) => {
                eprintln!("candidate {index}\t{}\t{}", failure.reason, failure.detail);
                first_failure.get_or_insert(failure);
            }
        }
    }
    Err(first_failure.unwrap_or_else(|| {
        let reason = match args.mode {
            Mode::Strict => "ReleaseAttestationMissing",
            Mode::Attested => "ProvenanceMissing",
        };
        downgrade(
            reason,
            format!(
                "{} bundles, none with predicate {wanted}",
                lines.len() - considered
            ),
        )
    }))
}

fn clean(text: &str) -> String {
    text.replace(['\t', '\n', '\r'], " ")
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            println!("ERROR\tUsage\t-\t{}", clean(&e));
            return ExitCode::from(3);
        }
    };
    // Startup invariant: without an installed provider and without the
    // aws-lc feature, sigstore-crypto panics on first use.
    if !args.no_provider
        && sigstore_crypto::install_default_provider(&ring_provider::RING_PROVIDER).is_err()
    {
        println!("ERROR\tProviderAlreadyInstalled\t-\t-");
        return ExitCode::from(3);
    }
    match run(&args) {
        Ok(notes) => {
            println!("PASS\t-\t{}\t-", clean(&notes.join(",")));
            ExitCode::SUCCESS
        }
        Err(failure) => {
            let (word, code) = match failure.verdict {
                Verdict::Invalid if failure.reason == "Usage" => ("ERROR", 3),
                Verdict::Invalid => ("INVALID", 1),
                Verdict::Downgrade => ("DOWNGRADE", 2),
            };
            println!("{word}\t{}\t-\t{}", failure.reason, clean(&failure.detail));
            ExitCode::from(code)
        }
    }
}
