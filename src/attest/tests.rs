// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixtures: attestations of the owner's public test repository
//! `kroxiksut/pchi-test` (release v0.1.0: release attestation and SLSA
//! provenance) and of its fork `kroxiksut/pchi-test-fork` (v0.3.0-mutable,
//! SLSA only), recorded by R-003 (P1-003b). Verification is offline against
//! the trusted roots shipped with `sigstore-trust-root` 0.15.0.

use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::*;
use crate::cas::Sha256Digest;
use crate::github::{
    AssetId, ExpectedRelease, GitObjectId, OwnerId, OwnerLogin, PinnedRepository, Release,
    ReleaseAsset, ReleaseId, RepositoryId, RepositoryIdentity, RepositoryName,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const V1: &str = include_str!("../../tests/data/attest/pchi-test-v0.1.0.jsonl");
const FORK: &str = include_str!("../../tests/data/attest/pchi-test-fork-v0.3.0.jsonl");

const REPO_ID: u64 = 1_429_109_739;
const USER_OWNER: u64 = 2_264_172;
const ORG_OWNER: u64 = 346_117_935;
const REUSED_NAME_REPO_ID: u64 = 1_429_307_950;
const FORK_ID: u64 = 1_429_309_242;
const RELEASE_ID: u64 = 420_324_447;
const TAG: &str = "v0.1.0";
const COMMIT: &str = "6ee0f9f53e5a296bd19904188d055608f32ffd82";
const ASSET: &str = "pakomichi-r003-fixture_0.1.0_all.deb";
const ASSET_SHA256: &str = "8fcda58d824b4fea8f98e036083f398f497941af4b8c15de5dac02dd900576fd";
const WORKFLOW: &str = ".github/workflows/immutable-release.yml";
const FORK_COMMIT: &str = "31c0b80f18969c5f8b70912bbba18dae9bdeea02";
const FORK_ASSET_SHA256: &str = "d3c6baed8cf8b2cb6eaa57f1b5a0b40ee3ffe8c261d2296cf75cee395f5f51c2";
const FORK_WORKFLOW: &str = ".github/workflows/mutable-attested.yml";

fn verifier() -> Result<AttestationVerifier, Box<dyn std::error::Error>> {
    ensure_crypto_provider()?;
    Ok(AttestationVerifier::new(&TrustedRoots::embedded()?)?)
}

fn lines(text: &str) -> Vec<&[u8]> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::as_bytes)
        .collect()
}

/// Line 0: release attestation; line 1: SLSA provenance.
fn v1_line(index: usize) -> Result<Value, Box<dyn std::error::Error>> {
    let line = V1.lines().nth(index).ok_or("fixture line missing")?;
    Ok(serde_json::from_str(line)?)
}

fn pin(
    repository_id: u64,
    owner_id: u64,
    earlier: &[u64],
    owner: &str,
    name: &str,
) -> Result<PinnedRepository, Box<dyn std::error::Error>> {
    let identity = RepositoryIdentity::new(
        RepositoryId::new(repository_id)?,
        OwnerId::new(owner_id)?,
        OwnerLogin::new(owner)?,
        RepositoryName::new(name)?,
    );
    let earlier = earlier
        .iter()
        .map(|id| OwnerId::new(*id))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PinnedRepository::restore(identity, earlier))
}

fn original() -> Result<PinnedRepository, Box<dyn std::error::Error>> {
    pin(REPO_ID, USER_OWNER, &[], "kroxiksut", "pchi-test")
}

fn digest(hex: &str) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
    Ok(Sha256Digest::from_hex(hex).map_err(|_| "bad digest")?)
}

fn release(
    id: u64,
    tag: &str,
    asset: &str,
    sha256: &str,
) -> Result<Release, Box<dyn std::error::Error>> {
    Ok(Release {
        id: ReleaseId::new(id)?,
        tag: tag.to_owned(),
        target_commitish: "main".to_owned(),
        draft: false,
        prerelease: false,
        immutable: Some(true),
        published_at: Some("2026-10-22T05:00:23Z".to_owned()),
        assets: vec![ReleaseAsset {
            id: AssetId::new(664_728_438)?,
            name: asset.to_owned(),
            size: 1,
            api_digest: Some(digest(sha256)?),
            uploaded: true,
            download_url: "https://github.com/kroxiksut/pchi-test/releases/download/v0.1.0/x"
                .to_owned(),
        }],
    })
}

struct Strict {
    repository: PinnedRepository,
    release_id: u64,
    tag: &'static str,
    commit: &'static str,
    asset: &'static str,
    sha256: &'static str,
}

impl Strict {
    fn v1() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            repository: original()?,
            release_id: RELEASE_ID,
            tag: TAG,
            commit: COMMIT,
            asset: ASSET,
            sha256: ASSET_SHA256,
        })
    }

    fn expected(&self) -> Result<ExpectedRelease, Box<dyn std::error::Error>> {
        let release = release(self.release_id, self.tag, self.asset, self.sha256)?;
        Ok(ExpectedRelease::new(
            &self.repository,
            &release,
            GitObjectId::from_hex(self.commit).map_err(|_| "bad commit")?,
            self.asset,
            digest(self.sha256)?,
        ))
    }

    fn verify(
        &self,
        bundles: &[&[u8]],
    ) -> Result<Result<StrictEvidence, AttestationFailure>, Box<dyn std::error::Error>> {
        Ok(verifier()?.verify_strict(bundles, &self.expected()?, Some(true)))
    }
}

fn provenance(
    repository: &PinnedRepository,
    workflow: &str,
    source_ref: SourceRef,
    commit: &str,
    sha256: &str,
) -> Result<ExpectedProvenance, Box<dyn std::error::Error>> {
    Ok(ExpectedProvenance::new(
        repository,
        workflow,
        source_ref,
        GitObjectId::from_hex(commit).map_err(|_| "bad commit")?,
        digest(sha256)?,
    )
    .map_err(|_| "bad workflow")?)
}

fn v1_provenance(
    repository: &PinnedRepository,
) -> Result<ExpectedProvenance, Box<dyn std::error::Error>> {
    provenance(
        repository,
        WORKFLOW,
        SourceRef::Branch("main".into()),
        COMMIT,
        ASSET_SHA256,
    )
}

fn sub_reason<T: std::fmt::Debug>(result: Result<T, AttestationFailure>) -> Option<SubReason> {
    match result {
        Err(failure) => {
            assert_eq!(
                failure.reason_code(),
                crate::error::ReasonCode::EAttestationInvalid,
                "{failure}"
            );
            failure.sub_reason()
        }
        Ok(evidence) => panic!("accepted: {evidence:?}"),
    }
}

fn missing<T: std::fmt::Debug>(result: Result<T, AttestationFailure>) -> Option<MissingEvidence> {
    match result {
        Err(AttestationFailure::Missing(missing)) => Some(missing),
        other => panic!("expected missing evidence, got {other:?}"),
    }
}

fn encode(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

// ------------------------------------------------------------------ Strict

#[test]
fn strict_accepts_the_pinned_release() -> TestResult {
    let evidence = Strict::v1()?.verify(&lines(V1))??;
    assert_eq!(evidence.owner_id, USER_OWNER);
    assert!(evidence.signed_at > 1_790_000_000);
    Ok(())
}

#[test]
fn strict_requires_an_immutable_release_and_a_release_attestation() -> TestResult {
    let strict = Strict::v1()?;
    let verifier = verifier()?;
    // The flag alone is not evidence, and evidence without the flag is not Strict.
    assert_eq!(
        missing(verifier.verify_strict(&[], &strict.expected()?, Some(true))),
        Some(MissingEvidence::NoBundle)
    );
    for flag in [None, Some(false)] {
        assert_eq!(
            missing(verifier.verify_strict(&lines(V1), &strict.expected()?, flag)),
            Some(MissingEvidence::NotImmutable)
        );
    }
    let slsa_only = encode(&v1_line(1)?)?;
    assert_eq!(
        missing(verifier.verify_strict(&[&slsa_only], &strict.expected()?, Some(true))),
        Some(MissingEvidence::NoReleaseAttestation)
    );
    Ok(())
}

#[test]
fn strict_binds_ids_release_tag_commit_and_asset() -> TestResult {
    let bundles = lines(V1);
    let cases: [(Strict, SubReason); 6] = [
        // A new repository that took the old name (R-003 U1).
        (
            Strict {
                repository: pin(
                    REUSED_NAME_REPO_ID,
                    USER_OWNER,
                    &[],
                    "kroxiksut",
                    "pchi-test",
                )?,
                ..Strict::v1()?
            },
            SubReason::RepositoryIdMismatch,
        ),
        // After a transfer, before the new owner is confirmed (T1).
        (
            Strict {
                repository: pin(
                    REPO_ID,
                    ORG_OWNER,
                    &[],
                    "pchi-test-org",
                    "pchi-test-renamed",
                )?,
                ..Strict::v1()?
            },
            SubReason::OwnerIdMismatch,
        ),
        (
            Strict {
                release_id: RELEASE_ID + 1,
                ..Strict::v1()?
            },
            SubReason::ReleaseMismatch,
        ),
        (
            Strict {
                tag: "v0.2.0",
                ..Strict::v1()?
            },
            SubReason::ReleaseMismatch,
        ),
        (
            Strict {
                commit: "0000000000000000000000000000000000000000",
                ..Strict::v1()?
            },
            SubReason::ReleaseMismatch,
        ),
        (
            Strict {
                asset: "other_0.1.0_all.deb",
                ..Strict::v1()?
            },
            SubReason::SubjectMismatch,
        ),
    ];
    for (strict, expected) in cases {
        assert_eq!(sub_reason(strict.verify(&bundles)?), Some(expected));
    }
    // Changed bytes: the digest is no subject of the signed statement.
    let changed = Strict {
        sha256: "0000000000000000000000000000000000000000000000000000000000000001",
        ..Strict::v1()?
    };
    assert_eq!(
        sub_reason(changed.verify(&bundles)?),
        Some(SubReason::ArtifactDigestMismatch)
    );
    Ok(())
}

#[test]
fn strict_follows_a_rename_and_a_confirmed_transfer() -> TestResult {
    let bundles = lines(V1);
    // Rename: same IDs, new name; names never bind.
    let renamed = Strict {
        repository: pin(REPO_ID, USER_OWNER, &[], "kroxiksut", "pchi-test-renamed")?,
        ..Strict::v1()?
    };
    assert!(renamed.verify(&bundles)?.is_ok());
    // Transfer confirmed: the organization is current and the earlier
    // owner stays accepted for attestations made before (T3).
    let transferred = Strict {
        repository: pin(
            REPO_ID,
            ORG_OWNER,
            &[USER_OWNER],
            "pchi-test-org",
            "pchi-test-renamed",
        )?,
        ..Strict::v1()?
    };
    assert_eq!(transferred.verify(&bundles)??.owner_id, USER_OWNER);
    Ok(())
}

#[test]
fn a_release_attestation_does_not_verify_under_the_public_good_root() -> TestResult {
    ensure_crypto_provider()?;
    let public_good =
        sigstore_trust_root::SigstoreInstance::PublicGood.embedded_trusted_root_json();
    let swapped = AttestationVerifier::new(&TrustedRoots::from_json(public_good, public_good)?)?;
    let result = swapped.verify_strict(&lines(V1), &Strict::v1()?.expected()?, Some(true));
    assert!(
        matches!(result, Err(AttestationFailure::Invalid { .. })),
        "{result:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------- Attested

#[test]
fn attested_accepts_the_pinned_workflow() -> TestResult {
    let repository = original()?;
    let evidence = verifier()?.verify_attested(&lines(V1), &v1_provenance(&repository)?)?;
    assert_eq!(evidence.owner_id, USER_OWNER);
    assert_eq!(
        evidence.signer,
        "https://github.com/kroxiksut/pchi-test/.github/workflows/immutable-release.yml@refs/heads/main"
    );
    assert_eq!(
        evidence.source_repository,
        "https://github.com/kroxiksut/pchi-test"
    );
    Ok(())
}

#[test]
fn attested_accepts_the_fork_only_under_its_own_pin() -> TestResult {
    let verifier = verifier()?;
    let fork = pin(FORK_ID, USER_OWNER, &[], "kroxiksut", "pchi-test-fork")?;
    let expected = provenance(
        &fork,
        FORK_WORKFLOW,
        SourceRef::Branch("main".into()),
        FORK_COMMIT,
        FORK_ASSET_SHA256,
    )?;
    assert!(verifier.verify_attested(&lines(FORK), &expected).is_ok());
    // The same owner ID does not make a fork the original (R-003 F1).
    let as_original = provenance(
        &original()?,
        FORK_WORKFLOW,
        SourceRef::Branch("main".into()),
        FORK_COMMIT,
        FORK_ASSET_SHA256,
    )?;
    assert_eq!(
        sub_reason(verifier.verify_attested(&lines(FORK), &as_original)),
        Some(SubReason::RepositoryIdMismatch)
    );
    Ok(())
}

#[test]
fn attested_binds_owner_workflow_ref_and_commit_exactly() -> TestResult {
    let verifier = verifier()?;
    let bundles = lines(V1);
    let repository = original()?;
    let branch = || SourceRef::Branch("main".into());
    let cases = [
        (
            provenance(
                &pin(
                    REPO_ID,
                    ORG_OWNER,
                    &[],
                    "pchi-test-org",
                    "pchi-test-renamed",
                )?,
                WORKFLOW,
                branch(),
                COMMIT,
                ASSET_SHA256,
            )?,
            SubReason::OwnerIdMismatch,
        ),
        (
            provenance(
                &repository,
                ".github/workflows/other.yml",
                branch(),
                COMMIT,
                ASSET_SHA256,
            )?,
            SubReason::WorkflowMismatch,
        ),
        // A prefix or a pattern is not the workflow.
        (
            provenance(
                &repository,
                ".github/workflows/immutable-release.yaml",
                branch(),
                COMMIT,
                ASSET_SHA256,
            )?,
            SubReason::WorkflowMismatch,
        ),
        (
            provenance(
                &repository,
                ".github/workflows/Immutable-release.yml",
                branch(),
                COMMIT,
                ASSET_SHA256,
            )?,
            SubReason::WorkflowMismatch,
        ),
        (
            provenance(
                &repository,
                WORKFLOW,
                SourceRef::ReleaseTag(TAG.into()),
                COMMIT,
                ASSET_SHA256,
            )?,
            SubReason::RefMismatch,
        ),
        (
            provenance(
                &repository,
                WORKFLOW,
                SourceRef::Branch("Main".into()),
                COMMIT,
                ASSET_SHA256,
            )?,
            SubReason::RefMismatch,
        ),
        (
            provenance(&repository, WORKFLOW, branch(), FORK_COMMIT, ASSET_SHA256)?,
            SubReason::CommitMismatch,
        ),
        (
            provenance(
                &repository,
                WORKFLOW,
                branch(),
                COMMIT,
                "0000000000000000000000000000000000000000000000000000000000000001",
            )?,
            SubReason::ArtifactDigestMismatch,
        ),
    ];
    for (expected, reason) in cases {
        assert_eq!(
            sub_reason(verifier.verify_attested(&bundles, &expected)),
            Some(reason)
        );
    }
    // Renamed and transferred-and-confirmed pins still verify.
    for repository in [
        pin(REPO_ID, USER_OWNER, &[], "kroxiksut", "pchi-test-renamed")?,
        pin(
            REPO_ID,
            ORG_OWNER,
            &[USER_OWNER],
            "pchi-test-org",
            "pchi-test-renamed",
        )?,
    ] {
        assert!(
            verifier
                .verify_attested(&bundles, &v1_provenance(&repository)?)
                .is_ok()
        );
    }
    Ok(())
}

#[test]
fn attested_refuses_release_only_sets_and_the_github_root() -> TestResult {
    let verifier = verifier()?;
    let expected = v1_provenance(&original()?)?;
    let release_only = encode(&v1_line(0)?)?;
    assert_eq!(
        missing(verifier.verify_attested(&[&release_only], &expected)),
        Some(MissingEvidence::NoProvenance)
    );
    let github = sigstore_trust_root::SigstoreInstance::GitHub.embedded_trusted_root_json();
    let swapped = AttestationVerifier::new(&TrustedRoots::from_json(github, github)?)?;
    assert!(matches!(
        swapped.verify_attested(&lines(V1), &expected),
        Err(AttestationFailure::Invalid { .. })
    ));
    Ok(())
}

#[test]
fn workflow_paths_must_be_workflow_files() -> TestResult {
    let repository = original()?;
    let commit = GitObjectId::from_hex(COMMIT).map_err(|_| "bad commit")?;
    let sha = digest(ASSET_SHA256)?;
    for bad in [
        "release.yml",
        ".github/workflows/",
        ".github/workflows/../x.yml",
        ".github/workflows/a/b.yml",
        ".github/workflows/release",
        ".github/workflows/.hidden.yml",
        "/.github/workflows/release.yml",
    ] {
        assert!(
            ExpectedProvenance::new(
                &repository,
                bad,
                SourceRef::Branch("main".into()),
                commit,
                sha
            )
            .is_err(),
            "{bad}"
        );
    }
    Ok(())
}

// --------------------------------------------------------- tampered bundles

fn tampered(
    change: impl Fn(&mut Value) -> Option<()>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bundle = v1_line(1)?;
    change(&mut bundle).ok_or("fixture field missing")?;
    Ok(encode(&bundle)?)
}

fn flip_base64(value: &mut Value) -> Option<()> {
    let mut bytes = STANDARD.decode(value.as_str()?).ok()?;
    *bytes.last_mut()? ^= 1;
    *value = Value::String(STANDARD.encode(bytes));
    Some(())
}

fn tlog(bundle: &mut Value) -> Option<&mut Value> {
    bundle.pointer_mut("/verificationMaterial/tlogEntries/0")
}

#[test]
fn tampered_attestations_are_refused_with_distinct_reasons() -> TestResult {
    let verifier = verifier()?;
    let expected = v1_provenance(&original()?)?;
    let forged_payload = tampered(|bundle| {
        let payload = bundle.pointer_mut("/dsseEnvelope/payload")?;
        let mut statement: Value =
            serde_json::from_slice(&STANDARD.decode(payload.as_str()?).ok()?).ok()?;
        *statement.pointer_mut("/predicate/buildDefinition/externalParameters/workflow/ref")? =
            Value::String("refs/heads/other".into());
        *payload = Value::String(STANDARD.encode(serde_json::to_vec(&statement).ok()?));
        Some(())
    })?;
    let cases = [
        (forged_payload, SubReason::SignatureInvalid),
        (
            tampered(|bundle| flip_base64(tlog(bundle)?.pointer_mut("/inclusionProof/hashes/0")?))?,
            SubReason::TlogInclusion,
        ),
        (
            tampered(|bundle| {
                let envelope = tlog(bundle)?.pointer_mut("/inclusionProof/checkpoint/envelope")?;
                let text = envelope.as_str()?.trim_end_matches('\n').to_owned();
                let (body, signature) = text.rsplit_once(' ')?;
                let mut signature = Value::String(signature.to_owned());
                flip_base64(&mut signature)?;
                *envelope = Value::String(format!("{body} {}\n", signature.as_str()?));
                Some(())
            })?,
            SubReason::TlogCheckpoint,
        ),
        (
            tampered(|bundle| {
                let time = tlog(bundle)?.get_mut("integratedTime")?;
                let moved = time.as_str()?.parse::<i64>().ok()? - 3600;
                *time = Value::String(moved.to_string());
                Some(())
            })?,
            SubReason::TlogPromise,
        ),
        (
            tampered(|bundle| {
                let signatures = bundle
                    .pointer_mut("/dsseEnvelope/signatures")?
                    .as_array_mut()?;
                let first = signatures.first()?.clone();
                signatures.push(first);
                Some(())
            })?,
            SubReason::BundleMalformed,
        ),
        (
            tampered(|bundle| {
                *bundle.pointer_mut("/dsseEnvelope/payloadType")? =
                    Value::String("text/plain".into());
                Some(())
            })?,
            SubReason::BundleUnsupported,
        ),
        (
            tampered(|bundle| {
                *bundle.get_mut("mediaType")? =
                    Value::String("application/vnd.dev.sigstore.bundle+json;version=0.1".into());
                Some(())
            })?,
            SubReason::BundleUnsupported,
        ),
        (
            tampered(|bundle| {
                bundle.as_object_mut()?.insert(
                    "padding".into(),
                    Value::String("x".repeat(MAX_BUNDLE_BYTES)),
                );
                Some(())
            })?,
            SubReason::BundleTooLarge,
        ),
        (b"not json".to_vec(), SubReason::BundleMalformed),
    ];
    for (bundle, reason) in cases {
        assert_eq!(
            sub_reason(verifier.verify_attested(&[&bundle], &expected)),
            Some(reason)
        );
    }
    let original = encode(&v1_line(1)?)?;
    let too_many: Vec<&[u8]> = (0..=MAX_BUNDLES).map(|_| original.as_slice()).collect();
    assert_eq!(
        sub_reason(verifier.verify_attested(&too_many, &expected)),
        Some(SubReason::TooManyBundles)
    );
    Ok(())
}

#[test]
fn a_valid_bundle_wins_over_a_broken_one_in_the_same_set() -> TestResult {
    let verifier = verifier()?;
    let expected = v1_provenance(&original()?)?;
    let valid = encode(&v1_line(1)?)?;
    assert!(
        verifier
            .verify_attested(&[b"not json", &valid], &expected)
            .is_ok()
    );
    Ok(())
}

// ------------------------------------------------------------ the contract

#[test]
fn sub_reasons_are_the_adr_030_names() {
    let names: HashSet<&str> = SubReason::ALL
        .iter()
        .map(|reason| reason.as_str())
        .collect();
    assert_eq!(names.len(), SubReason::ALL.len());
    for name in &names {
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{name}"
        );
    }
    assert_eq!(
        AttestationFailure::Missing(MissingEvidence::NoBundle).reason_code(),
        crate::error::ReasonCode::EEvidenceDowngrade
    );
}

#[test]
fn the_provider_is_installed_once_and_kept() -> TestResult {
    ensure_crypto_provider()?;
    ensure_crypto_provider()?;
    assert!(sigstore_crypto::try_default_provider().is_some());
    Ok(())
}

#[test]
fn n_007_an_api_digest_without_a_signature_is_not_evidence() -> TestResult {
    // The release lists the asset with its API digest, but no attestation
    // exists: neither level is reached, and the result is a downgrade.
    let verifier = verifier()?;
    assert_eq!(
        missing(verifier.verify_attested(&[], &v1_provenance(&original()?)?)),
        Some(MissingEvidence::NoBundle)
    );
    assert_eq!(
        AttestationFailure::Missing(MissingEvidence::NoBundle).reason_code(),
        crate::error::ReasonCode::EEvidenceDowngrade
    );
    Ok(())
}

#[test]
fn sub_reasons_are_exactly_the_wire_subcodes() {
    let ours: Vec<&str> = SubReason::ALL
        .iter()
        .map(|reason| reason.as_str())
        .collect();
    assert_eq!(ours, crate::error::ATTESTATION_SUBCODES);
}

#[test]
fn a_failure_becomes_a_reason_event_without_network_detail() -> TestResult {
    use crate::error::{ObjectKind, ObjectReference, ReasonEvent, SafeIdentifier};
    let object = ObjectReference::new(ObjectKind::Artifact, SafeIdentifier::new("artifact-1")?);
    let failure = AttestationFailure::invalid(
        SubReason::WorkflowMismatch,
        "signer https://github.com/evil/x/.github/workflows/a.yml@refs/heads/main",
    );
    let event = ReasonEvent::new(failure.reason(object.clone())?);
    assert_eq!(event.schema_version(), 2);
    let json = event.to_json()?;
    assert!(json.contains(r#""subcode":"workflow_mismatch""#), "{json}");
    assert!(!json.contains("evil"), "{json}");
    assert_eq!(ReasonEvent::from_json(&json)?, event);
    let missing =
        ReasonEvent::new(AttestationFailure::Missing(MissingEvidence::NoBundle).reason(object)?);
    assert_eq!(missing.schema_version(), 1);
    assert!(!missing.to_json()?.contains("subcode"));
    Ok(())
}
