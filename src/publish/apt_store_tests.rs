// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Duration;

use super::*;
use crate::cas::StoreConfig;
use crate::inspect::DebControl;
use crate::publish::PathClass;
use crate::publish::sign::{GpgSigner, GpgvVerifier};
use crate::publish::test_keys::{TestKey, TestResult};
use crate::state::test_support::TempDir;

const DAY: u64 = 86_400;
/// 2026-10-23T10:00:00Z.
const NOW: u64 = 1_792_749_600;
const RETENTION: Duration = Duration::from_secs(8 * DAY);
const LABEL: &str = "pakomichi-netwatch-strict";

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

struct Fixture {
    _dir: TempDir,
    cas: CasStore,
    store: GenerationStore,
    apt: AptRepository,
    key: TestKey,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = TempDir::new()?;
        let cas_root = dir.join("cas");
        std::fs::create_dir(&cas_root)?;
        let cas = CasStore::open(&cas_root, StoreConfig::default())?;
        let (store, _) = GenerationStore::open(&dir.join("publish"))?;
        Ok(Self {
            _dir: dir,
            cas,
            store,
            apt: AptRepository::new(LABEL, &["amd64"])?,
            key: TestKey::new("metadata")?,
        })
    }

    fn signer(&self) -> TestResult<GpgSigner> {
        Ok(GpgSigner::new(
            &self.key.homedir(),
            self.key.fingerprint.clone(),
        )?)
    }

    fn verifier(&self) -> TestResult<GpgvVerifier> {
        Ok(GpgvVerifier::new(
            &self.key.keyring(),
            self.key.fingerprint.clone(),
        )?)
    }

    /// An admitted package whose bytes are already in the CAS.
    fn package(&self, version: &str) -> TestResult<AptPackage> {
        let bytes = format!("netwatch {version} bytes");
        let stored = self.cas.insert(bytes.as_bytes())?;
        Ok(AptPackage {
            control: DebControl::from_text(&format!(
                "Package: netwatch\nVersion: {version}\nArchitecture: amd64\nDescription: fixture\n"
            ))?,
            object: ExpectedObject::new(stored.digest(), stored.size()),
        })
    }

    fn publish(
        &mut self,
        packages: &[AptPackage],
        signer: &dyn MetadataSigner,
        verifier: &dyn MetadataVerifier,
        now: u64,
    ) -> Result<GenerationId, AptPublishError> {
        let generation = AptGeneration {
            repo: RepoName::new(LABEL).map_err(PublishError::Manifest)?,
            source: SourceId::new("src-1").map_err(PublishError::Manifest)?,
            apt: &self.apt,
            packages,
            freshness: Freshness {
                confirmed_at: now - 600,
                max_freshness: 7 * DAY,
            },
        };
        publish_apt(
            &mut self.store,
            &self.cas,
            signer,
            verifier,
            generation,
            at(now),
        )
    }

    fn current(&self) -> TestResult<Option<GenerationId>> {
        Ok(self.store.current(&RepoName::new(LABEL)?)?)
    }

    fn resolve(
        &self,
        path: &str,
        now: u64,
    ) -> TestResult<Option<(GenerationId, crate::publish::Entry)>> {
        Ok(self.store.resolve(
            &RepoName::new(LABEL)?,
            &RepoPath::new(path)?,
            at(now),
            RETENTION,
        )?)
    }

    fn bytes(&self, object: &ExpectedObject) -> TestResult<Vec<u8>> {
        Ok(std::fs::read(self.cas.object_path(&object.sha256))?)
    }
}

/// Returns a fixed message, as a broken or compromised signer would.
struct FixedSigner(Vec<u8>);

impl MetadataSigner for FixedSigner {
    fn clearsign(&self, _text: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.0.clone())
    }
}

#[test]
fn a_published_generation_serves_a_signed_release_and_every_index_by_hash() -> TestResult {
    let mut fixture = Fixture::new()?;
    let package = fixture.package("0.35.4")?;
    let (signer, verifier) = (fixture.signer()?, fixture.verifier()?);
    let id = fixture.publish(std::slice::from_ref(&package), &signer, &verifier, NOW)?;
    assert_eq!(fixture.current()?, Some(id));

    let manifest = fixture.store.load(&RepoName::new(LABEL)?, id)?;
    let paths: Vec<&str> = manifest
        .entries()
        .map(|entry| entry.path.as_str())
        .collect();
    let plain = format!("dists/{LABEL}/main/binary-amd64/Packages");
    let packages = manifest
        .get(&RepoPath::new(&plain)?)
        .ok_or("no Packages index")?
        .object;
    let by_hash = format!(
        "dists/{LABEL}/main/binary-amd64/by-hash/SHA256/{}",
        packages.sha256.to_hex()
    );
    let pool = format!(
        "pool/{}/netwatch_0.35.4_amd64.deb",
        package.object.sha256.to_hex()
    );
    let in_release = format!("dists/{LABEL}/InRelease");
    for expected in [&plain, &by_hash, &pool, &in_release] {
        assert!(
            paths.contains(&expected.as_str()),
            "{expected} in {paths:?}"
        );
    }
    // Only the signed release: no unsigned `Release` for APT to fall back to.
    assert!(
        !paths.iter().any(|path| path.ends_with("/Release")),
        "{paths:?}"
    );

    let signed = fixture
        .manifest_object(&manifest, &in_release)
        .and_then(|object| fixture.bytes(&object))?;
    let text = String::from_utf8(verifier.verify_clearsigned(&signed)?)?;
    assert!(text.contains(&format!(
        " {} {} main/binary-amd64/Packages\n",
        packages.sha256.to_hex(),
        packages.size
    )));
    assert!(
        text.contains("Valid-Until: Fri, 30 Oct 2026 09:50:00 UTC\n"),
        "{text}"
    );
    assert_eq!(manifest.meta.valid_until.as_str(), "2026-10-30T09:50:00Z");
    Ok(())
}

impl Fixture {
    fn manifest_object(
        &self,
        manifest: &crate::publish::Manifest,
        path: &str,
    ) -> TestResult<ExpectedObject> {
        Ok(manifest
            .get(&RepoPath::new(path)?)
            .ok_or_else(|| format!("{path} missing"))?
            .object)
    }
}

#[test]
fn g9_a_signature_by_another_key_never_becomes_current() -> TestResult {
    let mut fixture = Fixture::new()?;
    let package = fixture.package("0.35.4")?;
    let verifier = fixture.verifier()?;
    let first = fixture.publish(
        std::slice::from_ref(&package),
        &fixture.signer()?,
        &verifier,
        NOW,
    )?;

    let other = TestKey::new("other")?;
    let foreign = GpgSigner::new(&other.homedir(), other.fingerprint.clone())?;
    let newer = fixture.package("0.36.0")?;
    let error = fixture
        .publish(&[package, newer], &foreign, &verifier, NOW + 3600)
        .err();
    assert!(matches!(error, Some(AptPublishError::Sign(_))), "{error:?}");
    assert_eq!(
        error.map(|error| error.reason()),
        Some(ReasonCode::ESnapshotInconsistent)
    );
    assert_eq!(fixture.current()?, Some(first), "current is unchanged");
    Ok(())
}

#[test]
fn a_valid_signature_over_another_release_never_becomes_current() -> TestResult {
    // The right key, but over another text: an older Release replayed by
    // the signer, or one with a longer validity than the confirmed one.
    let mut fixture = Fixture::new()?;
    let package = fixture.package("0.35.4")?;
    let (signer, verifier) = (fixture.signer()?, fixture.verifier()?);
    let first = fixture.publish(std::slice::from_ref(&package), &signer, &verifier, NOW)?;
    let manifest = fixture.store.load(&RepoName::new(LABEL)?, first)?;
    let old =
        fixture.bytes(&fixture.manifest_object(&manifest, &format!("dists/{LABEL}/InRelease"))?)?;

    let newer = fixture.package("0.36.0")?;
    let replay = FixedSigner(old);
    let error = fixture
        .publish(&[package.clone(), newer], &replay, &verifier, NOW + 3600)
        .err();
    assert!(
        matches!(error, Some(AptPublishError::SignedTextDiffers)),
        "{error:?}"
    );
    let longer = fixture.key.sign_with(
        b"Origin: Pakomichi\nValid-Until: Fri, 30 Oct 2099 10:00:00 UTC\n",
        &["--digest-algo", "SHA512", "--clearsign"],
    )?;
    assert!(matches!(
        fixture.publish(&[package], &FixedSigner(longer), &verifier, NOW + 3600),
        Err(AptPublishError::SignedTextDiffers)
    ));
    assert_eq!(fixture.current()?, Some(first));
    Ok(())
}

#[test]
fn a_stale_source_is_not_signed_again_and_current_stays() -> TestResult {
    let mut fixture = Fixture::new()?;
    let package = fixture.package("0.35.4")?;
    let (signer, verifier) = (fixture.signer()?, fixture.verifier()?);
    let first = fixture.publish(std::slice::from_ref(&package), &signer, &verifier, NOW)?;
    let generation = AptGeneration {
        repo: RepoName::new(LABEL)?,
        source: SourceId::new("src-1")?,
        apt: &fixture.apt,
        packages: &[package],
        freshness: Freshness {
            confirmed_at: NOW,
            max_freshness: 7 * DAY,
        },
    };
    let later = NOW + 7 * DAY;
    let error = publish_apt(
        &mut fixture.store,
        &fixture.cas,
        &signer,
        &verifier,
        generation,
        at(later),
    )
    .err();
    assert!(
        matches!(error, Some(AptPublishError::Index(AptError::Stale { .. }))),
        "{error:?}"
    );
    assert_eq!(fixture.current()?, Some(first));
    Ok(())
}

#[test]
fn an_older_generation_stays_consistent_after_the_next_one() -> TestResult {
    // R-004 G5: a client that fetched the old InRelease keeps fetching the
    // indexes and packages it names after the switch.
    let mut fixture = Fixture::new()?;
    let (signer, verifier) = (fixture.signer()?, fixture.verifier()?);
    let old_package = fixture.package("0.35.4")?;
    let first = fixture.publish(std::slice::from_ref(&old_package), &signer, &verifier, NOW)?;
    let first_manifest = fixture.store.load(&RepoName::new(LABEL)?, first)?;
    let new_package = fixture.package("0.36.0")?;
    let second = fixture.publish(&[new_package], &signer, &verifier, NOW + 3600)?;
    assert!(second > first);
    assert_eq!(fixture.current()?, Some(second));

    let later = NOW + 2 * 3600;
    for entry in first_manifest
        .entries()
        .filter(|entry| entry.class == PathClass::ContentAddressed)
    {
        let served = fixture.resolve(entry.path.as_str(), later)?;
        assert_eq!(
            served.map(|(_, served)| served.object),
            Some(entry.object),
            "{}",
            entry.path
        );
    }
    // Mutable paths come only from the current generation.
    let plain = fixture.resolve(&format!("dists/{LABEL}/main/binary-amd64/Packages"), later)?;
    assert_eq!(plain.map(|(id, _)| id), Some(second));
    let old_pool = format!(
        "pool/{}/netwatch_0.35.4_amd64.deb",
        old_package.object.sha256.to_hex()
    );
    assert!(fixture.resolve(&old_pool, later)?.is_some());
    Ok(())
}
