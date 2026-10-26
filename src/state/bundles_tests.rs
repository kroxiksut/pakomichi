// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::time::{Duration, SystemTime};

use rusqlite::params;

use super::*;
use crate::cas::{GcRoots, Store, StoreConfig};
use crate::policy::level::Level;
use crate::state::EvidenceRow;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

const AT: &str = "2026-10-25T12:00:00Z";
const SOURCE: &str = "github-1429109739";
const OTHER_SOURCE: &str = "github-1429109740";

fn open(dir: &TempDir) -> Result<StateOwner, StateError> {
    StateOwner::open(&dir.join("state.db"))
}

/// A database with two sources.
fn with_sources(dir: &TempDir) -> Result<StateOwner, Box<dyn Error>> {
    let mut owner = open(dir)?;
    for (id, repository) in [(SOURCE, "1429109739"), (OTHER_SOURCE, "1429109740")] {
        owner.connection().execute(
            "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, \
             first_seen_at) VALUES (?1, 'github', ?2, '2264172', ?3, ?4)",
            params![
                id,
                repository,
                format!("https://github.com/kroxiksut/{id}"),
                AT
            ],
        )?;
    }
    Ok(owner)
}

/// Records evidence of `SOURCE` for `subject` verified from `bundle`.
fn evidence(
    owner: &mut StateOwner,
    subject: &[u8],
    bundle: Sha256Digest,
) -> Result<String, StateError> {
    owner.record_evidence(
        SOURCE,
        &EvidenceRow {
            level: Level::Attested,
            repository_id: 1_429_109_739,
            subject: Sha256Digest::of(subject),
            signer_identity: "https://github.com/kroxiksut/pchi-test/.github/workflows/release.yml@refs/tags/v1.0.0",
            predicate_type: "https://slsa.dev/provenance/v1",
            bundle_sha256: bundle,
            record_json: "{}",
            verifier_version: "test",
        },
        AT,
    )
}

fn bundle(index: u8) -> Sha256Digest {
    Sha256Digest::of(&[b'b', index])
}

#[test]
fn recorded_bundles_come_back_exactly_and_recording_again_changes_nothing() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = with_sources(&dir)?;
    let first = evidence(&mut owner, b"package-1", bundle(1))?;
    let second = evidence(&mut owner, b"package-2", bundle(3))?;

    owner.record_evidence_bundles(SOURCE, &first, &[bundle(2), bundle(1)])?;
    // A repeated synchronization records the same bundle again.
    owner.record_evidence_bundles(SOURCE, &first, &[bundle(1)])?;
    // Two pieces of evidence may share a bundle; each keeps its own list.
    owner.record_evidence_bundles(SOURCE, &second, &[bundle(3), bundle(2)])?;

    let mut expected = vec![bundle(1), bundle(2)];
    expected.sort();
    assert_eq!(owner.evidence_bundles(&first)?, expected);
    let mut expected = vec![bundle(2), bundle(3)];
    expected.sort();
    assert_eq!(owner.evidence_bundles(&second)?, expected);
    assert_eq!(
        owner.referenced_bundles()?,
        [bundle(1), bundle(2), bundle(3)].into_iter().collect()
    );
    Ok(())
}

#[test]
fn a_bundle_for_evidence_that_is_not_recorded_for_the_source_is_refused() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = with_sources(&dir)?;
    let recorded = evidence(&mut owner, b"package-1", bundle(1))?;

    // Unknown evidence, and evidence of SOURCE claimed by another source
    // (ADR-034 point 3: evidence belongs to one source).
    for (source, id) in [
        (SOURCE, "evidence-unknown"),
        (OTHER_SOURCE, recorded.as_str()),
    ] {
        assert!(
            matches!(
                owner.record_evidence_bundles(source, id, &[bundle(1)]),
                Err(StateError::UnknownEvidence)
            ),
            "{source} {id}"
        );
    }
    assert!(owner.referenced_bundles()?.is_empty());
    assert!(owner.evidence_bundles(&recorded)?.is_empty());
    Ok(())
}

#[test]
fn evidence_names_at_most_sixteen_bundles_and_a_refused_call_records_none() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = with_sources(&dir)?;
    let id = evidence(&mut owner, b"package-1", bundle(0))?;
    let bundles: Vec<_> = (0..17).map(bundle).collect();

    assert!(matches!(
        owner.record_evidence_bundles(SOURCE, &id, &bundles),
        Err(StateError::TooManyBundles)
    ));
    // All or nothing: the first sixteen of a refused call are not kept.
    assert!(owner.evidence_bundles(&id)?.is_empty());

    owner.record_evidence_bundles(SOURCE, &id, &bundles[..16])?;
    // The same sixteen again are not a seventeenth.
    owner.record_evidence_bundles(SOURCE, &id, &bundles[..16])?;
    assert_eq!(owner.evidence_bundles(&id)?.len(), 16);
    assert!(matches!(
        owner.record_evidence_bundles(SOURCE, &id, &bundles[16..]),
        Err(StateError::TooManyBundles)
    ));
    assert_eq!(owner.evidence_bundles(&id)?.len(), 16);
    Ok(())
}

#[test]
fn a_recorded_bundle_survives_reopening_and_cannot_be_removed() -> TestResult {
    let dir = TempDir::new()?;
    let id = {
        let mut owner = with_sources(&dir)?;
        let id = evidence(&mut owner, b"package-1", bundle(1))?;
        owner.record_evidence_bundles(SOURCE, &id, &[bundle(1)])?;
        id
    };
    let mut owner = open(&dir)?;
    for statement in [
        "DELETE FROM evidence_bundle",
        "UPDATE evidence_bundle SET bundle_sha256 = lower(hex(zeroblob(32)))",
    ] {
        assert!(
            owner.connection().execute(statement, []).is_err(),
            "{statement}"
        );
    }
    assert_eq!(owner.evidence_bundles(&id)?, vec![bundle(1)]);
    assert_eq!(
        owner.referenced_bundles()?,
        [bundle(1)].into_iter().collect()
    );
    Ok(())
}

#[test]
fn the_collector_keeps_a_bundle_evidence_references_and_removes_the_rest() -> TestResult {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.join("cas"), StoreConfig::default())?;
    let referenced_bytes = br#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}"#;
    let unreferenced_bytes = br#"{"mediaType":"unreferenced"}"#;
    // `insert` leases each object; the leases end before the collection.
    let referenced = store.insert(&referenced_bytes[..])?.digest();
    let unreferenced = store.insert(&unreferenced_bytes[..])?.digest();
    {
        let mut owner = with_sources(&dir)?;
        let id = evidence(&mut owner, b"package-1", referenced)?;
        owner.record_evidence_bundles(SOURCE, &id, &[referenced])?;
    }

    // A later collection, from a freshly opened state database.
    let mut owner = open(&dir)?;
    let mut roots = GcRoots::new(SystemTime::now(), Duration::ZERO);
    for digest in owner.referenced_bundles()? {
        roots.pin(digest);
    }
    let report = store.collect_garbage(&roots)?;
    assert_eq!(report.removed, vec![unreferenced]);
    store.verify(crate::cas::ExpectedObject::new(
        referenced,
        referenced_bytes.len() as u64,
    ))?;
    Ok(())
}
