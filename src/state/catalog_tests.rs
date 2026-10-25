// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: &str = "2026-10-24T12:00:00Z";
const SOURCE: &str = "github-1429109739";

fn owner() -> Result<(TempDir, StateOwner), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    owner.connection().execute(
        "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, \
         first_seen_at) VALUES (?1, 'github', '1429109739', '2264172', \
         'https://github.com/kroxiksut/pchi-test', ?2)",
        params![SOURCE, AT],
    )?;
    Ok((dir, owner))
}

fn family(names: &[&str]) -> Result<Family, Box<dyn std::error::Error>> {
    Ok(Family::proposed(names.iter().map(|name| {
        (
            MemberKey::new(Ecosystem::Deb, name),
            ["all".to_owned()].into_iter().collect(),
        )
    }))?)
}

fn release(tag: &str) -> ReleaseRow<'_> {
    ReleaseRow {
        forge_release_id: 420_339_762,
        tag,
        commit: None,
        published_at: AT,
        channel: "stable",
        immutable: false,
    }
}

fn evidence(subject: Sha256Digest) -> EvidenceRow<'static> {
    EvidenceRow {
        level: Level::Attested,
        repository_id: 1_429_109_739,
        subject,
        signer_identity: ".github/workflows/release.yml@refs/heads/main",
        predicate_type: "https://slsa.dev/provenance/v1",
        bundle_sha256: Sha256Digest::of(b"bundle"),
        record_json: "{}",
        verifier_version: "test",
    }
}

fn artifact<'a>(release_row: &'a str, family_id: &'a str, sha256: Sha256Digest) -> ArtifactRow<'a> {
    ArtifactRow {
        release_row,
        asset_id: 664_783_235,
        family_id,
        ecosystem: Ecosystem::Deb,
        name: "sampleapp",
        version: "1.0-1",
        architecture: "all",
        filename: "sampleapp_1.0-1_all.deb",
        sha256,
        size: 800,
    }
}

#[test]
fn a_family_comes_back_as_it_was_saved_and_an_older_revision_is_refused() -> TestResult {
    let (_dir, mut owner) = owner()?;
    let mut proposed = family(&["sampleapp", "sampleapp-data"])?;
    owner.save_family(SOURCE, &proposed)?;
    let (_, restored) = owner.family(SOURCE)?.ok_or("no family")?;
    assert_eq!(restored, proposed);
    assert_eq!(
        restored.state(),
        FamilyState::Proposed,
        "never approved by default"
    );
    proposed.approve(1)?;
    owner.save_family(SOURCE, &proposed)?;
    assert_eq!(
        owner.family(SOURCE)?.ok_or("no family")?.1.state(),
        FamilyState::Approved
    );
    // A revision 2 saved, then an old copy of revision 1 again: the older
    // one must not overwrite what the administrator confirmed later.
    let newer = Family::restore(
        2,
        FamilyState::Proposed,
        family(&["sampleapp"])?.members().clone(),
    )?;
    owner.save_family(SOURCE, &newer)?;
    assert!(matches!(
        owner.save_family(SOURCE, &proposed),
        Err(StateError::StaleRevision)
    ));
    assert_eq!(owner.family(SOURCE)?.ok_or("no family")?.1, newer);
    Ok(())
}

#[test]
fn a_name_dropped_from_the_family_is_not_restored_as_a_member() -> TestResult {
    // The administrator approved only `sampleapp` out of the proposed set;
    // `sampleapp-extra` already has an artifact row, which keeps its
    // identity row. Restoring the family must not approve it back.
    let (_dir, mut owner) = owner()?;
    let proposed = family(&["sampleapp", "sampleapp-extra"])?;
    let family_id = owner.save_family(SOURCE, &proposed)?;
    let release_row = owner.record_release(SOURCE, &release("v1.0.0"))?;
    let mut extra = artifact(&release_row, &family_id, Sha256Digest::of(b"extra"));
    extra.name = "sampleapp-extra";
    owner.record_artifact(SOURCE, &extra, None, ArtifactState::Held)?;
    let approved = Family::restore(
        2,
        FamilyState::Approved,
        family(&["sampleapp"])?.members().clone(),
    )?;
    owner.save_family(SOURCE, &approved)?;
    let (_, restored) = owner.family(SOURCE)?.ok_or("no family")?;
    assert_eq!(restored, approved);
    // A name seen later outside the family is recorded, not approved.
    owner.record_seen_name(SOURCE, &MemberKey::new(Ecosystem::Deb, "sampleapp-new"))?;
    assert_eq!(owner.family(SOURCE)?.ok_or("no family")?.1, approved);
    let mut new = artifact(&release_row, &family_id, Sha256Digest::of(b"new"));
    new.name = "sampleapp-new";
    owner.record_artifact(SOURCE, &new, None, ArtifactState::Held)?;
    let seen: Vec<String> = owner
        .seen_names(SOURCE)?
        .into_keys()
        .map(|key| key.name)
        .collect();
    assert_eq!(seen, ["sampleapp-extra", "sampleapp-new"]);
    Ok(())
}

#[test]
fn a_release_seen_again_keeps_its_first_record() -> TestResult {
    let (_dir, mut owner) = owner()?;
    let first = owner.record_release(SOURCE, &release("v1.0.0"))?;
    // The tag was moved upstream: the stored release keeps what was seen.
    let again = owner.record_release(SOURCE, &release("v1.0.0-moved"))?;
    assert_eq!(first, again);
    let tag: String = owner.connection().query_row(
        "SELECT tag FROM release_record WHERE id = ?1",
        [&first],
        |row| row.get(0),
    )?;
    assert_eq!(tag, "v1.0.0");
    Ok(())
}

#[test]
fn evidence_covers_only_its_own_bytes_and_is_never_replaced() -> TestResult {
    let (_dir, mut owner) = owner()?;
    let family_id = owner.save_family(SOURCE, &family(&["sampleapp"])?)?;
    let release_row = owner.record_release(SOURCE, &release("v1.0.0"))?;
    let bytes = Sha256Digest::of(b"package");
    let other = Sha256Digest::of(b"other package");
    let proof = owner.record_evidence(SOURCE, &evidence(bytes), AT)?;
    assert_eq!(owner.record_evidence(SOURCE, &evidence(bytes), AT)?, proof);
    // Evidence for other bytes cannot admit these.
    assert!(
        owner
            .record_artifact(
                SOURCE,
                &artifact(&release_row, &family_id, other),
                Some(&proof),
                ArtifactState::Verified,
            )
            .is_err()
    );
    let id = owner.record_artifact(
        SOURCE,
        &artifact(&release_row, &family_id, bytes),
        Some(&proof),
        ArtifactState::Verified,
    )?;
    // Seen again without evidence (a later sync that could not reach
    // GitHub): the accepted evidence stays attached.
    let again = owner.record_artifact(
        SOURCE,
        &artifact(&release_row, &family_id, bytes),
        None,
        ArtifactState::Published,
    )?;
    assert_eq!(id, again);
    let (state, attached): (String, Option<String>) = owner.connection().query_row(
        "SELECT state, evidence_id FROM artifact WHERE id = ?1",
        [&id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(state, "published");
    assert_eq!(attached.as_deref(), Some(proof.as_str()));
    Ok(())
}

#[test]
fn the_same_asset_with_other_bytes_is_another_artifact() -> TestResult {
    // A replaced asset (E_ASSET_MUTATED) must not take over the accepted
    // record of the first bytes.
    let (_dir, mut owner) = owner()?;
    let family_id = owner.save_family(SOURCE, &family(&["sampleapp"])?)?;
    let release_row = owner.record_release(SOURCE, &release("v1.0.0"))?;
    let first = owner.record_artifact(
        SOURCE,
        &artifact(&release_row, &family_id, Sha256Digest::of(b"first")),
        None,
        ArtifactState::Candidate,
    )?;
    let second = owner.record_artifact(
        SOURCE,
        &artifact(&release_row, &family_id, Sha256Digest::of(b"replaced")),
        None,
        ArtifactState::Rejected,
    )?;
    assert_ne!(first, second);
    Ok(())
}

#[test]
fn the_trust_floor_only_rises() -> TestResult {
    let (_dir, mut owner) = owner()?;
    let floor = |owner: &mut StateOwner| -> Result<Option<String>, StateError> {
        Ok(owner.connection().query_row(
            "SELECT trust_floor FROM forge_repository WHERE id = ?1",
            [SOURCE],
            |row| row.get(0),
        )?)
    };
    owner.raise_trust_floor(SOURCE, Level::Attested)?;
    assert_eq!(floor(&mut owner)?.as_deref(), Some("attested"));
    // A Pinned release later is not a reason to lower it.
    owner.raise_trust_floor(SOURCE, Level::Pinned)?;
    assert_eq!(floor(&mut owner)?.as_deref(), Some("attested"));
    owner.raise_trust_floor(SOURCE, Level::Strict)?;
    assert_eq!(floor(&mut owner)?.as_deref(), Some("strict"));
    Ok(())
}
