// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SHA: &str = "a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9";

fn owner_with(state: &str) -> Result<(TempDir, StateOwner), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let evidence = if matches!(
        state,
        "discovered" | "candidate" | "held" | "rejected" | "revoked"
    ) {
        "NULL"
    } else {
        "'evidence-1'"
    };
    owner.connection().execute_batch(&format!(
        "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, first_seen_at) \
         VALUES ('source-1', 'github', '1429109739', '2264172', 'https://github.com/kroxiksut/pchi-test', '2026-10-22T00:00:00Z'); \
         INSERT INTO package_family (id, source_id, name, purpose) VALUES ('family-1', 'source-1', 'fixture', 'test'); \
         INSERT INTO package_identity (family_id, ecosystem, native_name, allowed_arches_json) \
         VALUES ('family-1', 'deb', 'pakomichi-r003-fixture', '[\"all\"]'); \
         INSERT INTO release_record (id, source_id, forge_release_id, tag, published_at, channel) \
         VALUES ('release-1', 'source-1', '420339762', 'v0.2.0-mutable', '2026-10-22T00:00:00Z', 'stable'); \
         INSERT INTO trust_evidence (id, source_id, evidence_type, root_chain_json, signer_identity, repository_id, \
         subject_sha256, predicate_type, verified_at, verifier_version, record_json) \
         VALUES ('evidence-1', 'source-1', 'attested', '[]', 'test-signer', '1429109739', '{SHA}', 'test', \
         '2026-10-22T00:00:00Z', '0.0.0', '{{}}'); \
         INSERT INTO artifact (id, source_id, release_id, asset_id, family_id, ecosystem, native_name, native_version, \
         architecture, filename, sha256, byte_size, evidence_id, state) \
         VALUES ('artifact-1', 'source-1', 'release-1', '664806807', 'family-1', 'deb', 'pakomichi-r003-fixture', \
         '0.2.0', 'all', 'pakomichi-r003-fixture_0.2.0_all.deb', '{SHA}', 800, {evidence}, '{state}');"
    ))?;
    Ok((dir, owner))
}

#[test]
fn an_accepted_object_names_its_repository_and_asset_by_id() -> TestResult {
    let digest = Sha256Digest::from_hex(SHA)?;
    for state in ["verified", "eligible", "published", "retired"] {
        let (_dir, mut owner) = owner_with(state)?;
        assert_eq!(
            owner.pinned_asset(&digest, 800)?,
            Some(AssetPinRow {
                repository_id: "1429109739".to_owned(),
                asset_id: "664806807".to_owned(),
            }),
            "{state}"
        );
    }
    Ok(())
}

#[test]
fn bytes_not_accepted_or_of_another_size_are_never_fetched() -> TestResult {
    let digest = Sha256Digest::from_hex(SHA)?;
    // A revoked release must not come back through the lazy path.
    for state in ["discovered", "candidate", "held", "rejected", "revoked"] {
        let (_dir, mut owner) = owner_with(state)?;
        assert_eq!(owner.pinned_asset(&digest, 800)?, None, "{state}");
    }
    let (_dir, mut owner) = owner_with("published")?;
    assert_eq!(owner.pinned_asset(&digest, 799)?, None);
    assert_eq!(owner.pinned_asset(&Sha256Digest::of(b"other"), 800)?, None);
    assert_eq!(owner.pinned_asset(&digest, u64::MAX)?, None);
    Ok(())
}
