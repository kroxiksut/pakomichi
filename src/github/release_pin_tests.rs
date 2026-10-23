// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests use the values observed on the R-003 test repository on 2026-10-22
//! (`research/r-003/results/owner-step*-*.tsv`).

use std::error::Error;

use super::*;
use crate::github::{OwnerLogin, RepositoryIdentity, RepositoryName};

type TestResult = Result<(), Box<dyn Error>>;

const REPOSITORY: u64 = 1_429_109_739;
const USER: u64 = 2_264_172;
const ORGANIZATION: u64 = 346_117_935;
const FORK: u64 = 1_429_309_242;
/// The R-003 tags are lightweight, so the tag reference is the commit.
const TAG_REF: &str = "6ee0f9f53e5a296bd19904188d055608f32ffd82";

const V010_RELEASE: u64 = 420_324_447;
const V010_ASSET: u64 = 664_728_438;
const V010_SHA256: &str = "8fcda58d824b4fea8f98e036083f398f497941af4b8c15de5dac02dd900576fd";
const V010_NAME: &str = "pakomichi-r003-fixture_0.1.0_all.deb";

const V020_RELEASE: u64 = 420_339_762;
const V020_ASSET: u64 = 664_783_235;
const V020_SHA256: &str = "93b4dc424c37d0eb0fd464025eed2a7d90c4f2b2d50a83bd7eee5bcc047c56cf";
const V020_NAME: &str = "pakomichi-r003-fixture_0.2.0_all.deb";
const REPLACED_ASSET: u64 = 664_806_807;
const REPLACED_SHA256: &str = "a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9";

fn digest(hex: &str) -> Result<Sha256Digest, Box<dyn Error>> {
    Ok(Sha256Digest::from_hex(hex)?)
}

fn asset(id: u64, name: &str, sha256: Option<&str>) -> Result<ReleaseAsset, Box<dyn Error>> {
    Ok(ReleaseAsset {
        id: AssetId::new(id)?,
        name: name.to_owned(),
        size: 772,
        api_digest: sha256.map(digest).transpose()?,
        uploaded: true,
        download_url: format!("https://github.com/kroxiksut/pchi-test/releases/download/x/{name}"),
    })
}

fn release(id: u64, tag: &str, assets: Vec<ReleaseAsset>) -> Result<Release, Box<dyn Error>> {
    Ok(Release {
        id: ReleaseId::new(id)?,
        tag: tag.to_owned(),
        target_commitish: "main".to_owned(),
        draft: false,
        prerelease: false,
        immutable: Some(false),
        published_at: Some("2026-10-22T05:28:45Z".to_owned()),
        assets,
    })
}

fn v020_pin() -> Result<AssetPin, Box<dyn Error>> {
    Ok(AssetPin {
        release_id: ReleaseId::new(V020_RELEASE)?,
        asset_id: AssetId::new(V020_ASSET)?,
        name: V020_NAME.to_owned(),
        sha256: digest(V020_SHA256)?,
    })
}

fn repository(
    owner: u64,
    login: &str,
    earlier: &[u64],
) -> Result<PinnedRepository, Box<dyn Error>> {
    let current = RepositoryIdentity::new(
        RepositoryId::new(REPOSITORY)?,
        OwnerId::new(owner)?,
        OwnerLogin::new(login)?,
        RepositoryName::new("pchi-test")?,
    );
    let earlier = earlier
        .iter()
        .map(|id| OwnerId::new(*id))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PinnedRepository::restore(current, earlier))
}

/// The predicate of the `v0.1.0` release attestation as observed in step 1.
fn v010_claims() -> Result<ReleaseClaims, Box<dyn Error>> {
    Ok(ReleaseClaims {
        repository_id: REPOSITORY,
        package_id: REPOSITORY,
        owner_id: USER,
        database_id: V010_RELEASE,
        tag: "v0.1.0".to_owned(),
        tag_refs: vec![GitObjectId::from_hex(TAG_REF)?],
        assets: vec![NamedSubject {
            name: V010_NAME.to_owned(),
            sha256: digest(V010_SHA256)?,
        }],
    })
}

fn v010_expected(pinned: &PinnedRepository) -> Result<ExpectedRelease, Box<dyn Error>> {
    let release = release(
        V010_RELEASE,
        "v0.1.0",
        vec![asset(V010_ASSET, V010_NAME, Some(V010_SHA256))?],
    )?;
    Ok(ExpectedRelease::new(
        pinned,
        &release,
        GitObjectId::from_hex(TAG_REF)?,
        V010_NAME,
        digest(V010_SHA256)?,
    ))
}

#[test]
fn object_ids_have_one_spelling() -> TestResult {
    let object = GitObjectId::from_hex(TAG_REF)?;
    assert_eq!(object.to_hex(), TAG_REF);
    assert_eq!(
        GitObjectId::from_hex(&TAG_REF.to_uppercase()),
        Err(InvalidObjectId)
    );
    assert_eq!(GitObjectId::from_hex(&TAG_REF[..39]), Err(InvalidObjectId));
    assert_eq!(
        GitObjectId::from_hex(&format!("{TAG_REF}0")),
        Err(InvalidObjectId)
    );
    assert_eq!(GitObjectId::from_hex(&"g".repeat(40)), Err(InvalidObjectId));
    Ok(())
}

#[test]
fn an_unchanged_asset_passes() -> TestResult {
    let current = release(
        V020_RELEASE,
        "v0.2.0-mutable",
        vec![asset(V020_ASSET, V020_NAME, Some(V020_SHA256))?],
    )?;
    let check = v020_pin()?.check(&current);
    assert_eq!(check, AssetCheck::Unchanged);
    assert_eq!(check.reason_code(), None);
    Ok(())
}

#[test]
fn r003_step3_replacement_under_the_same_name_is_mutated() -> TestResult {
    // Same release ID, tag, and asset name; new asset ID and digest.
    let current = release(
        V020_RELEASE,
        "v0.2.0-mutable",
        vec![asset(REPLACED_ASSET, V020_NAME, Some(REPLACED_SHA256))?],
    )?;
    let check = v020_pin()?.check(&current);
    assert_eq!(
        check,
        AssetCheck::Mutated {
            observed_asset_id: AssetId::new(REPLACED_ASSET)?,
            observed_sha256: Some(digest(REPLACED_SHA256)?),
        }
    );
    assert_eq!(check.reason_code(), Some(ReasonCode::EAssetMutated));
    Ok(())
}

#[test]
fn a_changed_digest_or_name_under_the_pinned_asset_id_is_mutated() -> TestResult {
    let pin = v020_pin()?;
    for changed in [
        asset(V020_ASSET, V020_NAME, Some(REPLACED_SHA256))?,
        asset(V020_ASSET, "renamed.deb", Some(V020_SHA256))?,
    ] {
        let current = release(V020_RELEASE, "v0.2.0-mutable", vec![changed])?;
        assert_eq!(
            pin.check(&current).reason_code(),
            Some(ReasonCode::EAssetMutated)
        );
    }
    Ok(())
}

#[test]
fn missing_digest_removed_asset_and_other_release_are_distinct() -> TestResult {
    let pin = v020_pin()?;
    let no_digest = release(
        V020_RELEASE,
        "v0.2.0-mutable",
        vec![asset(V020_ASSET, V020_NAME, None)?],
    )?;
    assert_eq!(pin.check(&no_digest), AssetCheck::DigestUnknown);
    let empty = release(V020_RELEASE, "v0.2.0-mutable", vec![])?;
    assert_eq!(pin.check(&empty), AssetCheck::Removed);
    let other = release(
        V010_RELEASE,
        "v0.1.0",
        vec![asset(V020_ASSET, V020_NAME, Some(V020_SHA256))?],
    )?;
    assert_eq!(
        pin.check(&other),
        AssetCheck::OtherRelease {
            observed: ReleaseId::new(V010_RELEASE)?
        }
    );
    Ok(())
}

#[test]
fn downloaded_bytes_must_equal_the_pin() -> TestResult {
    let pin = v020_pin()?;
    assert_eq!(pin.check_bytes(&digest(V020_SHA256)?), Ok(()));
    let error = pin.check_bytes(&digest(REPLACED_SHA256)?);
    assert_eq!(
        error,
        Err(BytesMutated {
            expected: digest(V020_SHA256)?,
            observed: digest(REPLACED_SHA256)?,
        })
    );
    assert!(matches!(error, Err(mutated) if mutated.reason_code() == ReasonCode::EAssetMutated));
    Ok(())
}

#[test]
fn r003_step3_an_attestation_of_the_removed_asset_is_not_the_current_asset() -> TestResult {
    let current = release(
        V020_RELEASE,
        "v0.2.0-mutable",
        vec![asset(REPLACED_ASSET, V020_NAME, Some(REPLACED_SHA256))?],
    )?;
    // The old file's attestation still verifies by digest (O3-old-online).
    assert_eq!(
        current_asset(&current, V020_NAME, &digest(V020_SHA256)?),
        Err(CurrentAssetError::DigestDiffers {
            asset_id: AssetId::new(REPLACED_ASSET)?,
            current: digest(REPLACED_SHA256)?,
        })
    );
    let found = current_asset(&current, V020_NAME, &digest(REPLACED_SHA256)?)?;
    assert_eq!(found.id.get(), REPLACED_ASSET);
    Ok(())
}

#[test]
fn current_asset_needs_an_uploaded_asset_with_a_digest() -> TestResult {
    let mut pending = asset(V020_ASSET, V020_NAME, Some(V020_SHA256))?;
    pending.uploaded = false;
    let current = release(V020_RELEASE, "v0.2.0-mutable", vec![pending])?;
    assert_eq!(
        current_asset(&current, V020_NAME, &digest(V020_SHA256)?),
        Err(CurrentAssetError::NotInRelease)
    );
    let no_digest = release(
        V020_RELEASE,
        "v0.2.0-mutable",
        vec![asset(V020_ASSET, V020_NAME, None)?],
    )?;
    assert_eq!(
        current_asset(&no_digest, V020_NAME, &digest(V020_SHA256)?),
        Err(CurrentAssetError::DigestUnknown {
            asset_id: AssetId::new(V020_ASSET)?
        })
    );
    // Names are exact: another case is another asset.
    assert_eq!(
        current_asset(&no_digest, &V020_NAME.to_uppercase(), &digest(V020_SHA256)?),
        Err(CurrentAssetError::NotInRelease)
    );
    Ok(())
}

#[test]
fn r003_step1_release_claims_match() -> TestResult {
    let expected = v010_expected(&repository(USER, "kroxiksut", &[])?)?;
    assert_eq!(expected.check_release_claims(&v010_claims()?), Ok(()));
    Ok(())
}

#[test]
fn r003_step2_a_release_attestation_found_by_commit_belongs_to_another_release() -> TestResult {
    // v0.2.0-mutable shares the tag commit with v0.1.0; looking up
    // `sha1:<tag commit>` returned the v0.1.0 release attestation.
    let pinned = repository(USER, "kroxiksut", &[])?;
    let mutable = release(
        V020_RELEASE,
        "v0.2.0-mutable",
        vec![asset(V020_ASSET, V020_NAME, Some(V020_SHA256))?],
    )?;
    let expected = ExpectedRelease::new(
        &pinned,
        &mutable,
        GitObjectId::from_hex(TAG_REF)?,
        V020_NAME,
        digest(V020_SHA256)?,
    );
    let mismatch = expected.check_release_claims(&v010_claims()?);
    assert_eq!(
        mismatch,
        Err(ReleaseMismatch::ReleaseId {
            observed: V010_RELEASE
        })
    );
    assert!(matches!(mismatch, Err(m) if m.sub_reason() == "release_mismatch"));
    Ok(())
}

#[test]
fn r003_transfer_keeps_releases_made_under_the_previous_owner() -> TestResult {
    // T3: after a confirmed transfer the user's owner ID is still accepted.
    let confirmed = repository(ORGANIZATION, "pchi-test-org", &[USER])?;
    let expected = v010_expected(&confirmed)?;
    assert_eq!(
        expected.accepted_owner_ids(),
        &[OwnerId::new(USER)?, OwnerId::new(ORGANIZATION)?]
    );
    assert_eq!(expected.check_release_claims(&v010_claims()?), Ok(()));

    // T1: re-pinning that replaces the owner ID loses the earlier releases.
    let replaced = repository(ORGANIZATION, "pchi-test-org", &[])?;
    let mismatch = v010_expected(&replaced)?.check_release_claims(&v010_claims()?);
    assert_eq!(mismatch, Err(ReleaseMismatch::OwnerId { observed: USER }));
    assert!(matches!(mismatch, Err(m) if m.sub_reason() == "owner_id_mismatch"));
    Ok(())
}

#[test]
fn every_release_field_is_checked_in_a_fixed_order() -> TestResult {
    let expected = v010_expected(&repository(USER, "kroxiksut", &[])?)?;
    let base = v010_claims()?;

    let mut claims = base.clone();
    claims.repository_id = FORK;
    claims.owner_id = ORGANIZATION;
    // Repository first, even when the owner differs too.
    assert_eq!(
        expected.check_release_claims(&claims),
        Err(ReleaseMismatch::RepositoryId { observed: FORK })
    );

    let mut claims = base.clone();
    claims.package_id = FORK;
    assert_eq!(
        expected.check_release_claims(&claims),
        Err(ReleaseMismatch::PackageId { observed: FORK })
    );

    let mut claims = base.clone();
    claims.tag = "V0.1.0".to_owned();
    assert_eq!(
        expected.check_release_claims(&claims),
        Err(ReleaseMismatch::Tag)
    );

    let mut claims = base.clone();
    claims.tag_refs = vec![GitObjectId::from_bytes([0; 20])];
    assert_eq!(
        expected.check_release_claims(&claims),
        Err(ReleaseMismatch::TagRef)
    );

    let mut claims = base.clone();
    claims.assets[0].sha256 = digest(REPLACED_SHA256)?;
    assert_eq!(
        expected.check_release_claims(&claims),
        Err(ReleaseMismatch::AssetSubject)
    );

    let mut claims = base.clone();
    claims.assets[0].name = V010_NAME.to_uppercase();
    assert_eq!(
        expected.check_release_claims(&claims),
        Err(ReleaseMismatch::AssetSubject)
    );
    Ok(())
}

#[test]
fn an_asset_name_listed_with_two_digests_is_refused() -> TestResult {
    let expected = v010_expected(&repository(USER, "kroxiksut", &[])?)?;
    let mut claims = v010_claims()?;
    claims.assets.push(NamedSubject {
        name: V010_NAME.to_owned(),
        sha256: digest(REPLACED_SHA256)?,
    });
    let mismatch = expected.check_release_claims(&claims);
    assert_eq!(mismatch, Err(ReleaseMismatch::AssetSubject));
    assert!(
        matches!(mismatch, Err(m) if m.sub_reason() == "subject_mismatch"
        && m.reason_code() == ReasonCode::EAttestationInvalid)
    );
    Ok(())
}

/// `github/github-mcp-server` v2.0.2 as observed on 2026-10-22
/// (`research/r-003/results/annotated-tag-reference.tsv`): an immutable
/// release with an annotated tag.
mod annotated_tag {
    use super::*;

    const REPOSITORY: u64 = 942_771_284;
    const OWNER: u64 = 9919;
    const RELEASE: u64 = 406_753_657;
    const ASSET: u64 = 621_635_784;
    const NAME: &str = "github-mcp-server_Linux_x86_64.tar.gz";
    const SHA256: &str = "815e27d931c796af0c97f24fd211e14f8a4607d4528377719a5ad2352086b0b0";
    /// `object.sha` of `git/ref/tags/v2.0.2`, an object of type `tag`.
    const TAG_OBJECT: &str = "503622d154b505a9cebff296a13bc6c9259ea993";
    /// The commit the tag object points to.
    const PEELED_COMMIT: &str = "eb47a99ddb866ca2b8a162920e6bda9521f33ebb";

    fn pinned() -> Result<PinnedRepository, Box<dyn Error>> {
        Ok(PinnedRepository::pin(RepositoryIdentity::new(
            RepositoryId::new(REPOSITORY)?,
            OwnerId::new(OWNER)?,
            OwnerLogin::new("github")?,
            RepositoryName::new("github-mcp-server")?,
        )))
    }

    fn expected(tag_ref: &str) -> Result<ExpectedRelease, Box<dyn Error>> {
        let mut current = release(RELEASE, "v2.0.2", vec![asset(ASSET, NAME, Some(SHA256))?])?;
        current.immutable = Some(true);
        Ok(ExpectedRelease::new(
            &pinned()?,
            &current,
            GitObjectId::from_hex(tag_ref)?,
            NAME,
            digest(SHA256)?,
        ))
    }

    /// The signed predicate and subjects: one `sha1` subject, the tag object.
    fn claims() -> Result<ReleaseClaims, Box<dyn Error>> {
        Ok(ReleaseClaims {
            repository_id: REPOSITORY,
            package_id: REPOSITORY,
            owner_id: OWNER,
            database_id: RELEASE,
            tag: "v2.0.2".to_owned(),
            tag_refs: vec![GitObjectId::from_hex(TAG_OBJECT)?],
            assets: vec![NamedSubject {
                name: NAME.to_owned(),
                sha256: digest(SHA256)?,
            }],
        })
    }

    #[test]
    fn the_tag_object_as_returned_matches() -> TestResult {
        assert_eq!(
            expected(TAG_OBJECT)?.check_release_claims(&claims()?),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn the_peeled_commit_is_not_in_the_attestation() -> TestResult {
        let mismatch = expected(PEELED_COMMIT)?.check_release_claims(&claims()?);
        assert_eq!(mismatch, Err(ReleaseMismatch::TagRef));
        assert!(matches!(mismatch, Err(m) if m.sub_reason() == "release_mismatch"));
        Ok(())
    }
}
