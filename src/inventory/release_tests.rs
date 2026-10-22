// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::github::{IdentityError, ReleaseAsset};
use crate::inventory::{ArchFamily, PlatformError, PrereleaseMarker};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn asset(id: u64, name: &str, size: u64) -> Result<ReleaseAsset, IdentityError> {
    Ok(ReleaseAsset {
        id: AssetId::new(id)?,
        name: name.to_owned(),
        size,
        api_digest: None,
        uploaded: true,
        download_url: format!("https://github.com/o/r/releases/download/v1/{name}"),
    })
}

fn release(
    tag: &str,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
) -> Result<Release, IdentityError> {
    Ok(Release {
        id: ReleaseId::new(7)?,
        tag: tag.to_owned(),
        target_commitish: "main".to_owned(),
        draft: false,
        prerelease,
        immutable: Some(true),
        published_at: Some("2026-10-21T00:00:00Z".to_owned()),
        assets,
    })
}

fn deb_amd64() -> Result<TargetPlatform, PlatformError> {
    TargetPlatform::new(Ecosystem::Deb, "amd64")
}

fn package(name: &str, version: &str, arch: &str) -> NativePackage {
    NativePackage {
        ecosystem: Ecosystem::Deb,
        name: name.to_owned(),
        version: version.to_owned(),
        arch: arch.to_owned(),
        source: false,
    }
}

fn inspected(
    id: u64,
    bytes: &[u8],
    package: NativePackage,
) -> Result<InspectedAsset, IdentityError> {
    Ok(InspectedAsset {
        asset_id: AssetId::new(id)?,
        sha256: Sha256Digest::of(bytes),
        package,
    })
}

fn decision_of(inventory: &ReleaseInventory, id: u64) -> Option<AssetDecision> {
    inventory
        .assets
        .iter()
        .find(|entry| entry.asset_id.get() == id)
        .map(|entry| entry.decision)
}

#[test]
fn a_mixed_release_selects_only_packages_for_the_target() -> TestResult {
    let release = release(
        "v0.6.1",
        false,
        vec![
            asset(1, "netwatch_0.6.1_amd64.deb", 100)?,
            asset(2, "netwatch_0.6.1_arm64.deb", 100)?,
            asset(3, "netwatch-0.6.1-1.x86_64.rpm", 100)?,
            asset(4, "netwatch_0.6.1_all.deb", 100)?,
            asset(5, "netwatch_0.6.1.deb", 100)?,
            asset(6, "netwatch-linux-amd64.tar.gz", 100)?,
            asset(7, "netwatch-darwin-arm64.tar.gz", 100)?,
            asset(8, "netwatch-windows-amd64.zip", 100)?,
            asset(9, "netwatch_0.6.1_amd64.deb.sig", 100)?,
            asset(10, "SHA256SUMS", 100)?,
            asset(11, "netwatch-dbgsym_0.6.1_amd64.ddeb", 100)?,
            asset(12, "netwatch-linux-amd64", 100)?,
            asset(13, "gh_2.102.1_linux_386.deb", 100)?,
            asset(14, "gh_2.102.1_linux_armv6.deb", 100)?,
        ],
    )?;
    let inventory = inventory_release(&release, &deb_amd64()?, &InventoryPolicy::default());

    let candidates: Vec<u64> = inventory
        .candidates()
        .map(|entry| entry.asset_id.get())
        .collect();
    assert_eq!(candidates, vec![1, 4, 5]);
    assert_eq!(
        decision_of(&inventory, 1),
        Some(AssetDecision::Candidate {
            hint: ArchHint::Family(ArchFamily::X86_64)
        })
    );
    assert_eq!(
        decision_of(&inventory, 2),
        Some(AssetDecision::Skipped(SkipReason::OtherArchitecture(
            ArchHint::Family(ArchFamily::Aarch64)
        )))
    );
    // Go release names (GOARCH): `linux_386`, `linux_armv6`.
    assert_eq!(
        decision_of(&inventory, 13),
        Some(AssetDecision::Skipped(SkipReason::OtherArchitecture(
            ArchHint::Family(ArchFamily::X86)
        )))
    );
    assert_eq!(
        decision_of(&inventory, 14),
        Some(AssetDecision::Skipped(SkipReason::OtherArchitecture(
            ArchHint::Arm32
        )))
    );
    assert_eq!(
        decision_of(&inventory, 3),
        Some(AssetDecision::Skipped(SkipReason::OtherEcosystem))
    );
    assert_eq!(
        decision_of(&inventory, 5),
        Some(AssetDecision::Candidate {
            hint: ArchHint::Unknown
        })
    );
    // Archives of any OS, including Linux, are never packages.
    for id in [6, 7, 8] {
        assert_eq!(
            decision_of(&inventory, id),
            Some(AssetDecision::Skipped(SkipReason::Archive))
        );
    }
    assert_eq!(
        decision_of(&inventory, 9),
        Some(AssetDecision::Skipped(SkipReason::Signature))
    );
    assert_eq!(
        decision_of(&inventory, 10),
        Some(AssetDecision::Skipped(SkipReason::Checksum))
    );
    assert_eq!(
        decision_of(&inventory, 11),
        Some(AssetDecision::Skipped(SkipReason::DebugPackage))
    );
    let review: Vec<u64> = inventory
        .needs_review()
        .map(|entry| entry.asset_id.get())
        .collect();
    assert_eq!(review, vec![12]);
    Ok(())
}

#[test]
fn broken_incomplete_and_oversized_assets_are_not_downloaded() -> TestResult {
    let mut incomplete = asset(2, "b_1.0_amd64.deb", 100)?;
    incomplete.uploaded = false;
    let release = release(
        "v1.0",
        false,
        vec![
            asset(1, "a_1.0_amd64.deb", 0)?,
            incomplete,
            asset(3, "c_1.0_amd64.deb", 11)?,
        ],
    )?;
    let policy = InventoryPolicy {
        max_package_bytes: 10,
        ..InventoryPolicy::default()
    };
    let inventory = inventory_release(&release, &deb_amd64()?, &policy);
    assert_eq!(
        decision_of(&inventory, 1),
        Some(AssetDecision::Rejected(ReasonCode::EArtifactMalformed))
    );
    assert_eq!(
        decision_of(&inventory, 2),
        Some(AssetDecision::Skipped(SkipReason::IncompleteUpload))
    );
    assert_eq!(
        decision_of(&inventory, 3),
        Some(AssetDecision::Skipped(SkipReason::TooLarge))
    );
    assert_eq!(inventory.candidates().count(), 0);
    Ok(())
}

#[test]
fn drafts_and_prereleases_are_excluded_on_the_stable_channel() -> TestResult {
    let target = deb_amd64()?;
    let stable = InventoryPolicy::default();

    let mut draft = release("v1.0", false, vec![asset(1, "a_1.0_amd64.deb", 1)?])?;
    draft.draft = true;
    let inventory = inventory_release(&draft, &target, &stable);
    assert_eq!(inventory.excluded, Some(ReleaseExclusion::Draft));
    assert_eq!(inventory.candidates().count(), 0);

    let flagged = release("v1.1", true, vec![asset(1, "a_1.1_amd64.deb", 1)?])?;
    let inventory = inventory_release(&flagged, &target, &stable);
    assert_eq!(
        inventory.excluded,
        Some(ReleaseExclusion::Channel(ChannelVerdict::Prerelease))
    );

    let include = InventoryPolicy {
        channel: ChannelPolicy::IncludePrerelease,
        ..InventoryPolicy::default()
    };
    let inventory = inventory_release(&flagged, &target, &include);
    assert_eq!(inventory.excluded, None);
    assert_eq!(inventory.candidates().count(), 1);
    Ok(())
}

#[test]
fn a_preview_tag_flagged_stable_is_unclear_and_not_offered() -> TestResult {
    // The shape of Win32-OpenSSH 10.4.0.0p1-Preview (R-007): stable flag,
    // pre-release tag.
    let release = release(
        "10.4.0.0p1-Preview",
        false,
        vec![asset(1, "openssh_10.4.0.0_amd64.deb", 1)?],
    )?;
    let inventory = inventory_release(&release, &deb_amd64()?, &InventoryPolicy::default());
    assert_eq!(
        inventory.excluded,
        Some(ReleaseExclusion::Channel(ChannelVerdict::Unclear(
            PrereleaseMarker::Preview
        )))
    );
    assert_eq!(inventory.candidates().count(), 0);
    assert_eq!(
        inventory.excluded.and_then(ReleaseExclusion::reason_code),
        Some(ReasonCode::EChannelUnclear)
    );
    // A flagged pre-release or a draft is simply not offered: no reason code.
    assert_eq!(
        ReleaseExclusion::Channel(ChannelVerdict::Prerelease).reason_code(),
        None
    );
    assert_eq!(ReleaseExclusion::Draft.reason_code(), None);
    Ok(())
}

#[test]
fn inspected_packages_are_admitted_by_their_native_metadata() -> TestResult {
    let target = deb_amd64()?;
    let policy = InventoryPolicy::default();
    let release = release(
        "v1.0",
        false,
        vec![
            asset(1, "a_1.0_amd64.deb", 10)?,
            asset(2, "b_1.0_all.deb", 10)?,
            // The name says amd64, the metadata says arm64: metadata wins.
            asset(3, "c_1.0_amd64.deb", 10)?,
            // No hint in the name; the metadata says i386.
            asset(4, "d_1.0.deb", 10)?,
            // A tilde version keeps a stable-flagged release off the stable
            // channel.
            asset(5, "e_1.0~rc1_amd64.deb", 10)?,
        ],
    )?;
    let inventory = inventory_release(&release, &target, &policy);
    let admitted = admit_release(
        &inventory,
        &[
            inspected(1, b"a", package("a", "1.0-1", "amd64"))?,
            inspected(2, b"b", package("b", "1.0-1", "all"))?,
            inspected(3, b"c", package("c", "1.0-1", "arm64"))?,
            inspected(4, b"d", package("d", "1.0-1", "i386"))?,
            inspected(5, b"e", package("e", "1.0~rc1-1", "amd64"))?,
        ],
        &target,
        &policy,
    )?;
    let expected = [
        Admission::Eligible,
        Admission::Eligible,
        Admission::Held(ReasonCode::EPlatformUnsupported),
        Admission::Held(ReasonCode::EPlatformUnsupported),
        Admission::Held(ReasonCode::EChannelUnclear),
    ];
    for ((id, admission), expected) in admitted.iter().zip(expected) {
        assert_eq!(*admission, expected, "asset {id}");
    }
    Ok(())
}

#[test]
fn bytes_that_differ_from_the_provider_digest_are_rejected() -> TestResult {
    let target = deb_amd64()?;
    let policy = InventoryPolicy::default();
    let mut announced = asset(1, "a_1.0_amd64.deb", 10)?;
    announced.api_digest = Some(Sha256Digest::of(b"announced"));
    let mut matching = asset(2, "b_1.0_amd64.deb", 10)?;
    matching.api_digest = Some(Sha256Digest::of(b"b"));
    let release = release("v1.0", false, vec![announced, matching])?;
    let inventory = inventory_release(&release, &target, &policy);
    let admitted = admit_release(
        &inventory,
        &[
            inspected(1, b"downloaded", package("a", "1.0-1", "amd64"))?,
            inspected(2, b"b", package("b", "1.0-1", "amd64"))?,
        ],
        &target,
        &policy,
    )?;
    assert_eq!(
        admitted[0].1,
        Admission::Rejected(ReasonCode::EAssetMutated)
    );
    assert_eq!(admitted[1].1, Admission::Eligible);
    Ok(())
}

#[test]
fn two_files_claiming_one_package_are_ambiguous() -> TestResult {
    let target = deb_amd64()?;
    let policy = InventoryPolicy::default();
    let release = release(
        "v1.0",
        false,
        vec![
            asset(1, "tool_1.0_amd64.deb", 10)?,
            asset(2, "tool_1.0_amd64-static.deb", 10)?,
            asset(3, "other_1.0_amd64.deb", 10)?,
        ],
    )?;
    let inventory = inventory_release(&release, &target, &policy);
    let admitted = admit_release(
        &inventory,
        &[
            inspected(1, b"dynamic", package("tool", "1.0-1", "amd64"))?,
            inspected(2, b"static", package("tool", "1.0-1", "amd64"))?,
            inspected(3, b"other", package("other", "1.0-1", "amd64"))?,
        ],
        &target,
        &policy,
    )?;
    assert_eq!(admitted[0].1, Admission::Held(ReasonCode::ESourceAmbiguous));
    assert_eq!(admitted[1].1, Admission::Held(ReasonCode::ESourceAmbiguous));
    assert_eq!(admitted[2].1, Admission::Eligible);
    Ok(())
}

#[test]
fn the_same_bytes_under_two_names_keep_the_first() -> TestResult {
    let target = deb_amd64()?;
    let policy = InventoryPolicy::default();
    let release = release(
        "v1.0",
        false,
        vec![
            asset(1, "tool_1.0_amd64.deb", 10)?,
            asset(2, "tool-latest_amd64.deb", 10)?,
        ],
    )?;
    let inventory = inventory_release(&release, &target, &policy);
    let first = AssetId::new(1)?;
    let admitted = admit_release(
        &inventory,
        &[
            inspected(1, b"same", package("tool", "1.0-1", "amd64"))?,
            inspected(2, b"same", package("tool", "1.0-1", "amd64"))?,
        ],
        &target,
        &policy,
    )?;
    assert_eq!(admitted[0].1, Admission::Eligible);
    assert_eq!(admitted[1].1, Admission::Duplicate { of: first });
    Ok(())
}

#[test]
fn rpm_source_packages_and_wrong_ecosystems_are_rejected() -> TestResult {
    let target = TargetPlatform::new(Ecosystem::Rpm, "x86_64")?;
    let policy = InventoryPolicy::default();
    let release = release(
        "v1.0",
        false,
        vec![
            asset(1, "tool-1.0-1.x86_64.rpm", 10)?,
            asset(2, "tool-1.0-1.rpm", 10)?,
            asset(3, "tool-1.0-1.noarch.rpm", 10)?,
        ],
    )?;
    let inventory = inventory_release(&release, &target, &policy);
    let rpm = |name: &str, arch: &str, source: bool| NativePackage {
        ecosystem: Ecosystem::Rpm,
        name: name.to_owned(),
        version: "1.0-1".to_owned(),
        arch: arch.to_owned(),
        source,
    };
    let admitted = admit_release(
        &inventory,
        &[
            inspected(1, b"bin", rpm("tool", "x86_64", false))?,
            // Named like a binary RPM, but it is an SRPM.
            inspected(2, b"src", rpm("tool", "x86_64", true))?,
            inspected(3, b"doc", rpm("tool-doc", "noarch", false))?,
        ],
        &target,
        &policy,
    )?;
    assert_eq!(admitted[0].1, Admission::Eligible);
    assert_eq!(
        admitted[1].1,
        Admission::Rejected(ReasonCode::EPlatformUnsupported)
    );
    assert_eq!(admitted[2].1, Admission::Eligible);
    Ok(())
}

#[test]
fn only_candidates_of_an_offered_release_can_be_admitted() -> TestResult {
    let target = deb_amd64()?;
    let policy = InventoryPolicy::default();
    let release = release(
        "v1.0",
        false,
        vec![
            asset(1, "a_1.0_amd64.deb", 10)?,
            asset(2, "a-linux-amd64.tar.gz", 10)?,
        ],
    )?;
    let inventory = inventory_release(&release, &target, &policy);
    let archive = inspected(2, b"x", package("a", "1.0-1", "amd64"))?;
    assert_eq!(
        admit_release(&inventory, &[archive], &target, &policy),
        Err(InventoryError::NotACandidate(AssetId::new(2)?))
    );
    let twice = inspected(1, b"a", package("a", "1.0-1", "amd64"))?;
    assert_eq!(
        admit_release(&inventory, &[twice.clone(), twice], &target, &policy),
        Err(InventoryError::DuplicateInput(AssetId::new(1)?))
    );

    let flagged = self::release("v1.1", true, vec![asset(1, "a_1.1_amd64.deb", 10)?])?;
    let excluded = inventory_release(&flagged, &target, &policy);
    let package = inspected(1, b"a", package("a", "1.1-1", "amd64"))?;
    assert_eq!(
        admit_release(&excluded, &[package], &target, &policy),
        Err(InventoryError::NotACandidate(AssetId::new(1)?))
    );
    Ok(())
}
