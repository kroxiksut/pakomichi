// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

const DAY: u64 = 86_400;
/// 2026-10-23T10:00:00Z, a Friday.
const NOW: u64 = 1_792_749_600;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn control(text: &str) -> DebControl {
    match DebControl::from_text(text) {
        Ok(control) => control,
        Err(error) => panic!("fixture control: {error}"),
    }
}

fn package(name: &str, version: &str, architecture: &str, bytes: &[u8]) -> AptPackage {
    AptPackage {
        control: control(&format!(
            "Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n\
             Maintainer: Fixture <fixture@example.invalid>\nDescription: fixture\n long text\n .\n more\n"
        )),
        object: ExpectedObject::new(Sha256Digest::of(bytes), bytes.len() as u64),
    }
}

fn repo() -> AptRepository {
    match AptRepository::new("pakomichi-netwatch-strict", &["amd64"]) {
        Ok(repo) => repo,
        Err(error) => panic!("fixture repository: {error}"),
    }
}

fn fresh() -> Freshness {
    Freshness {
        confirmed_at: NOW - 3600,
        max_freshness: 7 * DAY,
    }
}

fn files(indexes: &AptIndexes) -> GenerationFiles {
    GenerationFiles {
        indexes: indexes.indexes.iter().cloned().collect(),
        pool: indexes.pool.iter().cloned().collect(),
    }
}

fn release_field(indexes: &AptIndexes, name: &str) -> Option<String> {
    String::from_utf8_lossy(&indexes.release)
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")).map(str::to_owned))
}

#[test]
fn a_control_field_that_names_another_file_is_refused() {
    // A package whose control file already says where its bytes are could
    // point APT at another package's pool file or digest.
    for field in [
        "Filename: pool/0000/other.deb",
        "filename: pool/0000/other.deb",
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000",
        "Size: 1",
        "MD5sum: 00000000000000000000000000000000",
    ] {
        let mut hostile = package("netwatch", "0.35.4", "amd64", b"deb");
        hostile.control = control(&format!(
            "Package: netwatch\nVersion: 0.35.4\nArchitecture: amd64\n{field}\n"
        ));
        let error = build_indexes(&repo(), &[hostile], fresh(), NOW).err();
        assert!(
            matches!(error, Some(AptError::IndexFieldInControl { .. })),
            "{field}: {error:?}"
        );
        assert_eq!(
            error.map(|error| error.reason()),
            Some(ReasonCode::EArtifactMalformed)
        );
    }
}

#[test]
fn valid_until_is_the_confirmed_freshness_not_the_signing_time() -> TestResult {
    // Synchronization last confirmed three days ago: signing now must not
    // give the old data a fresh week (ADR-010, ADR-024 point 3).
    let freshness = Freshness {
        confirmed_at: NOW - 3 * DAY,
        max_freshness: 7 * DAY,
    };
    let indexes = build_indexes(&repo(), &[], freshness, NOW)?;
    assert_eq!(indexes.valid_until, NOW + 4 * DAY);
    assert_eq!(
        release_field(&indexes, "Valid-Until").as_deref(),
        Some("Tue, 27 Oct 2026 10:00:00 UTC")
    );
    assert_eq!(
        release_field(&indexes, "Date").as_deref(),
        Some("Fri, 23 Oct 2026 10:00:00 UTC")
    );
    Ok(())
}

#[test]
fn a_stale_confirmation_is_never_signed_as_fresh() {
    let stale = Freshness {
        confirmed_at: NOW - 7 * DAY,
        max_freshness: 7 * DAY,
    };
    let error = build_indexes(&repo(), &[], stale, NOW).err();
    assert!(matches!(error, Some(AptError::Stale { .. })), "{error:?}");
    assert_eq!(
        error.map(|error| error.reason()),
        Some(ReasonCode::ESourceStale)
    );
    // A clock that jumped back behind the last confirmation.
    let ahead = Freshness {
        confirmed_at: NOW + 60,
        max_freshness: 7 * DAY,
    };
    assert!(matches!(
        build_indexes(&repo(), &[], ahead, NOW),
        Err(AptError::ConfirmedInFuture { .. })
    ));
}

#[test]
fn two_files_of_one_version_are_ambiguous_however_the_version_is_spelled() {
    // APT merges equal versions and picks one by source order (R-001), so
    // equal-by-dpkg spellings count as one version.
    for (left, right) in [
        ("0.35.4", "0.35.4"),
        ("0.35.4", "0:0.35.4"),
        ("1.0", "1.0-0"),
    ] {
        let packages = [
            package("netwatch", left, "amd64", b"first"),
            package("netwatch", right, "amd64", b"second"),
        ];
        let error = build_indexes(&repo(), &packages, fresh(), NOW).err();
        assert!(
            matches!(error, Some(AptError::Ambiguous { .. })),
            "{left} / {right}: {error:?}"
        );
    }
    // The same bytes offered twice are one entry, not a conflict.
    let same = [
        package("netwatch", "0.35.4", "amd64", b"same"),
        package("netwatch", "0.35.4", "amd64", b"same"),
    ];
    let indexes = match build_indexes(&repo(), &same, fresh(), NOW) {
        Ok(indexes) => indexes,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(indexes.pool.len(), 1);
}

#[test]
fn every_stanza_names_the_stored_bytes_and_the_generation_checks() -> TestResult {
    let packages = [
        package("netwatch", "1:0.35.4-2", "amd64", b"netwatch bytes"),
        package("netwatch-data", "0.35.4", "all", b"data bytes"),
    ];
    let repo = AptRepository::new("pakomichi-netwatch-strict", &["amd64", "arm64"])?;
    let indexes = build_indexes(&repo, &packages, fresh(), NOW)?;
    let digest = Sha256Digest::of(b"netwatch bytes").to_hex();
    let amd64 = String::from_utf8(indexes.indexes[0].1.clone())?;
    assert!(
        amd64.contains(&format!(
            "Filename: pool/{digest}/netwatch_0.35.4-2_amd64.deb\nSize: 14\nSHA256: {digest}\n"
        )),
        "{amd64}"
    );
    // The description keeps its continuation lines verbatim.
    assert!(amd64.contains("Description: fixture\n long text\n .\n more\n"));
    // `all` is listed for every architecture; amd64 only for amd64.
    let arm64 = String::from_utf8(indexes.indexes[1].1.clone())?;
    assert!(arm64.contains("Package: netwatch-data") && !arm64.contains("Package: netwatch\n"));
    assert_eq!(
        release_field(&indexes, "Acquire-By-Hash").as_deref(),
        Some("yes")
    );
    assert_eq!(
        release_field(&indexes, "Origin").as_deref(),
        Some("Pakomichi")
    );
    check_generation(
        &repo,
        &indexes.release,
        &files(&indexes),
        indexes.valid_until,
        NOW,
    )?;
    Ok(())
}

#[test]
fn a_package_for_an_architecture_the_repository_does_not_serve_is_refused() {
    let error = build_indexes(
        &repo(),
        &[package("netwatch", "0.35.4", "arm64", b"arm")],
        fresh(),
        NOW,
    )
    .err();
    assert!(
        matches!(error, Some(AptError::ArchitectureNotServed { .. })),
        "{error:?}"
    );
}

fn built() -> (AptRepository, AptIndexes) {
    let packages = [
        package("netwatch", "0.35.4", "amd64", b"netwatch bytes"),
        package("netwatch-data", "0.35.4", "all", b"data bytes"),
    ];
    match build_indexes(&repo(), &packages, fresh(), NOW) {
        Ok(indexes) => (repo(), indexes),
        Err(error) => panic!("{error}"),
    }
}

fn refused(
    repo: &AptRepository,
    release: &[u8],
    files: &GenerationFiles,
    valid_until: u64,
) -> bool {
    matches!(
        check_generation(repo, release, files, valid_until, NOW),
        Err(AptError::Check(_))
    )
}

#[test]
fn a_packages_index_changed_after_release_is_refused() {
    let (repo, indexes) = built();
    let mut tampered = files(&indexes);
    // A well-formed index with one more dependency than was signed.
    if let Some(bytes) = tampered.indexes.values_mut().next() {
        let text = String::from_utf8_lossy(bytes).replacen(
            "Maintainer:",
            "Depends: injected-helper\nMaintainer:",
            1,
        );
        *bytes = text.into_bytes();
    }
    assert!(refused(
        &repo,
        &indexes.release,
        &tampered,
        indexes.valid_until
    ));
}

#[test]
fn a_stanza_that_points_at_other_bytes_is_refused() {
    let (repo, indexes) = built();
    // The pool file is served with other bytes than its stanza names.
    let mut swapped = files(&indexes);
    if let Some(object) = swapped.pool.values_mut().next() {
        *object = ExpectedObject::new(Sha256Digest::of(b"other"), object.size);
    }
    assert!(refused(
        &repo,
        &indexes.release,
        &swapped,
        indexes.valid_until
    ));
    // A stanza whose file is not served at all.
    let mut missing = files(&indexes);
    let first = missing.pool.keys().next().cloned();
    if let Some(first) = first {
        missing.pool.remove(&first);
    }
    assert!(refused(
        &repo,
        &indexes.release,
        &missing,
        indexes.valid_until
    ));
    // A served file that no index lists.
    let mut extra = files(&indexes);
    if let Ok(orphan) = RepoPath::new(&format!(
        "pool/{}/orphan_1_amd64.deb",
        Sha256Digest::of(b"orphan").to_hex()
    )) {
        extra
            .pool
            .insert(orphan, ExpectedObject::new(Sha256Digest::of(b"orphan"), 6));
    }
    assert!(refused(
        &repo,
        &indexes.release,
        &extra,
        indexes.valid_until
    ));
}

#[test]
fn a_release_of_another_repository_or_another_time_is_refused() {
    let (repo, indexes) = built();
    let files = files(&indexes);
    // Every logical repository is signed with the same local key, so APT
    // would accept the Release of the Pinned repository in place of the
    // Strict one; the check must not.
    let release = String::from_utf8_lossy(&indexes.release).into_owned();
    // Each field on its own: APT pins match `o=` and `l=` (P3-002a).
    for (field, other) in [
        ("Label", "pakomichi-netwatch-pinned"),
        ("Suite", "pakomichi-netwatch-pinned"),
        ("Codename", "pakomichi-netwatch-pinned"),
        ("Origin", "Debian"),
    ] {
        let line = release
            .lines()
            .find(|line| line.starts_with(&format!("{field}: ")))
            .unwrap_or_default()
            .to_owned();
        let other_level = release.replace(&line, &format!("{field}: {other}"));
        assert_ne!(other_level, release, "{field}");
        assert!(
            refused(&repo, other_level.as_bytes(), &files, indexes.valid_until),
            "{field}"
        );
    }
    // An older Release signed again (a replay) states another validity.
    assert!(refused(
        &repo,
        &indexes.release,
        &files,
        indexes.valid_until + 1
    ));
    // Without Acquire-By-Hash APT mixes generations (R-004 G3/G4).
    let no_by_hash = release.replace("Acquire-By-Hash: yes\n", "");
    assert!(refused(
        &repo,
        no_by_hash.as_bytes(),
        &files,
        indexes.valid_until
    ));
    // Expired at the time of the check.
    assert!(matches!(
        check_generation(
            &repo,
            &indexes.release,
            &files,
            indexes.valid_until,
            indexes.valid_until
        ),
        Err(AptError::Check(_))
    ));
}

#[test]
fn an_index_served_but_not_listed_is_refused() {
    let (repo, indexes) = built();
    let mut extra = files(&indexes);
    if let Ok(unlisted) =
        RepoPath::new("dists/pakomichi-netwatch-strict/main/binary-arm64/Packages")
    {
        extra.indexes.insert(unlisted, Vec::new());
    }
    assert!(refused(
        &repo,
        &indexes.release,
        &extra,
        indexes.valid_until
    ));
}

#[test]
fn release_dates_are_the_form_apt_reads_and_nothing_else_is_accepted() -> TestResult {
    assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 UTC");
    assert_eq!(rfc2822(951_782_400), "Tue, 29 Feb 2000 00:00:00 UTC");
    assert_eq!(rfc2822(NOW), "Fri, 23 Oct 2026 10:00:00 UTC");
    assert_eq!(iso8601(NOW), "2026-10-23T10:00:00Z");
    for seconds in [0, 951_782_400, NOW, NOW + 7 * DAY + 59] {
        assert_eq!(parse_rfc2822(&rfc2822(seconds))?, seconds);
    }
    for text in [
        "Thu, 23 Oct 2026 10:00:00 UTC",
        "Fri, 23 Oct 2026 10:00:00 GMT",
        "Fri, 23 Oct 2026 10:00 UTC",
        "Mon, 30 Feb 2026 10:00:00 UTC",
        "Fri,  23 Oct 2026 10:00:00 UTC",
    ] {
        assert!(parse_rfc2822(text).is_err(), "{text}");
    }
    Ok(())
}

#[test]
fn a_label_or_architecture_that_cannot_name_a_path_is_refused() {
    for label in ["", "Pakomichi", "a/b", "-x", &"x".repeat(65)] {
        assert!(AptRepository::new(label, &["amd64"]).is_err(), "{label:?}");
    }
    for architectures in [&[][..], &["all"][..], &["amd64/x"][..]] {
        assert!(AptRepository::new("pakomichi-x-strict", architectures).is_err());
    }
}

#[test]
fn the_source_is_low_priority_without_any_preferences_file() {
    // Until a name is activated with a 990 pin, nothing from the source may
    // displace a version from another source on an ordinary upgrade; the
    // repository itself says so, so a missing or deleted preferences file
    // cannot raise it to the default 500 (backports semantics, priority 100).
    let (repo, indexes) = built();
    assert_eq!(
        release_field(&indexes, "NotAutomatic").as_deref(),
        Some("yes")
    );
    assert_eq!(
        release_field(&indexes, "ButAutomaticUpgrades").as_deref(),
        Some("yes")
    );
    let release = String::from_utf8_lossy(&indexes.release).into_owned();
    for line in ["NotAutomatic: yes\n", "ButAutomaticUpgrades: yes\n"] {
        let without = release.replace(line, "");
        assert!(
            refused(
                &repo,
                without.as_bytes(),
                &files(&indexes),
                indexes.valid_until
            ),
            "{line}"
        );
    }
}
