// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

/// Members as capabilities; package roles are set where a test needs them.
fn namespace(members: &[&str]) -> SystemNamespace {
    let mut namespace = SystemNamespace::new();
    for member in members {
        namespace.insert_capability(member);
    }
    namespace
}

fn deb(name: &str, provides: Option<&str>, replaces: Option<&str>) -> Claims {
    Claims {
        name: name.to_owned(),
        provides: deb_list(provides),
        replacements: deb_list(replaces),
        replacement_relation: Relation::Replaces,
    }
}

fn rpm(name: &str, provides: &[&str], obsoletes: &[&str]) -> Claims {
    let names = |entries: &[&str]| {
        entries
            .iter()
            .filter_map(|entry| rpm_relation_name(entry))
            .map(str::to_owned)
            .collect()
    };
    Claims {
        name: name.to_owned(),
        provides: names(provides),
        replacements: names(obsoletes),
        replacement_relation: Relation::Obsoletes,
    }
}

fn conflict(relation: Relation, name: &str) -> Conflict {
    Conflict {
        relation,
        name: name.to_owned(),
    }
}

#[test]
fn relation_names_follow_each_ecosystem() {
    for (entry, name) in [
        ("foo", "foo"),
        ("foo (>= 1.0)", "foo"),
        ("foo(=1)", "foo"),
        ("  foo:any  ", "foo"),
        ("libc6 (= 2.36-9)", "libc6"),
    ] {
        assert_eq!(deb_relation_name(entry), Some(name), "{entry}");
    }
    assert_eq!(deb_relation_name("  "), None);
    for (entry, name) in [
        ("glibc", "glibc"),
        ("glibc >= 2.34", "glibc"),
        ("libc.so.6()(64bit)", "libc.so.6()(64bit)"),
        ("config(openssl) = 1:3.0.7", "config(openssl)"),
        ("/usr/bin/ssh", "/usr/bin/ssh"),
    ] {
        assert_eq!(rpm_relation_name(entry), Some(name), "{entry}");
    }
}

#[test]
fn n_008_a_provides_of_the_c_library_is_held() {
    // DEB: `sampleapp-glibc` with `Provides: libc6` (R-001 N-008).
    let debian = namespace(&["libc6", "libc6-dev", "bash"]);
    let claims = deb(
        "sampleapp-glibc",
        Some("libc6 (= 2.99), sampleapp-helper"),
        None,
    );
    let found = check(&debian, &claims);
    assert_eq!(found.conflicts, vec![conflict(Relation::Provides, "libc6")]);
    assert_eq!(
        found.reason_code(),
        Some(ReasonCode::ESystemPackageConflict)
    );
    assert_eq!(found.own_name, OwnName::Free);

    // RPM: the package name, a soname, and a file provide all count.
    let alma = namespace(&[
        "glibc",
        "libc.so.6()(64bit)",
        "/usr/bin/ssh",
        "openssh-clients",
    ]);
    for provide in ["glibc = 2.99", "libc.so.6()(64bit)", "/usr/bin/ssh"] {
        let found = check(&alma, &rpm("sampleapp-glibc", &[provide], &[]));
        assert_eq!(
            found.reason_code(),
            Some(ReasonCode::ESystemPackageConflict),
            "{provide}"
        );
    }
}

#[test]
fn n_026_replaces_and_obsoletes_are_held_whatever_their_version() {
    let debian = namespace(&["openssl", "libssl3"]);
    for replaces in [
        "libssl3",
        "libssl3 (<< 0.1)",
        "libssl3 (>= 99)",
        "libssl3:amd64",
    ] {
        let found = check(&debian, &deb("tool", None, Some(replaces)));
        assert_eq!(
            found.conflicts,
            vec![conflict(Relation::Replaces, "libssl3")],
            "{replaces}"
        );
    }
    let alma = namespace(&["openssl-libs"]);
    for obsoletes in ["openssl-libs", "openssl-libs < 0.1", "openssl-libs >= 99:1"] {
        let found = check(&alma, &rpm("tool", &[], &[obsoletes]));
        assert_eq!(
            found.conflicts,
            vec![conflict(Relation::Obsoletes, "openssl-libs")],
            "{obsoletes}"
        );
    }
}

#[test]
fn a_stray_alternative_does_not_hide_a_system_name() {
    let debian = namespace(&["libc6"]);
    let found = check(&debian, &deb("tool", Some("tool-data | libc6"), None));
    assert_eq!(found.conflicts, vec![conflict(Relation::Provides, "libc6")]);
}

#[test]
fn ordinary_application_packages_pass() {
    let debian = namespace(&["libc6", "bash", "coreutils"]);
    let found = check(
        &debian,
        &deb("netwatch", Some("netwatch-tui"), Some("netwatch-old")),
    );
    assert_eq!(found, Check::default());
    assert_eq!(found.reason_code(), None);

    let fedora = namespace(&["glibc", "bash"]);
    // RPM's automatic self-provides are not conflicts.
    let found = check(
        &fedora,
        &rpm(
            "netwatch",
            &["netwatch = 0.6.1-1", "netwatch(x86-64) = 0.6.1-1"],
            &[],
        ),
    );
    assert_eq!(found, Check::default());
}

#[test]
fn a_distribution_application_with_the_same_name_needs_a_migration() {
    // `gh` is packaged by Fedora too: not a conflict, but the artifact
    // stays observing until an explicit migration (ADR-022 point 3).
    let mut fedora = namespace(&["gh(x86-64)", "glibc"]);
    fedora.insert_package("gh", PackageRole::DistributionApplication);
    let found = check(
        &fedora,
        &rpm("gh", &["gh = 2.102.1-1", "gh(x86-64) = 2.102.1-1"], &[]),
    );
    assert!(found.conflicts.is_empty());
    assert_eq!(found.own_name, OwnName::NeedsMigration);
    assert_eq!(found.reason_code(), None);

    // A foreign package claiming another package's arch provide is not a
    // self-provide.
    let found = check(&fedora, &rpm("evil", &["gh(x86-64)"], &[]));
    assert_eq!(
        found.conflicts,
        vec![conflict(Relation::Provides, "gh(x86-64)")]
    );
}

#[test]
fn a_part_of_the_operating_system_with_the_same_name_is_held() {
    let mut debian = SystemNamespace::new();
    debian.insert_package("openssl", PackageRole::OsPart);
    let found = check(&debian, &deb("openssl", None, None));
    assert!(found.conflicts.is_empty());
    assert_eq!(found.own_name, OwnName::OsPart);
    assert_eq!(
        found.reason_code(),
        Some(ReasonCode::ESystemPackageConflict)
    );
}

#[test]
fn packages_installed_from_elsewhere_are_protected_too() {
    // A program from a PPA, COPR, or installed by hand cannot be replaced
    // or obsoleted silently, and its name needs a migration.
    let mut system = SystemNamespace::new();
    system.insert_package("netwatch", PackageRole::InstalledElsewhere);
    let found = check(&system, &rpm("netwatch-ng", &[], &["netwatch < 1.0"]));
    assert_eq!(
        found.conflicts,
        vec![conflict(Relation::Obsoletes, "netwatch")]
    );
    assert_eq!(
        found.reason_code(),
        Some(ReasonCode::ESystemPackageConflict)
    );
    let found = check(&system, &deb("netwatch", None, None));
    assert_eq!(found.own_name, OwnName::NeedsMigration);
}

#[test]
fn a_name_keeps_its_strongest_role() {
    let mut system = SystemNamespace::new();
    system.insert_package("openssl", PackageRole::InstalledElsewhere);
    system.insert_package("openssl", PackageRole::OsPart);
    system.insert_package("openssl", PackageRole::DistributionApplication);
    assert_eq!(system.role("openssl"), Some(PackageRole::OsPart));
    assert!(system.contains("openssl"));
    assert_eq!(system.role("absent"), None);
}

#[test]
fn every_conflict_is_reported_once_in_a_stable_order() {
    let debian = namespace(&["libc6", "libssl3"]);
    let found = check(
        &debian,
        &deb("tool", Some("libssl3, libc6, libc6 (= 2)"), Some("libc6")),
    );
    assert_eq!(
        found.conflicts,
        vec![
            conflict(Relation::Provides, "libc6"),
            conflict(Relation::Provides, "libssl3"),
            conflict(Relation::Replaces, "libc6"),
        ]
    );
}
