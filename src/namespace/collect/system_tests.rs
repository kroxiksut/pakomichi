// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::namespace::{Claims, OwnName, Relation, check};

/// LIVE, ignored by default: reads the namespace of the system it runs on.
/// Run on each first target after the native metadata is downloaded:
///
/// ```text
/// cargo test --lib namespace::collect::system -- --ignored --nocapture
/// ```
///
/// `PAKOMICHI_NS_EXPECT_FOREIGN` may name a source (APT base URI part or
/// DNF repository ID) that copies the distribution's names but is not
/// authenticated by its key; it must not be counted.
#[test]
#[ignore = "live: reads the native package metadata of this system"]
fn live_namespace_of_this_system() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::temp_dir().join(format!("pakomichi-ns-home-{}", std::process::id()));
    let config = CollectorConfig {
        dnf_home: home.clone(),
        installed_from_pakomichi: BTreeSet::new(),
        pakomichi_sources: BTreeSet::new(),
    };
    let started = Instant::now();
    let collected = collect(&config);
    let _ = fs::remove_dir_all(&home);
    if std::env::var("PAKOMICHI_NS_EXPECT_UNKNOWN").is_ok() {
        // After `dnf clean all` or before `apt update`: unknown, never empty,
        // and named as missing metadata so the remedy is the refresh.
        let error = collected
            .err()
            .ok_or("a namespace without native metadata")?;
        println!("unknown as expected: {error}");
        assert_eq!(
            error.reason_code(),
            crate::error::ReasonCode::ESystemNamespaceUnknown
        );
        assert!(matches!(error, CollectError::Unknown { .. }), "{error}");
        return Ok(());
    }
    let collected = collected?;
    let namespace = &collected.namespace;
    println!(
        "sources {:?}; {} members; {:?}",
        collected.sources,
        namespace.len(),
        started.elapsed()
    );
    if let Ok(foreign) = std::env::var("PAKOMICHI_NS_EXPECT_FOREIGN") {
        assert!(
            !collected
                .sources
                .iter()
                .any(|source| source.contains(&foreign)),
            "a source that only copies the distribution's names was counted: {foreign}"
        );
    }

    let os_release = fs::read_to_string("/etc/os-release")?;
    let deb = profile_for(&os_release).is_some_and(|profile| profile.family == Family::Apt);
    let (libc, shell) = if deb {
        ("libc6", "bash")
    } else {
        ("glibc", "bash")
    };
    for name in [libc, shell] {
        println!("role {name}: {:?}", namespace.role(name));
        assert_eq!(namespace.role(name), Some(PackageRole::OsPart), "{name}");
    }
    for name in ["gh", "netwatch", "curl", "openssl", "systemd", "coreutils"] {
        println!("role {name}: {:?}", namespace.role(name));
    }

    // N-008: a Provides of the C library; N-026: a replacement of it.
    let (provides, replacement, relation) = if deb {
        (
            vec![libc.to_owned()],
            vec![libc.to_owned()],
            Relation::Replaces,
        )
    } else {
        (
            vec!["libc.so.6()(64bit)".to_owned()],
            vec![libc.to_owned()],
            Relation::Obsoletes,
        )
    };
    let claims = Claims {
        name: "sampleapp-glibc".to_owned(),
        provides,
        replacements: replacement,
        replacement_relation: relation,
    };
    let found = check(namespace, &claims);
    println!("N-008/N-026: {found:?}");
    assert_eq!(found.conflicts.len(), 2);
    assert_eq!(
        found.reason_code(),
        Some(crate::error::ReasonCode::ESystemPackageConflict)
    );

    // An ordinary application name is free; a distribution application
    // needs a migration; the shell is a part of the operating system.
    let free = check(
        namespace,
        &Claims {
            name: "pakomichi-sample-app".to_owned(),
            provides: Vec::new(),
            replacements: Vec::new(),
            replacement_relation: relation,
        },
    );
    assert_eq!(free.own_name, OwnName::Free);
    let shell_claim = check(
        namespace,
        &Claims {
            name: shell.to_owned(),
            provides: Vec::new(),
            replacements: Vec::new(),
            replacement_relation: relation,
        },
    );
    assert_eq!(shell_claim.own_name, OwnName::OsPart);

    live_compatibility(&collected, deb, libc)?;
    Ok(())
}

/// P2-008b on live data: N-009 against the C library this system really
/// has, the execution policy read without root, and the other sources.
///
/// `PAKOMICHI_EXPECT_POLICY` (`off`, `on`, `unknown`) states the policy the
/// run expects; without it a system other than Astra Linux must be `off`.
/// `PAKOMICHI_EXPECT_OTHER_SOURCE` names part of a vendor source that must
/// have been read as another source; `PAKOMICHI_VENDOR_ONLY` and
/// `PAKOMICHI_VENDOR_NEWER` are dependencies checked against it.
fn live_compatibility(
    collected: &Collected,
    deb: bool,
    libc: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::compat::{
        self, Distribution, ExecutionPolicy, Origin, OtherReleaseBuilds, Target, policy,
    };
    use crate::family::PackageMetadata;
    use crate::inspect::fixtures::{deb_inspection, rpm_inspection};
    use crate::inventory::{Ecosystem, TargetPlatform};

    let packages = &collected.packages;
    println!(
        "packages: {} names; other sources {:?}; unreadable other sources {:?}",
        packages.len(),
        collected.other_sources,
        collected.other_unknown
    );
    let distribution_libc = packages.versions(Origin::Distribution, libc);
    let installed_libc = packages.versions(Origin::Installed, libc);
    println!("{libc}: distribution {distribution_libc:?}, installed {installed_libc:?}");
    let installed = installed_libc
        .first()
        .ok_or("the C library is not installed")?;
    if let Ok(expected) = std::env::var("PAKOMICHI_EXPECT_OTHER_SOURCE") {
        assert!(
            collected
                .other_sources
                .iter()
                .any(|source| source.contains(&expected)),
            "{expected} was not read as another source"
        );
    }

    let os_release = fs::read_to_string("/etc/os-release")?;
    let value = |key| {
        crate::namespace::collect::parse::os_release_value(&os_release, key).unwrap_or_default()
    };
    let policy = policy::detect();
    println!("execution policy: {policy:?}");
    match std::env::var("PAKOMICHI_EXPECT_POLICY").as_deref() {
        Ok("off") => assert_eq!(policy, ExecutionPolicy::Off),
        Ok("on") => assert_eq!(policy, ExecutionPolicy::On),
        Ok("unknown") => assert_eq!(policy, ExecutionPolicy::Unknown),
        Ok(other) => return Err(format!("unknown PAKOMICHI_EXPECT_POLICY {other}").into()),
        Err(_) if value("ID") != "astra" => assert_eq!(policy, ExecutionPolicy::Off),
        Err(_) => {}
    }

    let (ecosystem, arch) = if deb {
        (Ecosystem::Deb, "amd64")
    } else {
        (Ecosystem::Rpm, "x86_64")
    };
    let target = Target {
        platform: TargetPlatform::new(ecosystem, arch)?,
        distribution: Distribution::from_os_release(value("ID"), value("VERSION_ID")),
        execution_policy: policy,
        other_release_builds: OtherReleaseBuilds::default(),
    };
    let fixture = |requires: &str| -> Result<PackageMetadata, Box<dyn std::error::Error>> {
        if deb {
            let control = format!(
                "Package: sampleapp-compat\nVersion: 1.0\nArchitecture: amd64\n\
                 Maintainer: Pakomichi test fixture <noreply@example.invalid>\n\
                 Depends: {requires}\nDescription: TEST ONLY P2-008b fixture\n"
            );
            Ok(PackageMetadata::from_deb(&deb_inspection(&control)?)?)
        } else {
            let mut builder = rpm::PackageBuilder::new(
                "sampleapp-compat",
                "1.0",
                "MIT OR Apache-2.0",
                "x86_64",
                "TEST ONLY P2-008b fixture",
            );
            builder
                .release("1")
                .using_config(rpm::BuildConfig::v4().compression(rpm::CompressionType::None))
                .requires(rpm::Dependency::any(requires));
            let mut bytes = Vec::new();
            builder.build()?.write(&mut bytes)?;
            Ok(PackageMetadata::from_rpm(&rpm_inspection(&bytes)?)?)
        }
    };
    // N-009: a C library from a release that does not exist yet.
    let newer = if deb {
        "libc6 (>= 2.99)"
    } else {
        "libc.so.6(GLIBC_2.99)(64bit)"
    };
    // The C library this system has: its own version, or a symbol version
    // every glibc since 2.17 provides.
    let upstream = installed.split(['-', '+', '~']).next().unwrap_or(installed);
    let present = if deb {
        format!("libc6 (>= {upstream})")
    } else {
        "libc.so.6(GLIBC_2.17)(64bit)".to_owned()
    };
    let none = BTreeSet::new();
    let held = compat::assess(&target, &fixture(newer)?, &none, packages, false);
    let admitted = compat::assess(&target, &fixture(&present)?, &none, packages, false);
    println!("N-009 {newer}: {:?} {:?}", held.reason_code(), held.hold);
    println!(
        "present {present}: {:?} {:?}",
        admitted.reason_code(),
        admitted.confidence
    );
    if policy == ExecutionPolicy::Off {
        assert_eq!(
            held.reason_code(),
            Some(crate::error::ReasonCode::EDependencyUnsatisfiable)
        );
        assert_eq!(admitted.hold, None);
    } else {
        // N-035: everything is held while the policy is on or unknown.
        for assessment in [&held, &admitted] {
            assert_eq!(
                assessment.reason_code(),
                Some(crate::error::ReasonCode::EExecutionPolicy)
            );
        }
        assert!(compat::activation_allowed(&target).is_err());
    }

    // A configured vendor source: `PAKOMICHI_VENDOR_ONLY` is a dependency
    // only that source offers (admitted); `PAKOMICHI_VENDOR_NEWER` names a
    // package the distribution also ships, at a version only the vendor has
    // (held: a system name is never satisfied by another source).
    if let Ok(dependency) = std::env::var("PAKOMICHI_VENDOR_ONLY") {
        let assessment = compat::assess(&target, &fixture(&dependency)?, &none, packages, false);
        println!("vendor-only {dependency}: {:?}", assessment.hold);
        assert_eq!(assessment.hold, None, "{dependency}");
    }
    if let Ok(dependency) = std::env::var("PAKOMICHI_VENDOR_NEWER") {
        let assessment = compat::assess(&target, &fixture(&dependency)?, &none, packages, false);
        println!("vendor-newer {dependency}: {:?}", assessment.hold);
        assert_eq!(
            assessment.reason_code(),
            Some(crate::error::ReasonCode::EDependencyUnsatisfiable),
            "{dependency}"
        );
    }
    Ok(())
}
