// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;
use std::error::Error;

use rpm::{BuildConfig, CompressionType, Dependency, PackageBuilder};

use super::*;
use crate::inspect::fixtures::{deb_inspection, rpm_inspection};

type TestResult = Result<(), Box<dyn Error>>;

fn deb(
    name: &str,
    version: &str,
    arch: &str,
    extra: &str,
) -> Result<PackageMetadata, Box<dyn Error>> {
    let control = format!(
        "Package: {name}\nVersion: {version}\nArchitecture: {arch}\n\
         Maintainer: Pakomichi test fixture <noreply@example.invalid>\n{extra}\
         Description: TEST ONLY P2-008a compatibility fixture\n"
    );
    Ok(PackageMetadata::from_deb(&deb_inspection(&control)?)?)
}

fn rpm(
    name: &str,
    version: &str,
    release: &str,
    edit: impl FnOnce(&mut PackageBuilder),
) -> Result<PackageMetadata, Box<dyn Error>> {
    let mut builder = PackageBuilder::new(
        name,
        version,
        "MIT OR Apache-2.0",
        "x86_64",
        "TEST ONLY P2-008a compatibility fixture",
    );
    builder
        .release(release)
        .using_config(BuildConfig::v4().compression(CompressionType::None));
    edit(&mut builder);
    let mut bytes = Vec::new();
    builder.build()?.write(&mut bytes)?;
    Ok(PackageMetadata::from_rpm(&rpm_inspection(&bytes)?)?)
}

fn target(
    ecosystem: Ecosystem,
    arch: &str,
    id: &str,
    version_id: &str,
) -> Result<Target, Box<dyn Error>> {
    Ok(Target {
        platform: TargetPlatform::new(ecosystem, arch)?,
        distribution: Distribution::from_os_release(id, version_id),
        execution_policy: ExecutionPolicy::Off,
        other_release_builds: OtherReleaseBuilds::default(),
    })
}

fn debian12() -> Result<Target, Box<dyn Error>> {
    target(Ecosystem::Deb, "amd64", "debian", "12")
}

fn alma9() -> Result<Target, Box<dyn Error>> {
    target(Ecosystem::Rpm, "x86_64", "almalinux", "9.8")
}

/// What a Debian 12 system offers: the C library of bookworm and libpcap.
fn debian12_system() -> SystemPackages {
    let mut system = SystemPackages::new(Ecosystem::Deb);
    system.add_package(Origin::Distribution, "libc6", "2.36-9+deb12u10");
    system.add_package(Origin::Distribution, "libpcap0.8", "1.10.3-1");
    system.add_package(Origin::Installed, "libssl3", "3.0.17-1~deb12u2");
    system
}

/// What an AlmaLinux 9 system offers: glibc 2.34 with its symbol versions.
fn alma9_system() -> SystemPackages {
    let mut system = SystemPackages::new(Ecosystem::Rpm);
    system.add_package(Origin::Distribution, "glibc", "2.34-168.el9_6.20");
    for symbol in ["GLIBC_2.2.5", "GLIBC_2.17", "GLIBC_2.34"] {
        system.add_provide(
            Origin::Distribution,
            &format!("libc.so.6({symbol})(64bit)"),
            None,
        );
    }
    system.add_provide(Origin::Distribution, "libc.so.6()(64bit)", None);
    system
}

fn none() -> BTreeSet<String> {
    BTreeSet::new()
}

#[test]
fn n009_a_c_library_newer_than_the_system_is_held() -> TestResult {
    let package = deb(
        "netwatch",
        "0.36.0",
        "amd64",
        "Depends: libc6 (>= 2.38), libpcap0.8 (>= 1.5.1)\n",
    )?;
    let assessment = assess(&debian12()?, &package, &none(), &debian12_system(), false);

    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );
    assert_eq!(
        assessment.hold,
        Some(CompatHold::Dependency {
            clause: "libc6 (>= 2.38)".to_owned()
        })
    );
    assert!(!assessment.declared_dependency_satisfiable);
    assert_eq!(assessment.confidence, Confidence::Low);
    Ok(())
}

#[test]
fn a_test_record_never_overrides_a_dependency_hold() -> TestResult {
    let package = deb("netwatch", "0.36.0", "amd64", "Depends: libc6 (>= 2.38)\n")?;
    let assessment = assess(&debian12()?, &package, &none(), &debian12_system(), true);

    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );
    assert!(!assessment.platform_tested);
    assert_eq!(assessment.confidence, Confidence::Low);
    Ok(())
}

#[test]
fn a_family_that_provides_the_c_library_does_not_satisfy_a_newer_one() -> TestResult {
    // The family claims libc6 itself (the namespace check holds that member
    // separately); a dependency on a newer libc6 must still be checked
    // against the system, never waved through as the family's own.
    let package = deb("netwatch", "0.36.0", "amd64", "Depends: libc6 (>= 2.38)\n")?;
    let family_offers: BTreeSet<String> = ["netwatch", "libc6"].map(str::to_owned).into();
    let assessment = assess(
        &debian12()?,
        &package,
        &family_offers,
        &debian12_system(),
        false,
    );

    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );
    Ok(())
}

#[test]
fn a_dependency_only_the_family_offers_is_left_to_the_family_admission() -> TestResult {
    let package = deb(
        "app",
        "1.0-1",
        "amd64",
        "Depends: app-common (= 1.0-1), libc6 (>= 2.34)\n",
    )?;
    let family_offers: BTreeSet<String> = ["app", "app-common"].map(str::to_owned).into();
    let assessment = assess(
        &debian12()?,
        &package,
        &family_offers,
        &debian12_system(),
        false,
    );

    assert_eq!(assessment.hold, None);
    assert!(assessment.declared_dependency_satisfiable);
    Ok(())
}

#[test]
fn an_ordinary_system_dependency_is_admitted() -> TestResult {
    let package = deb(
        "netwatch",
        "0.35.4",
        "amd64",
        "Depends: libc6 (>= 2.34), libpcap0.8 (>= 1.5.1)\n",
    )?;
    let assessment = assess(&debian12()?, &package, &none(), &debian12_system(), false);

    assert_eq!(assessment.hold, None);
    assert!(assessment.format_arch_ok);
    assert!(assessment.declared_dependency_satisfiable);
    assert_eq!(assessment.build, BuildClaim::Generic);
    assert_eq!(assessment.confidence, Confidence::DependenciesSatisfiable);
    assert!(!assessment.platform_tested);
    Ok(())
}

#[test]
fn versions_are_compared_natively_not_as_text() -> TestResult {
    // As text "u10" sorts before "u9"; dpkg says u10 is newer.
    let package = deb(
        "app",
        "1.0",
        "amd64",
        "Depends: libc6 (>= 2.36-9+deb12u9)\n",
    )?;
    let assessment = assess(&debian12()?, &package, &none(), &debian12_system(), false);
    assert_eq!(assessment.hold, None);

    let tilde = deb("app", "1.0", "amd64", "Depends: libssl3 (>= 3.0.17-1)\n")?;
    // `3.0.17-1~deb12u2` is older than `3.0.17-1` under dpkg rules.
    let assessment = assess(&debian12()?, &tilde, &none(), &debian12_system(), false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );
    Ok(())
}

#[test]
fn an_alternative_the_system_offers_satisfies_the_clause() -> TestResult {
    let package = deb("app", "1.0", "amd64", "Depends: libfoo2 | libpcap0.8\n")?;
    let assessment = assess(&debian12()?, &package, &none(), &debian12_system(), false);
    assert_eq!(assessment.hold, None);

    let missing = deb("app", "1.0", "amd64", "Depends: libfoo2 | libbar3\n")?;
    let assessment = assess(&debian12()?, &missing, &none(), &debian12_system(), false);
    assert_eq!(
        assessment.hold,
        Some(CompatHold::Dependency {
            clause: "libfoo2 | libbar3".to_owned()
        })
    );
    Ok(())
}

#[test]
fn n009_on_rpm_a_glibc_symbol_version_the_system_lacks_is_held() -> TestResult {
    let package = rpm("netwatch", "0.36.0", "1", |builder| {
        builder.requires(Dependency::any("libc.so.6(GLIBC_2.38)(64bit)"));
    })?;
    let assessment = assess(&alma9()?, &package, &none(), &alma9_system(), false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );

    let older = rpm("netwatch", "0.35.4", "1", |builder| {
        builder.requires(Dependency::any("libc.so.6(GLIBC_2.34)(64bit)"));
        builder.requires(Dependency::greater_eq("glibc", "2.34"));
    })?;
    let assessment = assess(&alma9()?, &older, &none(), &alma9_system(), false);
    assert_eq!(assessment.hold, None);
    Ok(())
}

#[test]
fn n035_an_execution_policy_that_is_on_holds_everything() -> TestResult {
    let mut target = target(Ecosystem::Deb, "amd64", "astra", "1.8_x86-64")?;
    target.execution_policy = ExecutionPolicy::On;
    let package = deb("app", "1.0", "all", "")?;
    let assessment = assess(&target, &package, &none(), &debian12_system(), true);

    assert_eq!(assessment.reason_code(), Some(ReasonCode::EExecutionPolicy));
    assert!(
        !assessment.platform_tested,
        "a test record never overrides a hold"
    );
    assert_eq!(
        activation_allowed(&target),
        Err(CompatHold::ExecutionPolicy(ExecutionPolicy::On))
    );
    Ok(())
}

#[test]
fn n035_an_execution_policy_that_cannot_be_ruled_out_is_not_off() -> TestResult {
    let mut target = target(Ecosystem::Deb, "amd64", "astra", "1.8_x86-64")?;
    target.execution_policy = ExecutionPolicy::Unknown;
    let package = deb("app", "1.0", "all", "")?;

    assert_eq!(
        assess(&target, &package, &none(), &debian12_system(), false).reason_code(),
        Some(ReasonCode::EExecutionPolicy)
    );
    assert!(activation_allowed(&target).is_err());
    target.execution_policy = ExecutionPolicy::Off;
    assert_eq!(activation_allowed(&target), Ok(()));
    Ok(())
}

#[test]
fn a_build_for_another_distribution_is_held() -> TestResult {
    let fedora = rpm("app", "1.0", "1.fc44", |_| {})?;
    let assessment = assess(&alma9()?, &fedora, &none(), &alma9_system(), false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EPlatformUnsupported)
    );
    assert_eq!(
        assessment.hold,
        Some(CompatHold::OtherDistribution {
            tag: ".fc44".to_owned()
        })
    );

    // Astra Linux 1.8 is based on Debian 12, but Ubuntu is foreign to it.
    let astra = target(Ecosystem::Deb, "amd64", "astra", "1.8_x86-64")?;
    let ubuntu_on_astra = deb("app", "1.0-1ubuntu1~24.04", "amd64", "")?;
    let assessment = assess(&astra, &ubuntu_on_astra, &none(), &debian12_system(), false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EPlatformUnsupported)
    );

    let ubuntu = deb("app", "1.0-1ubuntu1~22.04", "amd64", "")?;
    let assessment = assess(&debian12()?, &ubuntu, &none(), &debian12_system(), false);
    assert_eq!(
        assessment.hold,
        Some(CompatHold::OtherDistribution {
            tag: "ubuntu".to_owned()
        })
    );
    Ok(())
}

#[test]
fn a_build_for_another_release_follows_the_setting() -> TestResult {
    let bullseye = deb(
        "app",
        "1.0-1~bpo11+1",
        "amd64",
        "Depends: libc6 (>= 2.31)\n",
    )?;
    let mut target = debian12()?;
    let assessment = assess(&target, &bullseye, &none(), &debian12_system(), false);
    assert_eq!(assessment.hold, None);
    assert_eq!(
        assessment.build,
        BuildClaim::OtherRelease {
            tag: "bpo11".to_owned()
        }
    );
    assert_eq!(
        assessment.confidence,
        Confidence::Low,
        "another release is never more than low"
    );

    target.other_release_builds = OtherReleaseBuilds::Hold;
    let assessment = assess(&target, &bullseye, &none(), &debian12_system(), false);
    assert_eq!(
        assessment.hold,
        Some(CompatHold::OtherRelease {
            tag: "bpo11".to_owned()
        })
    );

    let el8 = rpm("app", "1.0", "1.el8", |_| {})?;
    let assessment = assess(&alma9()?, &el8, &none(), &alma9_system(), false);
    assert_eq!(assessment.hold, None);
    assert!(!assessment.platform_claimed);
    Ok(())
}

#[test]
fn a_build_for_the_target_is_claimed_but_not_tested() -> TestResult {
    let el9 = rpm("app", "1.0", "1.el9_4", |builder| {
        builder.requires(Dependency::greater_eq("glibc", "2.34"));
    })?;
    let assessment = assess(&alma9()?, &el9, &none(), &alma9_system(), false);
    assert_eq!(
        assessment.build,
        BuildClaim::Target {
            tag: ".el9_4".to_owned()
        }
    );
    assert!(assessment.platform_claimed);
    assert!(!assessment.platform_tested);
    assert_eq!(assessment.confidence, Confidence::Claimed);

    let assessment = assess(&alma9()?, &el9, &none(), &alma9_system(), true);
    assert!(assessment.platform_tested);
    assert_eq!(assessment.confidence, Confidence::Tested);
    Ok(())
}

#[test]
fn a_rebuild_keeps_its_origin_tag_but_the_target_tag_decides() -> TestResult {
    let astra = target(Ecosystem::Deb, "amd64", "astra", "1.8_x86-64")?;
    let rebuild = deb("app", "2.36-9+deb12u4+astra1", "amd64", "")?;
    let assessment = assess(&astra, &rebuild, &none(), &debian12_system(), false);
    // Not another distribution: the Astra tag is present, its release is not.
    assert_eq!(assessment.hold, None);
    assert_eq!(
        assessment.build,
        BuildClaim::OtherRelease {
            tag: "astra".to_owned()
        }
    );
    Ok(())
}

#[test]
fn words_that_only_look_like_tags_are_not_claims() -> TestResult {
    for version in ["1.0-1.elfutils", "2.0-3.fcgi"] {
        let package = rpm(
            "app",
            "1.0",
            version.rsplit_once('-').map_or("1", |(_, r)| r),
            |_| {},
        )?;
        assert_eq!(
            build_claim(Ecosystem::Rpm, package.version(), &alma9()?.distribution),
            BuildClaim::Generic,
            "{version}"
        );
    }
    for version in ["1.0-1debian1", "1.0-bookworms1", "3.1-1nobleman"] {
        assert_eq!(
            build_claim(Ecosystem::Deb, version, &debian12()?.distribution),
            BuildClaim::Generic,
            "{version}"
        );
    }
    Ok(())
}

#[test]
fn no_data_about_the_system_holds_the_artifact() -> TestResult {
    let package = deb("app", "1.0", "amd64", "Depends: libc6 (>= 2.34)\n")?;
    let empty = SystemPackages::new(Ecosystem::Deb);
    let assessment = assess(&debian12()?, &package, &none(), &empty, false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::ESystemNamespaceUnknown)
    );

    // Data of another ecosystem is no data about this one.
    let assessment = assess(&debian12()?, &package, &none(), &alma9_system(), false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::ESystemNamespaceUnknown)
    );
    Ok(())
}

#[test]
fn a_foreign_architecture_or_ecosystem_is_held() -> TestResult {
    let arm = deb("app", "1.0", "arm64", "")?;
    let assessment = assess(&debian12()?, &arm, &none(), &debian12_system(), false);
    assert!(!assessment.format_arch_ok);
    assert_eq!(
        assessment.hold,
        Some(CompatHold::Architecture {
            arch: "arm64".to_owned()
        })
    );

    let universal = deb("app", "1.0", "all", "")?;
    assert_eq!(
        assess(&debian12()?, &universal, &none(), &debian12_system(), false).hold,
        None
    );

    let rpm_on_debian = rpm("app", "1.0", "1", |_| {})?;
    let assessment = assess(
        &debian12()?,
        &rpm_on_debian,
        &none(),
        &debian12_system(),
        false,
    );
    assert_eq!(assessment.hold, Some(CompatHold::Ecosystem(Ecosystem::Rpm)));
    Ok(())
}

#[test]
fn a_rich_dependency_is_not_evaluated_and_lowers_the_confidence() -> TestResult {
    let package = rpm("app", "1.0", "1", |builder| {
        builder.requires(Dependency::any("(glibc >= 2.34 or musl)"));
    })?;
    let assessment = assess(&alma9()?, &package, &none(), &alma9_system(), false);
    assert_eq!(assessment.hold, None);
    assert!(!assessment.declared_dependency_satisfiable);
    assert!(matches!(
        assessment.dependencies,
        Some(Dependencies::NotEvaluated { .. })
    ));
    assert_eq!(assessment.confidence, Confidence::Low);
    Ok(())
}

#[test]
fn distributions_are_read_from_os_release() {
    let read = |id, version| Distribution::from_os_release(id, version).to_string();
    assert_eq!(read("debian", "12"), "debian 12");
    assert_eq!(read("almalinux", "9.8"), "el 9");
    assert_eq!(read("fedora", "44"), "fedora 44");
    assert_eq!(read("astra", "1.8_x86-64"), "astra 1.8");
    assert_eq!(read("redos", "8.0"), "redos 8.0");
}

#[test]
fn a_debian_build_on_astra_is_another_release_not_a_foreign_build() -> TestResult {
    let mut astra = target(Ecosystem::Deb, "amd64", "astra", "1.8_x86-64")?;
    let debian = deb(
        "app",
        "1.0-1+deb12u1",
        "amd64",
        "Depends: libc6 (>= 2.34)
",
    )?;
    let assessment = assess(&astra, &debian, &none(), &debian12_system(), false);
    assert_eq!(assessment.hold, None);
    assert_eq!(
        assessment.build,
        BuildClaim::OtherRelease {
            tag: "deb12".to_owned()
        }
    );
    assert_eq!(assessment.confidence, Confidence::Low);

    astra.other_release_builds = OtherReleaseBuilds::Hold;
    let assessment = assess(&astra, &debian, &none(), &debian12_system(), false);
    assert_eq!(
        assessment.hold,
        Some(CompatHold::OtherRelease {
            tag: "deb12".to_owned()
        })
    );

    // The kinship is Astra Linux 1.8's own: a Debian build on Debian 12 is
    // the target, and Astra Linux 1.7 is not a target at all.
    assert_eq!(
        Distribution::from_os_release("astra", "1.7_x86-64").based_on(),
        None
    );
    Ok(())
}

#[test]
fn a_vendor_source_satisfies_an_ordinary_dependency() -> TestResult {
    let mut system = debian12_system();
    system.add_package(Origin::OtherSource, "postgresql-16", "16.10-1.pgdg120+1");
    let package = deb(
        "app",
        "1.0",
        "amd64",
        "Depends: postgresql-16 (>= 16.4)
",
    )?;
    let assessment = assess(&debian12()?, &package, &none(), &system, false);
    assert_eq!(assessment.hold, None);
    assert!(assessment.declared_dependency_satisfiable);
    Ok(())
}

#[test]
fn a_vendor_source_never_satisfies_a_system_name() -> TestResult {
    // A third-party repository with a newer C library must not make an
    // artifact that needs it look admissible.
    let mut system = debian12_system();
    system.add_package(Origin::OtherSource, "libc6", "2.40-1");
    let package = deb(
        "app",
        "1.0",
        "amd64",
        "Depends: libc6 (>= 2.38)
",
    )?;
    let assessment = assess(&debian12()?, &package, &none(), &system, false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );
    Ok(())
}

#[test]
fn data_only_from_other_sources_is_no_data_about_the_system() -> TestResult {
    let mut system = SystemPackages::new(Ecosystem::Deb);
    system.add_package(Origin::OtherSource, "libc6", "2.36-9+deb12u10");
    let package = deb(
        "app",
        "1.0",
        "amd64",
        "Depends: libc6 (>= 2.34)
",
    )?;
    let assessment = assess(&debian12()?, &package, &none(), &system, false);
    assert_eq!(
        assessment.reason_code(),
        Some(ReasonCode::ESystemNamespaceUnknown)
    );
    Ok(())
}

#[test]
fn a_repeated_offer_is_kept_once() {
    let mut system = SystemPackages::new(Ecosystem::Rpm);
    // glibc.i686 and glibc.x86_64, and each package's `glibc = evr` provide.
    for _ in 0..4 {
        system.add_package(Origin::Distribution, "glibc", "2.34-275.el9_8");
    }
    system.add_package(Origin::Installed, "glibc", "2.34-275.el9_8");
    assert_eq!(
        system.versions(Origin::Distribution, "glibc"),
        ["2.34-275.el9_8"]
    );
    assert_eq!(
        system.versions(Origin::Installed, "glibc"),
        ["2.34-275.el9_8"]
    );
}
