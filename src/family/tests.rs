// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;

use rpm::{BuildConfig, CompressionType, Dependency, PackageBuilder};

use super::*;
use crate::inspect::fixtures::{deb_inspection, rpm_inspection};
use crate::namespace::{self, Claims, Conflict, PackageRole, SystemNamespace};

type TestResult = Result<(), Box<dyn Error>>;

/// Metadata of a binary DEB read through the real inspection path.
fn deb(name: &str, version: &str, extra: &str) -> Result<PackageMetadata, Box<dyn Error>> {
    deb_arch(name, version, "amd64", extra)
}

fn deb_arch(
    name: &str,
    version: &str,
    arch: &str,
    extra: &str,
) -> Result<PackageMetadata, Box<dyn Error>> {
    let control = format!(
        "Package: {name}\nVersion: {version}\nArchitecture: {arch}\n\
         Maintainer: Pakomichi test fixture <noreply@example.invalid>\n{extra}\
         Description: TEST ONLY P2-007 family fixture\n"
    );
    Ok(PackageMetadata::from_deb(&deb_inspection(&control)?)?)
}

/// Metadata of a binary RPM built with the `rpm` crate and read back.
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
        "TEST ONLY P2-007 family fixture",
    );
    builder
        .release(release)
        .using_config(BuildConfig::v4().compression(CompressionType::None));
    edit(&mut builder);
    let mut bytes = Vec::new();
    builder.build()?.write(&mut bytes)?;
    Ok(PackageMetadata::from_rpm(&rpm_inspection(&bytes)?)?)
}

fn candidate(key: &'static str, package: PackageMetadata) -> Candidate<&'static str> {
    Candidate {
        key,
        sha256: Sha256Digest::of(key.as_bytes()),
        package,
        held: None,
    }
}

fn admit(family: &Family, candidates: &[Candidate<&'static str>]) -> FamilyAdmission<&'static str> {
    admit_family(family, candidates, &SystemNamespace::new())
}

fn arches(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn family(ecosystem: Ecosystem, names: &[&str], arch: &str) -> Result<Family, FamilyError> {
    let mut family = Family::proposed(
        names
            .iter()
            .map(|name| (MemberKey::new(ecosystem, name), arches(&[arch]))),
    )?;
    family.approve(1)?;
    Ok(family)
}

fn sampleapp() -> Result<Family, FamilyError> {
    family(
        Ecosystem::Deb,
        &["sampleapp", "sampleapp-cli", "sampleapp-service"],
        "amd64",
    )
}

fn decisions(
    admission: &FamilyAdmission<&'static str>,
) -> Vec<(&'static str, FamilyDecision<&'static str>)> {
    admission.decisions.clone()
}

fn publish() -> FamilyDecision<&'static str> {
    FamilyDecision::Publish
}

fn held_for(admission: &FamilyAdmission<&'static str>, key: &'static str) -> Option<ReasonCode> {
    admission
        .decision(&key)
        .and_then(FamilyDecision::reason_code)
}

/// E2E-02's family: three members, native dependencies main → service and
/// cli → main, upgraded from 1.0 to 1.1 together.
#[test]
fn a_three_member_family_upgrades_consistently() -> TestResult {
    let candidates = vec![
        candidate(
            "app-1.0",
            deb(
                "sampleapp",
                "1.0-1",
                "Depends: sampleapp-service (= 1.0-1)\n",
            )?,
        ),
        candidate("svc-1.0", deb("sampleapp-service", "1.0-1", "")?),
        candidate(
            "cli-1.0",
            deb("sampleapp-cli", "1.0-1", "Depends: sampleapp (>= 1.0)\n")?,
        ),
        candidate(
            "app-1.1",
            deb(
                "sampleapp",
                "1.1-1",
                "Depends: sampleapp-service (= 1.1-1)\n",
            )?,
        ),
        candidate("svc-1.1", deb("sampleapp-service", "1.1-1", "")?),
        candidate(
            "cli-1.1",
            deb("sampleapp-cli", "1.1-1", "Depends: sampleapp (>= 1.0)\n")?,
        ),
    ];
    let admission = admit(&sampleapp()?, &candidates);
    assert_eq!(
        decisions(&admission),
        vec![
            ("app-1.0", FamilyDecision::Superseded),
            ("svc-1.0", FamilyDecision::Superseded),
            ("cli-1.0", FamilyDecision::Superseded),
            ("app-1.1", publish()),
            ("svc-1.1", publish()),
            ("cli-1.1", publish()),
        ]
    );
    assert_eq!(admission.review, None);
    Ok(())
}

/// families-compatibility.md: if `app (= 0.6)` needs `app-service (= 0.6)`,
/// both are published or the new `app` is not admitted.
#[test]
fn a_member_whose_family_dependency_is_missing_is_held() -> TestResult {
    let candidates = vec![
        candidate(
            "app-1.1",
            deb(
                "sampleapp",
                "1.1-1",
                "Depends: sampleapp-service (= 1.1-1)\n",
            )?,
        ),
        candidate("svc-1.1", deb("sampleapp-service", "1.1-1", "")?),
        candidate(
            "app-1.2",
            deb(
                "sampleapp",
                "1.2-1",
                "Depends: sampleapp-service (= 1.2-1)\n",
            )?,
        ),
        // cli 1.2 needs app 1.2, which cannot be admitted: held in cascade.
        candidate(
            "cli-1.2",
            deb("sampleapp-cli", "1.2-1", "Depends: sampleapp (= 1.2-1)\n")?,
        ),
    ];
    let admission = admit(&sampleapp()?, &candidates);
    assert_eq!(admission.decision(&"app-1.1"), Some(&publish()));
    assert_eq!(admission.decision(&"svc-1.1"), Some(&publish()));
    assert_eq!(
        admission.decision(&"app-1.2"),
        Some(&FamilyDecision::Held {
            reason: ReasonCode::EDependencyUnsatisfiable,
            detail: HoldDetail::Dependency {
                clause: "sampleapp-service (= 1.2-1)".to_owned()
            },
        })
    );
    assert_eq!(
        held_for(&admission, "cli-1.2"),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );
    Ok(())
}

/// The newest of every name is published, plus every older artifact the
/// published ones need, so the snapshot stays consistent.
#[test]
fn publication_includes_the_older_versions_members_need() -> TestResult {
    let candidates = vec![
        candidate(
            "app-1.1",
            deb(
                "sampleapp",
                "1.1-1",
                "Depends: sampleapp-service (= 1.1-1)\n",
            )?,
        ),
        candidate("svc-1.1", deb("sampleapp-service", "1.1-1", "")?),
        candidate("svc-1.2", deb("sampleapp-service", "1.2-1", "")?),
        candidate("svc-1.0", deb("sampleapp-service", "1.0-1", "")?),
    ];
    let admission = admit(&sampleapp()?, &candidates);
    assert_eq!(
        decisions(&admission),
        vec![
            ("app-1.1", publish()),
            ("svc-1.1", publish()),
            ("svc-1.2", publish()),
            ("svc-1.0", FamilyDecision::Superseded),
        ]
    );
    Ok(())
}

/// The same version number is not required across members.
#[test]
fn members_may_have_different_versions() -> TestResult {
    let family = family(Ecosystem::Deb, &["app", "app-common"], "amd64")?;
    let candidates = vec![
        candidate(
            "app-2.0",
            deb("app", "2.0-1", "Depends: app-common (>= 1.5)\n")?,
        ),
        candidate("common-1.7", deb("app-common", "1.7-3", "")?),
    ];
    let admission = admit(&family, &candidates);
    assert_eq!(
        decisions(&admission),
        vec![("app-2.0", publish()), ("common-1.7", publish())]
    );
    Ok(())
}

/// Versions are compared natively: 1.10 is newer than 1.9 and 1.0~rc1 is
/// older than 1.0.
#[test]
fn the_newest_version_is_chosen_natively() -> TestResult {
    let candidates = vec![
        candidate("app-1.10", deb("sampleapp", "1.10-1", "")?),
        candidate("app-1.9", deb("sampleapp", "1.9-1", "")?),
        candidate("cli-1.0", deb("sampleapp-cli", "1.0-1", "")?),
        candidate("cli-1.0rc1", deb("sampleapp-cli", "1.0~rc1-1", "")?),
    ];
    let admission = admit(&sampleapp()?, &candidates);
    assert_eq!(
        decisions(&admission),
        vec![
            ("app-1.10", publish()),
            ("app-1.9", FamilyDecision::Superseded),
            ("cli-1.0", publish()),
            ("cli-1.0rc1", FamilyDecision::Superseded),
        ]
    );
    Ok(())
}

/// ADR-002: a new name needs a review, even with a similar prefix, and
/// nothing it claims makes it a member (negative test of P2-007).
#[test]
fn a_new_name_is_held_whatever_it_provides_or_replaces() -> TestResult {
    let family = sampleapp()?;
    let candidates = vec![
        candidate("app-1.1", deb("sampleapp", "1.1-1", "")?),
        candidate(
            "driver-1.1",
            deb(
                "sampleapp-driver",
                "1.1-1",
                "Provides: sampleapp-service (= 1.1-1)\nReplaces: sampleapp-service\n",
            )?,
        ),
        // A member that depends on the service: the new package's Provides
        // must not satisfy it.
        candidate(
            "cli-1.1",
            deb("sampleapp-cli", "1.1-1", "Depends: sampleapp-service\n")?,
        ),
    ];
    let admission = admit(&family, &candidates);
    assert_eq!(admission.decision(&"app-1.1"), Some(&publish()));
    assert_eq!(
        admission.decision(&"driver-1.1"),
        Some(&FamilyDecision::Held {
            reason: ReasonCode::EFamilyUnapproved,
            detail: HoldDetail::NewName,
        })
    );
    assert_eq!(
        held_for(&admission, "cli-1.1"),
        Some(ReasonCode::EDependencyUnsatisfiable)
    );
    let review = admission.review.ok_or("no review")?;
    assert_eq!(review.base_revision, 1);
    assert_eq!(
        review.additions,
        BTreeMap::from([(
            MemberKey::new(Ecosystem::Deb, "sampleapp-driver"),
            arches(&["amd64"])
        )])
    );
    // Confirming the review makes it a member at the next revision.
    let extended = family.extend(&review)?;
    assert_eq!(extended.revision(), 2);
    assert_eq!(
        admit(&extended, &candidates).decision(&"driver-1.1"),
        Some(&publish())
    );
    // A review computed against revision 1 cannot extend revision 2.
    assert_eq!(
        extended.extend(&review),
        Err(FamilyError::StaleReview {
            reviewed: 1,
            current: 2
        })
    );
    Ok(())
}

#[test]
fn a_proposed_family_admits_nothing_until_approved() -> TestResult {
    let mut family = Family::proposed([
        (
            MemberKey::new(Ecosystem::Deb, "sampleapp"),
            arches(&["amd64"]),
        ),
        (
            MemberKey::new(Ecosystem::Deb, "sampleapp-cli"),
            arches(&["amd64"]),
        ),
    ])?;
    assert_eq!(family.state(), FamilyState::Proposed);
    let candidates = vec![
        candidate("app-1.0", deb("sampleapp", "1.0-1", "")?),
        candidate("cli-1.0", deb("sampleapp-cli", "1.0-1", "")?),
    ];
    let admission = admit(&family, &candidates);
    for (_, decision) in &admission.decisions {
        assert_eq!(
            decision,
            &FamilyDecision::Held {
                reason: ReasonCode::EFamilyUnapproved,
                detail: HoldDetail::FamilyNotApproved,
            }
        );
    }
    assert_eq!(
        admission.review,
        Some(CompositionReview {
            base_revision: 1,
            additions: BTreeMap::new()
        })
    );
    assert_eq!(
        family.approve(2),
        Err(FamilyError::StaleReview {
            reviewed: 2,
            current: 1
        })
    );
    family.approve(1)?;
    let admission = admit(&family, &candidates);
    assert_eq!(
        decisions(&admission),
        vec![("app-1.0", publish()), ("cli-1.0", publish())]
    );
    assert!(Family::proposed([]).is_err());
    Ok(())
}

#[test]
fn a_new_architecture_of_a_member_needs_a_review() -> TestResult {
    let candidates = vec![candidate(
        "app-all",
        deb_arch("sampleapp", "1.0-1", "all", "")?,
    )];
    let admission = admit(&sampleapp()?, &candidates);
    assert_eq!(
        admission.decision(&"app-all"),
        Some(&FamilyDecision::Held {
            reason: ReasonCode::EFamilyUnapproved,
            detail: HoldDetail::NewArchitecture,
        })
    );
    let review = admission.review.ok_or("no review")?;
    assert_eq!(
        review.additions,
        BTreeMap::from([(
            MemberKey::new(Ecosystem::Deb, "sampleapp"),
            arches(&["all"])
        )])
    );
    Ok(())
}

/// ADR-022 point 1: natively equal versions with different bytes are
/// ambiguous, also across releases; equal bytes are one artifact.
#[test]
fn equal_versions_with_different_bytes_are_ambiguous() -> TestResult {
    let candidates = vec![
        candidate("app-1.0-a", deb("sampleapp", "1.0", "")?),
        candidate("app-1.00-b", deb("sampleapp", "1.00", "")?),
        Candidate {
            key: "app-1.0-copy",
            sha256: Sha256Digest::of(b"app-1.0-a"),
            package: deb("sampleapp", "1.0", "")?,
            held: None,
        },
        candidate("cli-0.9", deb("sampleapp-cli", "0.9", "")?),
    ];
    let admission = admit(&sampleapp()?, &candidates);
    assert_eq!(
        decisions(&admission),
        vec![
            (
                "app-1.0-a",
                FamilyDecision::Held {
                    reason: ReasonCode::ESourceAmbiguous,
                    detail: HoldDetail::Ambiguous {
                        with: vec!["app-1.00-b"]
                    },
                }
            ),
            (
                "app-1.00-b",
                FamilyDecision::Held {
                    reason: ReasonCode::ESourceAmbiguous,
                    detail: HoldDetail::Ambiguous {
                        with: vec!["app-1.0-a"]
                    },
                }
            ),
            (
                "app-1.0-copy",
                FamilyDecision::Duplicate { of: "app-1.0-a" }
            ),
            ("cli-0.9", publish()),
        ]
    );
    Ok(())
}

#[test]
fn alternatives_and_provides_follow_dpkg() -> TestResult {
    let family = sampleapp()?;
    let candidates = vec![
        // An alternative outside the family is left to APT.
        candidate(
            "cli-1",
            deb(
                "sampleapp-cli",
                "1.0",
                "Depends: sampleapp-service (= 9) | default-mta\n",
            )?,
        ),
        // Both alternatives are members: one of them must be admissible.
        candidate(
            "app-1",
            deb(
                "sampleapp",
                "1.0",
                "Depends: sampleapp-service (= 9) | sampleapp-cli\n",
            )?,
        ),
        candidate(
            "svc-1",
            deb(
                "sampleapp-service",
                "1.0",
                "Provides: sampleapp-backend (= 1.1), sampleapp-api\n",
            )?,
        ),
    ];
    let admission = admit(&family, &candidates);
    assert_eq!(
        decisions(&admission),
        vec![
            ("cli-1", publish()),
            ("app-1", publish()),
            ("svc-1", publish())
        ]
    );
    let svc = &candidates[2].package;
    let atom = |name: &str, constraint: Option<(Op, &str)>| Atom {
        name: name.to_owned(),
        constraint: constraint.map(|(op, version)| (op, version.to_owned())),
    };
    assert!(svc.satisfies(&atom("sampleapp-backend", Some((Op::GreaterEqual, "1.1")))));
    assert!(!svc.satisfies(&atom("sampleapp-backend", Some((Op::Greater, "1.1")))));
    // dpkg: an unversioned Provides never satisfies a versioned dependency.
    assert!(svc.satisfies(&atom("sampleapp-api", None)));
    assert!(!svc.satisfies(&atom("sampleapp-api", Some((Op::GreaterEqual, "0")))));
    assert!(svc.satisfies(&atom("sampleapp-service", Some((Op::Equal, "1.00")))));
    Ok(())
}

#[test]
fn rpm_families_follow_rpm_matching() -> TestResult {
    let family = family(
        Ecosystem::Rpm,
        &["sampleapp", "sampleapp-service", "sampleapp-cli"],
        "x86_64",
    )?;
    let candidates = vec![
        // No release in the requirement: any release of 1.1 matches.
        candidate(
            "app",
            rpm("sampleapp", "1.1", "1.el9", |builder| {
                builder.requires(Dependency::eq("sampleapp-service", "1.1"));
            })?,
        ),
        candidate("svc", rpm("sampleapp-service", "1.1", "3.el9", |_| {})?),
        // A release in the requirement must match it.
        candidate(
            "cli",
            rpm("sampleapp-cli", "1.1", "1.el9", |builder| {
                builder.requires(Dependency::eq("sampleapp-service", "1.1-2.el9"));
            })?,
        ),
    ];
    let admission = admit(&family, &candidates);
    assert_eq!(admission.decision(&"app"), Some(&publish()));
    assert_eq!(admission.decision(&"svc"), Some(&publish()));
    assert_eq!(
        admission.decision(&"cli"),
        Some(&FamilyDecision::Held {
            reason: ReasonCode::EDependencyUnsatisfiable,
            detail: HoldDetail::Dependency {
                clause: "sampleapp-service = 1.1-2.el9".to_owned()
            },
        })
    );
    Ok(())
}

#[test]
fn rpm_unversioned_provides_and_rich_dependencies() -> TestResult {
    let family = family(
        Ecosystem::Rpm,
        &["sampleapp", "sampleapp-service"],
        "x86_64",
    )?;
    let candidates = vec![
        // RPM: an unversioned Provides satisfies a versioned requirement.
        candidate(
            "svc",
            rpm("sampleapp-service", "1.0", "1", |builder| {
                builder.provides(Dependency::any("sampleapp-backend"));
            })?,
        ),
        candidate(
            "app-1",
            rpm("sampleapp", "1.0", "1", |builder| {
                builder
                    .requires(Dependency::greater_eq("sampleapp-backend", "2.0"))
                    .requires(Dependency::any("(glibc >= 2.34 or musl)"))
                    .requires(Dependency::any("/bin/sh"));
            })?,
        ),
        // A rich dependency that names a member is not evaluated.
        candidate(
            "app-2",
            rpm("sampleapp", "2.0", "1", |builder| {
                builder.requires(Dependency::any("(sampleapp-service >= 2 if systemd)"));
            })?,
        ),
    ];
    let admission = admit(&family, &candidates);
    assert_eq!(admission.decision(&"svc"), Some(&publish()));
    assert_eq!(admission.decision(&"app-1"), Some(&publish()));
    assert_eq!(
        admission.decision(&"app-2"),
        Some(&FamilyDecision::Held {
            reason: ReasonCode::EDependencyUnsatisfiable,
            detail: HoldDetail::RichDependency {
                clause: "(sampleapp-service >= 2 if systemd)".to_owned()
            },
        })
    );
    Ok(())
}

#[test]
fn malformed_metadata_is_rejected() -> TestResult {
    for extra in [
        "Depends: sampleapp-service (>= 1.0-)\n",
        "Breaks: a | b\n",
        "Provides: sampleapp-api (>= 1)\n",
        "Pre-Depends: dpkg [amd64]\n",
    ] {
        let control = format!(
            "Package: sampleapp\nVersion: 1.0\nArchitecture: amd64\n{extra}Description: TEST ONLY\n"
        );
        let error = PackageMetadata::from_deb(&deb_inspection(&control)?);
        assert_eq!(
            error.as_ref().map_err(MetadataError::reason_code),
            Err(ReasonCode::EArtifactMalformed),
            "{extra}"
        );
    }
    // The inspector accepts an empty revision; the family model refuses it.
    let control =
        "Package: sampleapp\nVersion: 1.0-\nArchitecture: amd64\nDescription: TEST ONLY\n";
    assert!(matches!(
        PackageMetadata::from_deb(&deb_inspection(control)?),
        Err(MetadataError::Version(VersionError::EmptyRevision))
    ));
    Ok(())
}

/// N-008 and N-026 with P2-014: membership never excuses a system
/// namespace conflict. The namespace check holds the member, the hold is
/// passed to the family admission, and members that need it are held in
/// cascade; a capability only the family provides is no conflict.
#[test]
fn family_members_still_face_the_system_namespace() -> TestResult {
    let mut system = SystemNamespace::new();
    system.insert_package("libc6", PackageRole::OsPart);
    system.insert_package("mail-transport-agent", PackageRole::DistributionApplication);

    let control = |name: &str, extra: &str| {
        format!(
            "Package: {name}\nVersion: 1.0\nArchitecture: amd64\n{extra}Description: TEST ONLY\n"
        )
    };
    let inspections = [
        // N-008: Provides of the C library, beside a family capability.
        (
            "glibc",
            deb_inspection(&control(
                "sampleapp-service",
                "Provides: libc6 (= 2.99), sampleapp-backend\n",
            ))?,
        ),
        // N-026: Replaces of a distribution package, with a version constraint.
        (
            "replaces",
            deb_inspection(&control(
                "sampleapp-cli",
                "Replaces: mail-transport-agent (<< 0.1)\n",
            ))?,
        ),
        // Needs the family capability, and the C library from the system.
        (
            "app",
            deb_inspection(&control(
                "sampleapp",
                "Depends: sampleapp-backend, libc6 (>= 2.36)\n",
            ))?,
        ),
    ];
    let mut candidates = Vec::new();
    for (key, inspection) in &inspections {
        let check = namespace::check(&system, &Claims::from_deb(inspection));
        let mut candidate = candidate(key, PackageMetadata::from_deb(inspection)?);
        candidate.held = check.reason_code();
        if *key == "glibc" {
            assert_eq!(
                check.conflicts,
                vec![Conflict {
                    relation: namespace::Relation::Provides,
                    name: "libc6".to_owned()
                }]
            );
        }
        candidates.push(candidate);
    }
    let admission = admit_family(&sampleapp()?, &candidates, &system);
    let earlier = FamilyDecision::Held {
        reason: ReasonCode::ESystemPackageConflict,
        detail: HoldDetail::EarlierCheck,
    };
    assert_eq!(admission.decision(&"glibc"), Some(&earlier));
    assert_eq!(admission.decision(&"replaces"), Some(&earlier));
    // Only the held member offers `sampleapp-backend`; `libc6` is the
    // system's, so it is left to APT and does not count here.
    assert_eq!(
        admission.decision(&"app"),
        Some(&FamilyDecision::Held {
            reason: ReasonCode::EDependencyUnsatisfiable,
            detail: HoldDetail::Dependency {
                clause: "sampleapp-backend".to_owned()
            },
        })
    );
    Ok(())
}

#[test]
fn rpm_metadata_skips_file_and_rpmlib_requirements() -> TestResult {
    let package = rpm("sampleapp", "1.0", "1.el9", |builder| {
        builder
            .requires(Dependency::any("/usr/bin/python3"))
            .requires(Dependency::greater_eq("glibc", "2.34"))
            .provides(Dependency::eq("sampleapp-api", "2"));
    })?;
    assert_eq!(package.version(), "1.0-1.el9");
    assert!(package.depends().iter().all(|clause| match clause {
        Clause::Any(atoms) => atoms.iter().all(|atom| !atom.name.starts_with(['/', 'r'])),
        Clause::Rich(_) => false,
    }));
    assert!(package.depends().iter().any(|clause| matches!(
        clause,
        Clause::Any(atoms) if atoms[0].name == "glibc"
    )));
    Ok(())
}
