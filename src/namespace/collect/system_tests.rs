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
    Ok(())
}
