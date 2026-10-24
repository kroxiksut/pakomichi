// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

const PORT: u16 = 18080;

fn source(key: &str, repositories: &[(&str, &[&str])]) -> SourceConfig {
    SourceConfig {
        source_key: key.to_owned(),
        repositories: repositories
            .iter()
            .map(|(label, names)| LogicalSource {
                label: (*label).to_owned(),
                activated: names.iter().map(|name| (*name).to_owned()).collect(),
            })
            .collect(),
    }
}

fn text(files: &[ManagedFile], kind: FileKind) -> String {
    files
        .iter()
        .find(|file| file.kind == kind)
        .map(|file| String::from_utf8_lossy(&file.bytes).into_owned())
        .unwrap_or_default()
}

#[test]
fn every_member_of_an_activated_family_is_pinned_by_origin_and_label() -> Result<(), ConfigError> {
    // P3-002a: a family member left without the pin changes publisher on an
    // ordinary upgrade; the Origin alone does not tell two levels apart.
    let files = render(
        &[source(
            "sampleapp",
            &[
                (
                    "pakomichi-sampleapp-strict",
                    &["sampleapp", "sampleapp-helper"],
                ),
                ("pakomichi-sampleapp-pinned", &[]),
            ],
        )],
        PORT,
        b"key",
    )?;
    let pref = text(&files, FileKind::Preferences);
    assert_eq!(
        pref,
        format!(
            "Explanation: {HEADER}\nPackage: sampleapp sampleapp-helper\n\
             Pin: release o=Pakomichi,l=pakomichi-sampleapp-strict\nPin-Priority: 990\n"
        )
    );
    assert!(!pref.contains("Pin: origin"));
    // The Pinned repository has no activated names and no pin at all.
    assert!(!pref.contains("pinned"));
    Ok(())
}

#[test]
fn a_name_or_label_that_could_add_a_field_is_refused() {
    // `*` would pin the whole repository at 990; a line break would add a
    // field such as a priority of 1001.
    for name in [
        "*",
        "sampleapp\nPin-Priority: 1001",
        "sample app",
        "Sampleapp",
        "-x",
        "a",
    ] {
        let error = render(
            &[source(
                "sampleapp",
                &[("pakomichi-sampleapp-strict", &[name])],
            )],
            PORT,
            b"key",
        )
        .err();
        assert_eq!(
            error,
            Some(ConfigError::InvalidPackageName(name.to_owned())),
            "{name:?}"
        );
    }
    for label in ["pakomichi-x-strict\nPin: origin 127.0.0.1", "Pakomichi", ""] {
        assert!(
            matches!(
                render(&[source("x", &[(label, &["netwatch"])])], PORT, b"key"),
                Err(ConfigError::InvalidLabel(_))
            ),
            "{label:?}"
        );
    }
    assert!(matches!(
        render(&[source("x y", &[])], PORT, b"key"),
        Err(ConfigError::InvalidSourceKey(_))
    ));
}

#[test]
fn one_name_activated_in_two_repositories_is_refused() {
    // Two 990 pins: the higher version decides, so the Pinned level (or
    // another source) could take an activated name over.
    let levels = render(
        &[source(
            "sampleapp",
            &[
                ("pakomichi-sampleapp-strict", &["sampleapp"]),
                ("pakomichi-sampleapp-pinned", &["sampleapp"]),
            ],
        )],
        PORT,
        b"key",
    );
    assert!(
        matches!(levels, Err(ConfigError::ActivatedTwice { .. })),
        "{levels:?}"
    );
    let sources = render(
        &[
            source("a", &[("pakomichi-a-strict", &["shared-name"])]),
            source("b", &[("pakomichi-b-strict", &["shared-name"])]),
        ],
        PORT,
        b"key",
    );
    assert!(matches!(sources, Err(ConfigError::ActivatedTwice { .. })));
    let twice = render(
        &[
            source("a", &[("pakomichi-a-strict", &[])]),
            source("a", &[("pakomichi-a-attested", &[])]),
        ],
        PORT,
        b"key",
    );
    assert!(matches!(twice, Err(ConfigError::Duplicate(_))));
}

#[test]
fn every_repository_is_signed_by_the_local_keyring_on_loopback() -> Result<(), ConfigError> {
    let files = render(
        &[source(
            "netwatch",
            &[
                ("pakomichi-netwatch-strict", &[]),
                ("pakomichi-netwatch-attested", &[]),
            ],
        )],
        PORT,
        b"key bytes",
    )?;
    let sources = text(&files, FileKind::Sources);
    assert_eq!(
        sources
            .matches("Signed-By: /etc/apt/keyrings/pakomichi.gpg\n")
            .count(),
        2
    );
    assert_eq!(sources.matches("URIs: http://127.0.0.1:18080/").count(), 2);
    assert!(!sources.to_ascii_lowercase().contains("trusted"));
    // No activated name: no preferences file, the repository stays at the
    // priority its Release gives (100).
    assert!(files.iter().all(|file| file.kind != FileKind::Preferences));
    assert_eq!(text(&files, FileKind::Keyring), "key bytes");
    // Nothing configured: nothing managed, not even the keyring.
    assert_eq!(render(&[], PORT, b"key")?, Vec::new());
    assert_eq!(render(&[], 0, b"key"), Err(ConfigError::InvalidPort));
    Ok(())
}
