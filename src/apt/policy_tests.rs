// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

const STRICT: &str = "pakomichi-sampleapp-strict";
const PINNED: &str = "pakomichi-sampleapp-pinned";
const OURS: &str = "http://127.0.0.1:18080/pakomichi-sampleapp-strict pakomichi-sampleapp-strict/main amd64 Packages";
const LEVEL: &str = "http://127.0.0.1:18080/pakomichi-sampleapp-pinned pakomichi-sampleapp-pinned/main amd64 Packages";
const DISTRO: &str = "http://deb.debian.org/debian-security bookworm-security/main amd64 Packages";

fn ours() -> Vec<OurRepository> {
    vec![
        OurRepository::new(18080, STRICT),
        OurRepository::new(18080, PINNED),
    ]
}

fn activated(names: &[&str]) -> BTreeMap<String, OurRepository> {
    names
        .iter()
        .map(|name| ((*name).to_owned(), OurRepository::new(18080, STRICT)))
        .collect()
}

fn parse(text: &str) -> Vec<PackagePolicy> {
    match parse_policy(text) {
        Ok(policies) => policies,
        Err(error) => panic!("{error}\n{text}"),
    }
}

fn protected_family() -> String {
    format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.1-1 500\n        500 {DISTRO}\n\
         \x20*** 1.0-1 990\n        100 {OURS}\n        100 /var/lib/dpkg/status\n\
         sampleapp-helper:\n  Installed: 1.0-1\n  Candidate: 1.0-1\n  Version table:\n\
         \x20*** 1.0-1 990\n        100 {OURS}\n        100 /var/lib/dpkg/status\n\
         \x20    0.9-1 500\n        500 {DISTRO}\n"
    )
}

#[test]
fn the_output_of_apt_2_6_to_3_0_parses_into_versions_and_sources() {
    let policies = parse(&protected_family());
    assert_eq!(policies.len(), 2);
    let app = &policies[0];
    assert_eq!(app.installed.as_deref(), Some("1.0-1"));
    assert_eq!(app.versions.len(), 2);
    assert_eq!(app.versions[1].priority, 990);
    assert_eq!(
        app.versions[1].sources[0].dist.as_deref(),
        Some("pakomichi-sampleapp-strict/main")
    );
    assert_eq!(app.versions[1].sources[1].location, "/var/lib/dpkg/status");
    let none = parse("absent-name:\n  Installed: (none)\n  Candidate: (none)\n  Version table:\n");
    assert_eq!(
        (none[0].installed.clone(), none[0].candidate.clone()),
        (None, None)
    );
    // An unknown line is an error, not something to skip.
    assert!(parse_policy("sampleapp:\n  Installed: 1.0\n  Surprise: yes\n").is_err());
}

#[test]
fn n027_a_newer_distribution_version_is_a_notice_and_the_publisher_stays() {
    let selection = judge(
        &parse(&protected_family()),
        &activated(&["sampleapp", "sampleapp-helper"]),
        &[],
        &ours(),
    );
    assert_eq!(selection.findings, Vec::new());
    assert_eq!(
        selection.notices,
        vec![Notice {
            name: "sampleapp".to_owned(),
            version: "1.1-1".to_owned(),
            source: "http://deb.debian.org/debian-security bookworm-security/main".to_owned(),
        }]
    );
}

#[test]
fn an_activated_name_whose_candidate_is_not_its_pinned_version_is_unsafe() {
    // A foreign preference, a lost pin, or a pin on the wrong level: APT
    // will move the name to another publisher on the next upgrade.
    let foreign_pin = format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.1-1\n  Version table:\n\
         \x20    1.1-1 1001\n        500 {DISTRO}\n\
         \x20*** 1.0-1 990\n        100 {OURS}\n        100 /var/lib/dpkg/status\n"
    );
    let lost_pin = format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.1-1\n  Version table:\n\
         \x20    1.1-1 500\n        500 {DISTRO}\n\
         \x20*** 1.0-1 100\n        100 {OURS}\n        100 /var/lib/dpkg/status\n"
    );
    let other_level = format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.2-1\n  Version table:\n\
         \x20    1.2-1 990\n        100 {LEVEL}\n\
         \x20*** 1.0-1 100\n        100 {OURS}\n        100 /var/lib/dpkg/status\n"
    );
    for text in [foreign_pin, lost_pin, other_level] {
        let selection = judge(&parse(&text), &activated(&["sampleapp"]), &[], &ours());
        assert!(
            matches!(
                selection.findings.as_slice(),
                [Finding::NotProtected { .. }]
            ),
            "{text}\n{selection:?}"
        );
    }
    // No pin yet and nothing else offers the name: the candidate is ours,
    // but at 100 the first distribution version would take it over.
    let unpinned = format!(
        "sampleapp:\n  Installed: 1.0-1\n  Candidate: 1.0-1\n  Version table:\n\
         \x20*** 1.0-1 100\n        100 {OURS}\n        100 /var/lib/dpkg/status\n"
    );
    let selection = judge(&parse(&unpinned), &activated(&["sampleapp"]), &[], &ours());
    assert!(matches!(
        selection.findings.as_slice(),
        [Finding::NotProtected {
            priority: Some(100),
            ..
        }]
    ));
    // A name APT does not know at all (the source is gone).
    let selection = judge(&[], &activated(&["sampleapp"]), &[], &ours());
    assert!(matches!(
        selection.findings.as_slice(),
        [Finding::NotProtected {
            candidate: None,
            ..
        }]
    ));
}

#[test]
fn n010_an_equal_version_in_another_source_is_ambiguous_even_when_pinned() {
    // APT 2.6 merges equal versions: the pin raises the merged version and
    // the file may still come from the other source (R-001).
    let merged = format!(
        "sampleapp:\n  Installed: (none)\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 990\n        500 {DISTRO}\n        100 {OURS}\n"
    );
    let selection = judge(&parse(&merged), &activated(&["sampleapp"]), &[], &ours());
    assert_eq!(
        selection.findings,
        vec![Finding::EqualVersionElsewhere {
            name: "sampleapp".to_owned(),
            version: "1.0-1".to_owned(),
            other: "http://deb.debian.org/debian-security bookworm-security/main".to_owned(),
        }]
    );
    assert_eq!(selection.findings[0].reason(), ReasonCode::ESourceAmbiguous);
}

#[test]
fn a_published_name_that_is_not_activated_never_takes_a_name_over() {
    // The repository's own priority is 100; at 500 the higher version from
    // us would replace the distribution's on `apt upgrade`.
    let takes_over = format!(
        "curl:\n  Installed: 7.88.1-10\n  Candidate: 8.99.0\n  Version table:\n\
         \x20    8.99.0 500\n        500 {OURS}\n\
         \x20*** 7.88.1-10 500\n        500 {DISTRO}\n        100 /var/lib/dpkg/status\n"
    );
    let selection = judge(
        &parse(&takes_over),
        &BTreeMap::new(),
        &["curl".to_owned()],
        &ours(),
    );
    assert!(matches!(
        selection.findings.as_slice(),
        [Finding::TakesOver { .. }]
    ));
    let low = takes_over
        .replace("8.99.0 500\n        500", "8.99.0 100\n        100")
        .replace("Candidate: 8.99.0", "Candidate: 7.88.1-10");
    let selection = judge(
        &parse(&low),
        &BTreeMap::new(),
        &["curl".to_owned()],
        &ours(),
    );
    assert_eq!(selection.findings, Vec::new());
    // Keeping a copy installed from us is not a takeover.
    let kept = format!(
        "freeapp:\n  Installed: 2.0-1\n  Candidate: 2.0-1\n  Version table:\n\
         \x20*** 2.0-1 100\n        100 {OURS}\n        100 /var/lib/dpkg/status\n\
         \x20    1.0-1 500\n        500 {DISTRO}\n"
    );
    let selection = judge(
        &parse(&kept),
        &BTreeMap::new(),
        &["freeapp".to_owned()],
        &ours(),
    );
    assert_eq!(selection.findings, Vec::new());
    // One entry merged from our file and another source's: an ambiguity,
    // shown, not a takeover.
    let merged = format!(
        "eqapp:\n  Installed: (none)\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 500\n        500 {DISTRO}\n        100 {OURS}\n"
    );
    let selection = judge(
        &parse(&merged),
        &BTreeMap::new(),
        &["eqapp".to_owned()],
        &ours(),
    );
    assert!(
        matches!(
            selection.findings.as_slice(),
            [Finding::EqualVersionElsewhere { .. }]
        ),
        "{selection:?}"
    );
}

#[test]
fn n010_an_equal_version_is_ambiguous_when_apt_lists_it_twice() {
    // APT 2.8+ does not merge: the same version appears as two entries,
    // and the candidate may be the other source's one.
    let unmerged = format!(
        "sampleapp:\n  Installed: (none)\n  Candidate: 1.0-1\n  Version table:\n\
         \x20    1.0-1 500\n        500 {DISTRO}\n\
         \x20    1.0-1 100\n        100 {OURS}\n"
    );
    let policies = parse(&unmerged);
    let family = |members: &[&str]| Family {
        repository: OurRepository::new(18080, STRICT),
        members: members.iter().map(|name| (*name).to_owned()).collect(),
    };
    let (pins, held) = pins_to_write(&policies, &[family(&["sampleapp"])]);
    assert!(
        pins.is_empty(),
        "a name with an equal version elsewhere is not pinned"
    );
    assert!(
        matches!(held.as_slice(), [(_, Held::Ambiguous(_))]),
        "{held:?}"
    );
    let selection = judge(&policies, &activated(&["sampleapp"]), &[], &ours());
    assert!(
        selection
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::EqualVersionElsewhere { .. })),
        "{selection:?}"
    );
    // `0:1.0-1` is the same version as `1.0-1` for dpkg.
    let epoch = unmerged.replacen("     1.0-1 500", "     0:1.0-1 500", 1);
    assert!(
        pins_to_write(&parse(&epoch), &[family(&["sampleapp"])])
            .0
            .is_empty()
    );
    // A different version elsewhere is no ambiguity.
    let other = unmerged.replacen("     1.0-1 500", "     1.1-1 500", 1);
    assert_eq!(
        pins_to_write(&parse(&other), &[family(&["sampleapp"])])
            .0
            .len(),
        1
    );
}

#[test]
fn a_family_is_pinned_whole_or_not_at_all() {
    // P3-002a: a member left without the pin changes publisher. Here the
    // helper is not listed yet (no `apt update` since the source was
    // added), so equality cannot be ruled out and nothing is pinned.
    let only_app = format!(
        "sampleapp:\n  Installed: (none)\n  Candidate: 1.1-1\n  Version table:\n\
         \x20    1.1-1 500\n        500 {DISTRO}\n\
         \x20    1.0-1 100\n        100 {OURS}\n\
         sampleapp-helper:\n  Installed: (none)\n  Candidate: 1.1-1\n  Version table:\n\
         \x20    1.1-1 500\n        500 {DISTRO}\n"
    );
    let family = Family {
        repository: OurRepository::new(18080, STRICT),
        members: ["sampleapp", "sampleapp-helper"]
            .iter()
            .map(|n| (*n).to_owned())
            .collect(),
    };
    let (pins, held) = pins_to_write(&parse(&only_app), std::slice::from_ref(&family));
    assert!(pins.is_empty(), "{pins:?}");
    assert_eq!(
        held,
        vec![(
            family.members.clone(),
            Held::NotListed {
                name: "sampleapp-helper".to_owned()
            }
        )]
    );
    // Once APT lists both members in the repository, both are pinned.
    let listed = format!("{only_app}\x20    1.0-1 100\n        100 {OURS}\n");
    let (pins, held) = pins_to_write(&parse(&listed), &[family]);
    assert_eq!(
        pins.keys().collect::<Vec<_>>(),
        ["sampleapp", "sampleapp-helper"]
    );
    assert!(held.is_empty());
}
