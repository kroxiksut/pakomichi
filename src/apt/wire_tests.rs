// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::ipc::channels::{ApplyApt, ApplyRequest, ApplyResponse, DriftWire, DriftedWire};
use crate::ipc::protocol::{decode, encode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SHA: &str = "a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9";
const OPERATION: &str = "0123456789abcdef0123456789abcdef";

fn desired() -> Desired {
    Desired {
        port: 18080,
        keyring: vec![0x99, 0x01, 0xff],
        sources: vec![SourceConfig {
            source_key: "sampleapp".to_owned(),
            repositories: vec![LogicalSource {
                label: "pakomichi-sampleapp-strict".to_owned(),
                activated: ["sampleapp".to_owned()].into_iter().collect(),
            }],
        }],
    }
}

#[test]
fn the_apply_messages_have_a_pinned_wire_shape() -> TestResult {
    let request = ApplyRequest::ApplyApt(ApplyApt {
        operation_id: OPERATION.to_owned(),
        desired: desired_to_wire(&desired()),
        previous: desired_to_wire(&Desired::empty(18080)),
        known: vec![ManagedDigestWire {
            path: "/etc/apt/keyrings/pakomichi.gpg".to_owned(),
            sha256: SHA.to_owned(),
        }],
    });
    let text = format!(
        concat!(
            r#"{{"desired":{{"keyring_hex":"9901ff","port":18080,"sources":[{{"repositories":"#,
            r#"[{{"activated":["sampleapp"],"label":"pakomichi-sampleapp-strict"}}],"#,
            r#""source_key":"sampleapp"}}]}},"known":[{{"path":"/etc/apt/keyrings/pakomichi.gpg","#,
            r#""sha256":"{SHA}"}}],"operation_id":"{OPERATION}","previous":{{"keyring_hex":"","#,
            r#""port":18080,"sources":[]}},"schema_version":1,"type":"apply_apt"}}"#
        ),
        SHA = SHA,
        OPERATION = OPERATION
    );
    assert_eq!(encode(&request), text);
    assert_eq!(decode::<ApplyRequest>(&text)?, request);
    let drifted = ApplyResponse::Drifted(DriftedWire {
        drift: vec![DriftWire {
            path: "/etc/apt/sources.list.d/pakomichi-sampleapp.sources".to_owned(),
            kind: "changed".to_owned(),
        }],
    });
    assert_eq!(
        encode(&drifted),
        concat!(
            r#"{"drift":[{"kind":"changed","path":"/etc/apt/sources.list.d/"#,
            r#"pakomichi-sampleapp.sources"}],"schema_version":1,"type":"drifted"}"#
        )
    );
    Ok(())
}

#[test]
fn an_unknown_field_in_any_nested_part_is_refused() {
    // A field the applier does not know might be a protection it would
    // silently ignore.
    for text in [
        r#"{"schema_version":1,"type":"apply_apt","operation_id":"x","known":[],"desired":{"port":1,"keyring_hex":"","sources":[],"uri":"http://evil/"},"previous":{"port":1,"keyring_hex":"","sources":[]}}"#,
        r#"{"schema_version":1,"type":"apply_apt","operation_id":"x","known":[{"path":"/etc/apt/keyrings/pakomichi.gpg","sha256":"00","mode":"0777"}],"desired":{"port":1,"keyring_hex":"","sources":[]},"previous":{"port":1,"keyring_hex":"","sources":[]}}"#,
    ] {
        assert!(decode::<ApplyRequest>(text).is_err(), "{text}");
    }
}

#[test]
fn the_desired_configuration_survives_the_wire_unchanged() -> TestResult {
    let original = desired();
    assert_eq!(desired_from_wire(&desired_to_wire(&original))?, original);
    let digests: BTreeMap<String, Sha256Digest> = [(
        "/etc/apt/preferences.d/pakomichi-sampleapp.pref".to_owned(),
        Sha256Digest::from_hex(SHA)?,
    )]
    .into_iter()
    .collect();
    assert_eq!(digests_from_wire(&digests_to_wire(&digests))?, digests);
    Ok(())
}

#[test]
fn hostile_values_are_refused_before_the_applier_sees_them() {
    let refused = |wire: AptConfigWire| desired_from_wire(&wire).is_err();
    let mut wire = desired_to_wire(&desired());
    wire.keyring_hex = "9901FF".to_owned();
    assert!(refused(wire.clone()), "uppercase hex");
    wire.keyring_hex = "990".to_owned();
    assert!(refused(wire.clone()), "odd hex");
    wire.keyring_hex = "00".repeat(MAX_KEYRING_BYTES + 1);
    assert!(refused(wire.clone()), "keyring over the limit");
    let mut twice = desired_to_wire(&desired());
    twice.sources[0].repositories[0].activated = vec!["sampleapp".into(), "sampleapp".into()];
    assert!(refused(twice), "a name twice");
    let mut many = desired_to_wire(&desired());
    many.sources = vec![many.sources[0].clone(); MAX_SOURCES + 1];
    assert!(refused(many), "too many sources");

    let entry = |path: &str, sha256: &str| ManagedDigestWire {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
    };
    for (entries, what) in [
        (vec![entry("/etc/passwd", SHA)], "a system file"),
        (
            vec![entry("/etc/apt/sources.list.d/debian.sources", SHA)],
            "another source's file",
        ),
        (
            vec![entry(
                "/etc/apt/sources.list.d/pakomichi-a/../../x.sources",
                SHA,
            )],
            "a path with ..",
        ),
        (
            vec![entry("/etc/apt/keyrings/pakomichi.gpg", "00")],
            "a short digest",
        ),
        (
            vec![
                entry("/etc/apt/keyrings/pakomichi.gpg", SHA),
                entry("/etc/apt/keyrings/pakomichi.gpg", SHA),
            ],
            "one path twice",
        ),
    ] {
        assert!(digests_from_wire(&entries).is_err(), "{what}");
    }
    assert!(is_operation_id(OPERATION));
    assert!(!is_operation_id("0123456789ABCDEF0123456789ABCDEF"));
    assert!(!is_operation_id("0123"));
}
