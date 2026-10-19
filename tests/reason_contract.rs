// SPDX-License-Identifier: MIT OR Apache-2.0

use pakomichi::error::{
    ObjectKind, ObjectReference, REASON_SCHEMA_VERSION, Reason, ReasonCode, ReasonEvent,
    SafeIdentifier, SafeText, SafeValueError,
};
use serde_json::json;
use std::path::Path;

fn must_succeed<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("expected success, got {error:?}"),
    }
}

fn must_fail<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => panic!("expected failure, got {value:?}"),
        Err(error) => error,
    }
}

fn source_reference() -> ObjectReference {
    ObjectReference::new(
        ObjectKind::Source,
        must_succeed(SafeIdentifier::new("source-1234")),
    )
}

fn safe_message() -> SafeText {
    must_succeed(SafeText::new("repository identity changed"))
}

#[test]
fn every_documented_reason_code_has_a_stable_wire_value() {
    let actual: Vec<String> = ReasonCode::ALL
        .into_iter()
        .map(|code| {
            let value = must_succeed(serde_json::to_value(code));
            let Some(code) = value.as_str() else {
                panic!("reason code must serialize as a string");
            };
            code.to_owned()
        })
        .collect();
    let expected = [
        "E_REPO_ID_CHANGED",
        "E_OWNER_TRANSFER",
        "E_ASSET_MUTATED",
        "E_ATTESTATION_INVALID",
        "E_SIGNATURE_POLICY",
        "E_FAMILY_UNAPPROVED",
        "E_SYSTEM_PACKAGE_CONFLICT",
        "E_SOURCE_AMBIGUOUS",
        "E_DEPENDENCY_UNSATISFIABLE",
        "E_PLATFORM_UNSUPPORTED",
        "E_SNAPSHOT_INCONSISTENT",
        "E_CACHE_DIGEST_MISMATCH",
        "E_SOURCE_STALE",
        "E_FORGE_UNAVAILABLE",
        "E_ADMIN_APPLY_FAILED",
        "E_DISK_EXHAUSTED",
    ];

    assert_eq!(expected, actual.as_slice());
}

#[test]
fn reason_event_has_a_version_object_reference_and_safe_message() {
    let event = ReasonEvent::new(Reason::new(
        ReasonCode::ERepoIdChanged,
        source_reference(),
        safe_message(),
    ));
    let serialized = must_succeed(serde_json::to_value(&event));

    assert_eq!(
        json!({
            "schema_version": 1,
            "event": "reason",
            "reason": {
                "code": "E_REPO_ID_CHANGED",
                "object": {"kind": "source", "id": "source-1234"},
                "message": "repository identity changed"
            }
        }),
        serialized
    );

    let round_trip = must_succeed(ReasonEvent::from_json(&serialized.to_string()));
    assert_eq!(event, round_trip);
    assert_eq!(REASON_SCHEMA_VERSION, round_trip.schema_version());
}

#[test]
fn cli_rendering_uses_only_the_stable_code_reference_and_safe_text() {
    let reason = Reason::new(
        ReasonCode::ERepoIdChanged,
        source_reference(),
        safe_message(),
    );

    assert_eq!(
        "[E_REPO_ID_CHANGED] source source-1234: repository identity changed",
        reason.to_string()
    );
}

#[test]
fn constructors_reject_secret_bearing_values() {
    let values = [
        "Authorization: Bearer example".to_owned(),
        "token=example".to_owned(),
        "password:hunter2".to_owned(),
        [
            "github",
            "_pat_",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ]
        .concat(),
        "https://user:credential@example.invalid/path".to_owned(),
        [
            "https://",
            "ghp",
            "_",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "@example.invalid/",
        ]
        .concat(),
        "fetch from https://user@example.invalid failed".to_owned(),
        ["-----BEGIN ", "PRIVATE KEY-----"].concat(),
        ["-----BEGIN ", "PGP PRIVATE KEY BLOCK-----"].concat(),
        ["key ", "AKIA", "ABCDEFGHIJKLMNOP"].concat(),
        ["xox", "b-", "123456789012-abcdef"].concat(),
        "api_key=example".to_owned(),
    ];

    for value in values {
        assert_eq!(
            Err(SafeValueError::SuspectedSecret),
            SafeText::new(value.clone()),
            "{value} must be rejected"
        );
    }

    assert_eq!(
        Err(SafeValueError::InvalidIdentifierCharacter),
        SafeIdentifier::new("https://example.invalid/source")
    );
}

#[test]
fn ordinary_package_and_key_wording_is_accepted() {
    let values = [
        "package slovakia-maps 1.0 is held",
        "package akiapp requires review",
        "repository signing private key permissions are too broad",
        "metadata key rotation is pending",
        "GitHub release ghp_ is not a token prefix here",
        "see https://example.invalid/releases?page=2",
        "AKIA alone is not an access key",
    ];

    for value in values {
        assert!(
            SafeText::new(value).is_ok(),
            "{value} must be accepted as safe text"
        );
    }
}

#[test]
fn reason_codes_match_the_error_specification() {
    let specification = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("en")
        .join("specifications")
        .join("errors.md");
    let text = must_succeed(std::fs::read_to_string(&specification));
    let documented: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| rest.split('`').next())
        .filter(|code| code.starts_with("E_"))
        .collect();
    let implemented: Vec<&str> = ReasonCode::ALL.iter().map(|code| code.as_str()).collect();

    assert_eq!(documented, implemented);
}

#[test]
fn deserialization_cannot_bypass_safe_text_validation() {
    let json = r#"{
        "schema_version": 1,
        "event": "reason",
        "reason": {
            "code": "E_FORGE_UNAVAILABLE",
            "object": {"kind": "source", "id": "source-1234"},
            "message": "Authorization: Bearer example"
        }
    }"#;

    let error = must_fail(ReasonEvent::from_json(json));
    assert!(error.to_string().contains("sensitive data"));
}

#[test]
fn unknown_schema_versions_and_fields_are_rejected() {
    let version_error = must_fail(ReasonEvent::from_json(
        r#"{
            "schema_version": 2,
            "event": "reason",
            "reason": {
                "code": "E_SOURCE_STALE",
                "object": {"kind": "source", "id": "source-1234"},
                "message": "source metadata is stale"
            }
        }"#,
    ));
    assert!(version_error.to_string().contains("schema version 2"));

    let field_error = must_fail(ReasonEvent::from_json(
        r#"{
            "schema_version": 1,
            "event": "reason",
            "extra": true,
            "reason": {
                "code": "E_SOURCE_STALE",
                "object": {"kind": "source", "id": "source-1234"},
                "message": "source metadata is stale"
            }
        }"#,
    ));
    assert!(field_error.to_string().contains("unknown field"));
}
