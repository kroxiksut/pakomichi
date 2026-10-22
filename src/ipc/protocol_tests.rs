// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID: &str = "00112233445566778899aabbccddeeff";

#[test]
fn every_request_variant_has_a_pinned_wire_shape() -> TestResult {
    // Pinned text, not a round trip through our own serializer: a renamed
    // field or variant must break this test (ADR-029 Verification).
    let status = [
        (
            StatusRequest::Ping(Empty {}),
            r#"{"schema_version":1,"type":"ping"}"#,
        ),
        (
            StatusRequest::Status(Empty {}),
            r#"{"schema_version":1,"type":"status"}"#,
        ),
        (
            StatusRequest::Operation(OperationQuery {
                operation_id: ID.to_owned(),
            }),
            r#"{"operation_id":"00112233445566778899aabbccddeeff","schema_version":1,"type":"operation"}"#,
        ),
    ];
    for (request, text) in status {
        assert_eq!(encode(&request), text);
        assert_eq!(decode::<StatusRequest>(text)?, request);
    }
    let admin = [
        (
            AdminRequest::Ping(Empty {}),
            r#"{"schema_version":1,"type":"ping"}"#,
        ),
        (
            AdminRequest::Status(Empty {}),
            r#"{"schema_version":1,"type":"status"}"#,
        ),
        (
            AdminRequest::Operation(OperationQuery {
                operation_id: ID.to_owned(),
            }),
            r#"{"operation_id":"00112233445566778899aabbccddeeff","schema_version":1,"type":"operation"}"#,
        ),
        (
            AdminRequest::Plan(PlanRequest {
                action: AdminAction::DoctorRepair,
            }),
            r#"{"action":"doctor_repair","schema_version":1,"type":"plan"}"#,
        ),
        (
            AdminRequest::Confirm(ConfirmRequest {
                plan_digest: "ab".repeat(32),
                confirmed: true,
            }),
            r#"{"confirmed":true,"plan_digest":"abababababababababababababababababababababababababababababababab","schema_version":1,"type":"confirm"}"#,
        ),
    ];
    for (request, text) in admin {
        assert_eq!(encode(&request), text);
        assert_eq!(decode::<AdminRequest>(text)?, request);
    }
    Ok(())
}

#[test]
fn every_response_variant_has_a_pinned_wire_shape() -> TestResult {
    let responses = [
        (Response::Pong(Empty {}), r#"{"schema_version":1,"type":"pong"}"#.to_owned()),
        (
            Response::Status(StatusReport { service_version: "0.0.0".to_owned(), operations_running: 2 }),
            r#"{"operations_running":2,"schema_version":1,"service_version":"0.0.0","type":"status"}"#.to_owned(),
        ),
        (
            Response::Operation(OperationView {
                operation_id: ID.to_owned(),
                action: AdminAction::DoctorRepair,
                state: OperationState::Running,
            }),
            format!(r#"{{"action":"doctor_repair","operation_id":"{ID}","schema_version":1,"state":"running","type":"operation"}}"#),
        ),
        (
            Response::Plan(PlanView {
                action: AdminAction::DoctorRepair,
                plan_digest: "cd".repeat(32),
                summary: "reset-failed; start socket".to_owned(),
            }),
            format!(
                r#"{{"action":"doctor_repair","plan_digest":"{}","schema_version":1,"summary":"reset-failed; start socket","type":"plan"}}"#,
                "cd".repeat(32)
            ),
        ),
        (
            Response::Started(Started { operation_id: ID.to_owned() }),
            format!(r#"{{"operation_id":"{ID}","schema_version":1,"type":"started"}}"#),
        ),
        (
            Response::error(ErrorKind::StalePlan, "plan changed"),
            r#"{"error":"stale_plan","message":"plan changed","schema_version":1,"supported_versions":[1],"type":"error"}"#.to_owned(),
        ),
    ];
    for (response, text) in responses {
        assert_eq!(encode(&response), text);
        assert_eq!(decode::<Response>(&text)?, response);
    }
    for (kind, text) in [
        (ErrorKind::UnsupportedVersion, "unsupported_version"),
        (ErrorKind::Malformed, "malformed"),
        (ErrorKind::UnknownOperation, "unknown_operation"),
        (ErrorKind::StalePlan, "stale_plan"),
        (ErrorKind::NotConfirmed, "not_confirmed"),
        (ErrorKind::Internal, "internal"),
    ] {
        assert_eq!(serde_json::to_value(kind)?, Value::from(text));
    }
    for (state, text) in [
        (OperationState::Queued, "queued"),
        (OperationState::Running, "running"),
        (OperationState::Succeeded, "succeeded"),
        (OperationState::Failed, "failed"),
    ] {
        assert_eq!(serde_json::to_value(state)?, Value::from(text));
    }
    Ok(())
}

#[test]
fn versions_other_than_one_are_refused() {
    for text in [
        r#"{"type":"ping"}"#,
        r#"{"schema_version":2,"type":"ping"}"#,
        r#"{"schema_version":0,"type":"ping"}"#,
        r#"{"schema_version":"1","type":"ping"}"#,
        r#"{"schema_version":1.0,"type":"ping"}"#,
        r#"{"schema_version":null,"type":"ping"}"#,
    ] {
        assert_eq!(
            decode::<StatusRequest>(text),
            Err(ProtocolError::UnsupportedVersion),
            "{text}"
        );
    }
}

#[test]
fn unknown_types_fields_and_values_are_refused() {
    for text in [
        "not json",
        "[1]",
        r#"{"schema_version":1}"#,
        r#"{"schema_version":1,"type":"reboot"}"#,
        r#"{"schema_version":1,"type":"ping","extra":true}"#,
        r#"{"schema_version":1,"type":"operation"}"#,
        r#"{"schema_version":1,"type":"operation","operation_id":7}"#,
        r#"{"schema_version":1,"type":"Ping"}"#,
    ] {
        assert_eq!(
            decode::<StatusRequest>(text),
            Err(ProtocolError::Malformed),
            "{text}"
        );
    }
}

#[test]
fn administrative_requests_do_not_parse_on_the_status_channel() {
    let plan = r#"{"action":"doctor_repair","schema_version":1,"type":"plan"}"#;
    let confirm = format!(
        r#"{{"confirmed":true,"plan_digest":"{}","schema_version":1,"type":"confirm"}}"#,
        "ab".repeat(32)
    );
    assert_eq!(decode::<StatusRequest>(plan), Err(ProtocolError::Malformed));
    assert_eq!(
        decode::<StatusRequest>(&confirm),
        Err(ProtocolError::Malformed)
    );
    assert!(decode::<AdminRequest>(plan).is_ok());
    assert!(decode::<AdminRequest>(&confirm).is_ok());
}

#[test]
fn a_confirmation_without_its_protection_field_is_refused() {
    // `confirmed` has no default: absent is neither true nor false.
    let missing = format!(
        r#"{{"plan_digest":"{}","schema_version":1,"type":"confirm"}}"#,
        "ab".repeat(32)
    );
    assert_eq!(
        decode::<AdminRequest>(&missing),
        Err(ProtocolError::Malformed)
    );
    let null = format!(
        r#"{{"confirmed":null,"plan_digest":"{}","schema_version":1,"type":"confirm"}}"#,
        "ab".repeat(32)
    );
    assert_eq!(decode::<AdminRequest>(&null), Err(ProtocolError::Malformed));
    let text = format!(
        r#"{{"confirmed":"yes","plan_digest":"{}","schema_version":1,"type":"confirm"}}"#,
        "ab".repeat(32)
    );
    assert_eq!(decode::<AdminRequest>(&text), Err(ProtocolError::Malformed));
}

#[test]
fn duplicate_keys_are_refused_at_any_depth() {
    // JSON parsers disagree on which duplicate wins; a message with one
    // must not mean different things to different readers.
    let digest = "ab".repeat(32);
    for text in [
        format!(
            r#"{{"confirmed":false,"confirmed":true,"plan_digest":"{digest}","schema_version":1,"type":"confirm"}}"#
        ),
        r#"{"schema_version":2,"schema_version":1,"type":"ping"}"#.to_owned(),
        r#"{"schema_version":1,"type":"status","type":"ping"}"#.to_owned(),
    ] {
        assert!(decode::<AdminRequest>(&text).is_err(), "{text}");
    }
    let nested = r#"{"schema_version":1,"type":"status","service_version":"1","operations_running":1,"operations_running":2}"#;
    assert!(decode::<Response>(nested).is_err());
}

#[test]
fn operation_ids_are_exactly_32_lowercase_hex_digits() {
    let id = OperationId::parse(ID);
    assert_eq!(id.map(|id| id.to_string()), Some(ID.to_owned()));
    for bad in [
        "",
        "0011",
        &ID.to_uppercase(),
        &format!("{ID}0"),
        "zz112233445566778899aabbccddeeff",
        "+0112233445566778899aabbccddeeff",
    ] {
        assert_eq!(OperationId::parse(bad), None, "{bad}");
    }
}

#[test]
fn the_plan_digest_binds_the_action_and_the_exact_text() {
    let digest = plan_digest(AdminAction::DoctorRepair, "reset-failed; start socket");
    assert_eq!(digest.len(), 64);
    assert_eq!(
        digest,
        plan_digest(AdminAction::DoctorRepair, "reset-failed; start socket")
    );
    assert_ne!(
        digest,
        plan_digest(AdminAction::DoctorRepair, "reset-failed; start socket ")
    );
}
