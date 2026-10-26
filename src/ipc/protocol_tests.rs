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
                action: AdminAction::SourceAdd(SourceAdd {
                    url: "https://github.com/kroxiksut/pchi-test".to_owned(),
                    observe: false,
                    signer: Some(".github/workflows/release.yml@tag".to_owned()),
                }),
            }),
            r#"{"action":{"kind":"source_add","observe":false,"signer":".github/workflows/release.yml@tag","url":"https://github.com/kroxiksut/pchi-test"},"schema_version":1,"type":"plan"}"#,
        ),
        (
            AdminRequest::Plan(PlanRequest {
                action: AdminAction::SourceActivate(SourceActivate {
                    source_id: "source-1".to_owned(),
                    packages: vec!["sampleapp".to_owned()],
                    policy: ActivationPolicy::Supplemental,
                }),
            }),
            r#"{"action":{"kind":"source_activate","packages":["sampleapp"],"policy":"supplemental","source_id":"source-1"},"schema_version":1,"type":"plan"}"#,
        ),
        (
            AdminRequest::Plan(PlanRequest {
                action: AdminAction::SourceAllowPinned(SourceAllowPinned {
                    source_id: "source-1".to_owned(),
                }),
            }),
            r#"{"action":{"kind":"source_allow_pinned","source_id":"source-1"},"schema_version":1,"type":"plan"}"#,
        ),
        (
            AdminRequest::Plan(PlanRequest {
                action: AdminAction::ReleaseApprove(ReleaseApprove {
                    source_id: "source-1".to_owned(),
                    release_id: 268_800_123,
                }),
            }),
            r#"{"action":{"kind":"release_approve","release_id":268800123,"source_id":"source-1"},"schema_version":1,"type":"plan"}"#,
        ),
        (
            AdminRequest::Plan(PlanRequest {
                action: AdminAction::Sync(SyncTarget {
                    source_id: None,
                    force: false,
                }),
            }),
            r#"{"action":{"force":false,"kind":"sync","source_id":null},"schema_version":1,"type":"plan"}"#,
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
            Response::Status(StatusReport {
                service_version: "0.0.0".to_owned(),
                operations_running: 2,
                loopback_port: Some(879),
                sources: vec![SourceStatus {
                    source_id: "github-1429109739".to_owned(),
                    url: "https://github.com/kroxiksut/pchi-test".to_owned(),
                    state: "active".to_owned(),
                    trust_floor: Some("attested".to_owned()),
                    pinned_consent: false,
                    last_verified_at: None,
                    signer: Some(".github/workflows/release.yml@tag".to_owned()),
                    activated: vec!["sampleapp".to_owned()],
                    updates_elsewhere: vec![UpdateElsewhere {
                        name: "sampleapp".to_owned(),
                        version: "1.1-1".to_owned(),
                        offered_by: "http://deb.debian.org/debian-security bookworm-security/main"
                            .to_owned(),
                    }],
                    apt_problems: vec![AptProblem {
                        name: Some("sampleapp-data".to_owned()),
                        reason_code: Some(ReasonCode::ESourceAmbiguous),
                        message: "same version elsewhere".to_owned(),
                    }],
                }],
            }),
            r#"{"loopback_port":879,"operations_running":2,"schema_version":1,"service_version":"0.0.0","sources":[{"activated":["sampleapp"],"apt_problems":[{"message":"same version elsewhere","name":"sampleapp-data","reason_code":"E_SOURCE_AMBIGUOUS"}],"last_verified_at":null,"pinned_consent":false,"signer":".github/workflows/release.yml@tag","source_id":"github-1429109739","state":"active","trust_floor":"attested","updates_elsewhere":[{"name":"sampleapp","offered_by":"http://deb.debian.org/debian-security bookworm-security/main","version":"1.1-1"}],"url":"https://github.com/kroxiksut/pchi-test"}],"type":"status"}"#.to_owned(),
        ),
        (
            Response::Operation(OperationView {
                operation_id: ID.to_owned(),
                action: AdminAction::Sync(SyncTarget {
                    source_id: None,
                    force: false,
                }),
                state: OperationState::Failed,
                outcome: Some(OperationOutcome {
                    message: "sync failed".to_owned(),
                    reason_codes: vec![ReasonCode::EAdminApplyFailed],
                }),
            }),
            format!(r#"{{"action":{{"force":false,"kind":"sync","source_id":null}},"operation_id":"{ID}","outcome":{{"message":"sync failed","reason_codes":["E_ADMIN_APPLY_FAILED"]}},"schema_version":1,"state":"failed","type":"operation"}}"#),
        ),
        (
            Response::Plan(PlanView {
                action: AdminAction::Sync(SyncTarget {
                    source_id: None,
                    force: false,
                }),
                plan_digest: "cd".repeat(32),
                summary: "synchronize 1 source".to_owned(),
                changes: vec![PlanChange {
                    kind: ChangeKind::WriteFile,
                    target: "/etc/apt/keyrings/pakomichi.gpg".to_owned(),
                    before: None,
                    after: Some("ef".repeat(32)),
                    risks: vec![ReasonCode::ESourceAmbiguous],
                }],
            }),
            format!(
                r#"{{"action":{{"force":false,"kind":"sync","source_id":null}},"changes":[{{"after":"{}","before":null,"kind":"write_file","risks":["E_SOURCE_AMBIGUOUS"],"target":"/etc/apt/keyrings/pakomichi.gpg"}}],"plan_digest":"{}","schema_version":1,"summary":"synchronize 1 source","type":"plan"}}"#,
                "ef".repeat(32),
                "cd".repeat(32)
            ),
        ),
        (
            Response::Refused(ActionRefusal {
                reason_code: Some(ReasonCode::ENameProvidedElsewhere),
                message: "sampleapp is installed from another source".to_owned(),
            }),
            r#"{"message":"sampleapp is installed from another source","reason_code":"E_NAME_PROVIDED_ELSEWHERE","schema_version":1,"type":"refused"}"#.to_owned(),
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
    let plan = r#"{"action":{"force":false,"kind":"sync","source_id":null},"schema_version":1,"type":"plan"}"#;
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
fn n029_socket_recovery_is_no_request_of_any_channel() {
    // `pchi doctor --repair` runs as root in the CLI (owner decision of
    // 2026-10-25): the unprivileged state owner never plans or runs it.
    let plan = r#"{"action":{"kind":"doctor_repair"},"schema_version":1,"type":"plan"}"#;
    assert_eq!(decode::<AdminRequest>(plan), Err(ProtocolError::Malformed));
    assert_eq!(decode::<StatusRequest>(plan), Err(ProtocolError::Malformed));
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
    let sync = AdminAction::Sync(SyncTarget {
        source_id: None,
        force: false,
    });
    let text = |summary: &str| Plan {
        summary: summary.to_owned(),
        changes: Vec::new(),
    };
    let digest = plan_digest(&sync, &text("synchronize 1 source"));
    assert_eq!(digest.len(), 64);
    assert_eq!(digest, plan_digest(&sync, &text("synchronize 1 source")));
    assert_ne!(digest, plan_digest(&sync, &text("synchronize 1 source ")));
}

#[test]
fn a_confirmation_binds_the_arguments_and_every_change_of_the_plan() {
    // A plan shown for one package must not confirm another one, and a
    // plan whose changes moved since it was shown is another plan.
    let activate = |package: &str| {
        AdminAction::SourceActivate(SourceActivate {
            source_id: "source-1".to_owned(),
            packages: vec![package.to_owned()],
            policy: ActivationPolicy::Supplemental,
        })
    };
    let plan = |after: &str| Plan {
        summary: "activate".to_owned(),
        changes: vec![PlanChange {
            kind: ChangeKind::WriteFile,
            target: "/etc/apt/preferences.d/pakomichi-sampleapp.pref".to_owned(),
            before: None,
            after: Some(after.to_owned()),
            risks: Vec::new(),
        }],
    };
    let shown = plan_digest(&activate("sampleapp"), &plan("aa"));
    assert_eq!(shown, plan_digest(&activate("sampleapp"), &plan("aa")));
    assert_ne!(shown, plan_digest(&activate("otherapp"), &plan("aa")));
    assert_ne!(shown, plan_digest(&activate("sampleapp"), &plan("bb")));
    let mut risky = plan("aa");
    risky.changes[0].risks.push(ReasonCode::ESourceAmbiguous);
    assert_ne!(shown, plan_digest(&activate("sampleapp"), &risky));
}

#[test]
fn an_action_without_its_protection_field_is_refused() {
    // `observe` and `force` have no default: a client that left them out
    // is refused, never read as either value.
    for text in [
        r#"{"schema_version":1,"type":"plan","action":{"kind":"source_add","url":"https://github.com/o/r"}}"#,
        r#"{"schema_version":1,"type":"plan","action":{"kind":"sync","source_id":null}}"#,
        r#"{"schema_version":1,"type":"plan","action":{"kind":"source_activate","source_id":"s","packages":["a"]}}"#,
        r#"{"schema_version":1,"type":"plan","action":{"kind":"source_add","url":"https://github.com/o/r","observe":false,"token":"x"}}"#,
    ] {
        assert!(decode::<AdminRequest>(text).is_err(), "{text}");
    }
}
