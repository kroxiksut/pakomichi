// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::ipc::protocol::{ProtocolError, decode, encode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SHA: &str = "a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9";

#[test]
fn every_new_channel_message_has_a_pinned_wire_shape() -> TestResult {
    // Pinned text: a renamed field or variant breaks the test, not just a
    // round trip through our own serializer (ADR-029 Verification).
    let object = || ObjectRef {
        sha256: SHA.to_owned(),
        size: 800,
    };
    let fetch = FetchRequest::Fetch(object());
    let text = format!(r#"{{"schema_version":1,"sha256":"{SHA}","size":800,"type":"fetch"}}"#);
    assert_eq!(encode(&fetch), text);
    assert_eq!(decode::<FetchRequest>(&text)?, fetch);
    let failed = FetchResponse::Failed(FetchFailure {
        http_status: 502,
        message: "asset is gone (HTTP 404)".to_owned(),
    });
    assert_eq!(
        encode(&failed),
        r#"{"http_status":502,"message":"asset is gone (HTTP 404)","schema_version":1,"type":"failed"}"#
    );
    let sign = SignRequest::Clearsign(SignText {
        text: "Origin: Pakomichi\n".to_owned(),
    });
    assert_eq!(
        encode(&sign),
        r#"{"schema_version":1,"text":"Origin: Pakomichi\n","type":"clearsign"}"#
    );
    let inspect = InspectRequest::InspectDeb(object());
    assert_eq!(
        encode(&inspect),
        format!(r#"{{"schema_version":1,"sha256":"{SHA}","size":800,"type":"inspect_deb"}}"#)
    );
    let refused = InspectResponse::Refused(InspectRefusal {
        reason_code: Some("E_ARTIFACT_MALFORMED".to_owned()),
        message: "truncated archive".to_owned(),
    });
    assert_eq!(
        encode(&refused),
        r#"{"message":"truncated archive","reason_code":"E_ARTIFACT_MALFORMED","schema_version":1,"type":"refused"}"#
    );
    Ok(())
}

#[test]
fn a_request_of_another_channel_or_with_an_extra_field_is_refused() {
    let sign = encode(&SignRequest::Clearsign(SignText {
        text: "x".to_owned(),
    }));
    // A signing request sent to the fetch channel, and the reverse.
    assert_eq!(decode::<FetchRequest>(&sign), Err(ProtocolError::Malformed));
    let fetch = format!(r#"{{"schema_version":1,"sha256":"{SHA}","size":1,"type":"fetch"}}"#);
    assert_eq!(decode::<SignRequest>(&fetch), Err(ProtocolError::Malformed));
    assert_eq!(
        decode::<InspectRequest>(&fetch),
        Err(ProtocolError::Malformed)
    );
    // An extra field, a missing one, a negative size, another version.
    for text in [
        format!(
            r#"{{"schema_version":1,"sha256":"{SHA}","size":1,"type":"fetch","url":"http://x"}}"#
        ),
        r#"{"schema_version":1,"size":1,"type":"fetch"}"#.to_owned(),
        format!(r#"{{"schema_version":1,"sha256":"{SHA}","size":-1,"type":"fetch"}}"#),
    ] {
        assert_eq!(
            decode::<FetchRequest>(&text),
            Err(ProtocolError::Malformed),
            "{text}"
        );
    }
    assert_eq!(
        decode::<FetchRequest>(&fetch.replace("\"schema_version\":1", "\"schema_version\":2")),
        Err(ProtocolError::UnsupportedVersion)
    );
}
