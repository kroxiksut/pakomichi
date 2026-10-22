// SPDX-License-Identifier: MIT OR Apache-2.0

//! Messages of the local IPC protocol, version 1 (ADR-029 points 2, 5–8).
//!
//! Every message is a JSON object with `schema_version` and `type`. Each
//! channel has its own request type: [`StatusRequest`] has no
//! administrative variant, so an administrative request on the status
//! channel fails to parse instead of being checked by a field of its own.
//! Wire types reject unknown fields and carry no defaults; a field that
//! confirms an action is required. The CLI and the server share this
//! module, so no default or name exists twice.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::cas::Sha256Digest;

/// The only protocol version this build speaks.
pub const PROTOCOL_VERSION: u64 = 1;

/// A request or response body without fields.
///
/// Field-less variants wrap this struct instead of being unit variants:
/// serde 1.0.229 ignores `deny_unknown_fields` on the unit variants of an
/// internally tagged enum, so `{"type":"ping","extra":true}` would parse.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// An operation identifier: 128 random bits as 32 lowercase hex digits
/// (ADR-029 point 7). It names an operation; it never grants authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId([u8; 16]);

impl OperationId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 32
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// An administrative action that needs a plan and a confirmation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAction {
    /// `pchi doctor --repair`: `systemctl reset-failed` for the units, then
    /// start the socket (ADR-021 point 3.1).
    DoctorRepair,
}

impl AdminAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DoctorRepair => "doctor_repair",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationQuery {
    pub operation_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    pub action: AdminAction,
}

/// Confirms exactly the plan that was shown. Both fields are required: a
/// request without `confirmed` is refused, never read as `false` or `true`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRequest {
    pub plan_digest: String,
    pub confirmed: bool,
}

/// Requests accepted on `status.sock`: read-only only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StatusRequest {
    Ping(Empty),
    Status(Empty),
    Operation(OperationQuery),
}

/// Requests accepted on `admin.sock`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminRequest {
    Ping(Empty),
    Status(Empty),
    Operation(OperationQuery),
    Plan(PlanRequest),
    Confirm(ConfirmRequest),
}

/// What the server reports about itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    pub service_version: String,
    pub operations_running: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationView {
    pub operation_id: String,
    pub action: AdminAction,
    pub state: OperationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanView {
    pub action: AdminAction,
    pub plan_digest: String,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Started {
    pub operation_id: String,
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// `schema_version` missing or not supported.
    UnsupportedVersion,
    /// Not valid JSON, an unknown `type` or field, a missing or mistyped
    /// field. Nothing of the request was applied.
    Malformed,
    /// No such operation for this caller; an unknown and a foreign
    /// identifier get the same answer.
    UnknownOperation,
    /// The confirmed plan is unknown, expired, or no longer the plan the
    /// server would run.
    StalePlan,
    /// `confirmed` was `false`.
    NotConfirmed,
    /// The server could not complete the request (for example, no random
    /// source for an operation identifier); nothing was started.
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: ErrorKind,
    pub message: String,
    pub supported_versions: Vec<u64>,
}

/// Responses on every channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong(Empty),
    Status(StatusReport),
    Operation(OperationView),
    Plan(PlanView),
    Started(Started),
    Error(ErrorBody),
}

impl Response {
    pub fn error(error: ErrorKind, message: &str) -> Self {
        Self::Error(ErrorBody {
            error,
            message: message.to_owned(),
            supported_versions: vec![PROTOCOL_VERSION],
        })
    }
}

/// Why a frame is not an acceptable message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    UnsupportedVersion,
    Malformed,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "unsupported schema_version",
            Self::Malformed => "malformed message",
        })
    }
}

impl std::error::Error for ProtocolError {}

impl ProtocolError {
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::UnsupportedVersion => ErrorKind::UnsupportedVersion,
            Self::Malformed => ErrorKind::Malformed,
        }
    }
}

/// A JSON value read with duplicate object keys refused at every depth.
///
/// `serde_json::Value` and `Map` keep the last of two equal keys without a
/// word, while other parsers keep the first: `{"confirmed":false,
/// "confirmed":true}` would mean different things to different readers.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Self)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = sequence.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut entries: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            let StrictValue(value) = entries.next_value()?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Parses one message: the object must carry `schema_version` 1, and the
/// rest must be exactly a `T`. Duplicate keys are refused at any depth.
/// Error details never quote the input.
pub fn decode<T: DeserializeOwned>(text: &str) -> Result<T, ProtocolError> {
    let StrictValue(value) = serde_json::from_str(text).map_err(|_| ProtocolError::Malformed)?;
    let Value::Object(mut object) = value else {
        return Err(ProtocolError::Malformed);
    };
    match object.remove("schema_version") {
        Some(Value::Number(version)) if version.as_u64() == Some(PROTOCOL_VERSION) => {}
        _ => return Err(ProtocolError::UnsupportedVersion),
    }
    serde_json::from_value(Value::Object(object)).map_err(|_| ProtocolError::Malformed)
}

/// Serialises one message with `schema_version` 1. Keys come out sorted,
/// so the text of a message is deterministic.
pub fn encode<T: Serialize>(message: &T) -> String {
    let mut object = match serde_json::to_value(message) {
        Ok(Value::Object(object)) => object,
        // Every protocol type is an internally tagged enum, hence an object.
        _ => Map::new(),
    };
    object.insert("schema_version".to_owned(), Value::from(PROTOCOL_VERSION));
    Value::Object(object).to_string()
}

/// The digest that a confirmation must repeat: SHA-256 over the action and
/// the exact plan text that was shown.
pub fn plan_digest(action: AdminAction, summary: &str) -> String {
    let mut bytes = Vec::with_capacity(summary.len() + 32);
    bytes.extend_from_slice(action.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(summary.as_bytes());
    Sha256Digest::of(&bytes).to_hex()
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
