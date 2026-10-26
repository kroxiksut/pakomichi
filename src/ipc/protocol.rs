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
use crate::error::ReasonCode;

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

/// `pchi source add <url> [--observe]`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAdd {
    /// The repository address; the server validates it (HTTPS, a
    /// supported forge, no userinfo) and pins the repository by its ID.
    pub url: String,
    /// Only observe: never offered for activation. Required, so a client
    /// that forgot it is refused instead of read as either value.
    pub observe: bool,
    /// The Attested signer the administrator names, `<workflow>@<ref rule>`
    /// (`--workflow`, `--ref`; ADR-036 point 1). `None` lets the server
    /// look for it; either way the plan shows the signer to be stored.
    pub signer: Option<String>,
}

/// The mode an activation asks for (`policy-engine.md`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationPolicy {
    Supplemental,
    Preferred,
}

/// `pchi source activate <id> --packages <list> [--policy …]`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceActivate {
    pub source_id: String,
    pub packages: Vec<String>,
    pub policy: ActivationPolicy,
}

/// `pchi source allow-pinned <id>`: Pinned consent for one source
/// (ADR-027 point 4.1).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAllowPinned {
    pub source_id: String,
}

/// `pchi release approve <source-id> <release-id>`: approval of the exact
/// digests of one release of a Pinned source (ADR-027 point 4.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseApprove {
    pub source_id: String,
    /// The forge's release ID, as `pchi source inspect` shows it.
    pub release_id: u64,
}

/// `pchi sync [<id>] [--force]`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncTarget {
    /// Every source when absent.
    pub source_id: Option<String>,
    pub force: bool,
}

/// An administrative action that needs a plan and a confirmation. Its
/// arguments are part of the plan digest, so a confirmation applies to
/// exactly these arguments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdminAction {
    SourceAdd(SourceAdd),
    SourceActivate(SourceActivate),
    SourceAllowPinned(SourceAllowPinned),
    ReleaseApprove(ReleaseApprove),
    Sync(SyncTarget),
}

impl AdminAction {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SourceAdd(_) => "source_add",
            Self::SourceActivate(_) => "source_activate",
            Self::SourceAllowPinned(_) => "source_allow_pinned",
            Self::ReleaseApprove(_) => "release_approve",
            Self::Sync(_) => "sync",
        }
    }
}

/// What one change of a plan does (ADR-033 point 5).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A source is recorded and its repository pinned by ID.
    AddSource,
    /// The Attested signer of a source is recorded; `after` is
    /// `<workflow>@<ref rule>` (ADR-036 point 1).
    SetSigner,
    /// A name is activated in a source (its pin is written); `after` is
    /// the mode.
    ActivateName,
    /// The family of a source is saved at its next revision; `before` and
    /// `after` describe the revision, state, and names (ADR-036 point 3).
    ApproveFamily,
    /// A source is synchronized; what it publishes follows the policy.
    SyncSource,
    /// A managed file is written; `before`/`after` are SHA-256 digests.
    WriteFile,
    /// A managed file is removed.
    RemoveFile,
    /// A new generation of a logical repository is published.
    PublishGeneration,
    /// Pinned consent is recorded for a source (ADR-027 point 4.1).
    AllowPinned,
    /// One artifact of a release is approved by its exact SHA-256; `target`
    /// is the file name, `after` the digest (ADR-027 point 4.2).
    ApproveRelease,
}

/// One change of a plan, in its canonical form.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanChange {
    pub kind: ChangeKind,
    pub target: String,
    pub before: Option<String>,
    pub after: Option<String>,
    /// The reason codes of the risks the administrator accepts with it.
    pub risks: Vec<ReasonCode>,
}

/// What the server would do: a summary for people and the changes for
/// clients. The digest covers both, with the action and its arguments.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub summary: String,
    pub changes: Vec<PlanChange>,
}

/// Why the server will not plan an action (the request was well formed).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRefusal {
    pub reason_code: Option<ReasonCode>,
    pub message: String,
}

/// How a finished operation ended, for the client to show.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOutcome {
    pub message: String,
    pub reason_codes: Vec<ReasonCode>,
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

/// One source as the status API shows it (`specifications/cli-api.md`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStatus {
    pub source_id: String,
    pub url: String,
    /// `forge_repository.state`.
    pub state: String,
    /// The trust floor; absent before the first admission.
    pub trust_floor: Option<String>,
    pub pinned_consent: bool,
    pub last_verified_at: Option<String>,
    /// The confirmed Attested signer, `<workflow>@<ref rule>`; without one
    /// the source is admitted at Strict or Pinned only (ADR-036 point 1).
    pub signer: Option<String>,
    /// Names activated in this source now.
    pub activated: Vec<String>,
    /// Newer versions of activated names that other sources offer.
    pub updates_elsewhere: Vec<UpdateElsewhere>,
    /// Promises APT does not keep now, as of the last operation.
    pub apt_problems: Vec<AptProblem>,
}

/// A newer version of an activated name in another source, including a
/// distribution security update: the publisher stays, and switching is
/// the user's decision (ADR-022 point 3).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateElsewhere {
    pub name: String,
    pub version: String,
    /// The other source as APT names it: URI and suite.
    pub offered_by: String,
}

/// A promise of a source that APT does not keep now, or why APT's choice
/// could not be read (then `name` and `reason_code` are absent).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AptProblem {
    pub name: Option<String>,
    pub reason_code: Option<ReasonCode>,
    pub message: String,
}

/// What the server reports about itself and the sources it keeps.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    pub service_version: String,
    pub operations_running: u32,
    /// The loopback port the APT sources name; absent when the service runs
    /// without the synchronization pipeline. `pchi doctor` compares it with
    /// the reader socket's port (ADR-036 point 2).
    pub loopback_port: Option<u16>,
    pub sources: Vec<SourceStatus>,
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
    /// Present once the operation finished.
    pub outcome: Option<OperationOutcome>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanView {
    pub action: AdminAction,
    pub plan_digest: String,
    pub summary: String,
    pub changes: Vec<PlanChange>,
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
    /// The action is well formed but cannot be planned now.
    Refused(ActionRefusal),
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

/// The digest that a confirmation must repeat: SHA-256 over the canonical
/// JSON of the action with its arguments and the plan that was shown
/// (ADR-029 point 8, ADR-033 point 5). Fields serialize in declaration
/// order and the plan holds no map, so the same plan gives the same bytes.
pub fn plan_digest(action: &AdminAction, plan: &Plan) -> String {
    #[derive(Serialize)]
    struct Canonical<'a> {
        action: &'a AdminAction,
        plan: &'a Plan,
    }
    let text = serde_json::to_string(&Canonical { action, plan }).unwrap_or_default();
    Sha256Digest::of(text.as_bytes()).to_hex()
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
