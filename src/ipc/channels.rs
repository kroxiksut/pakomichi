// SPDX-License-Identifier: MIT OR Apache-2.0

//! Messages of the channels added by ADR-035: `fetch.sock` (reader →
//! state owner), `sign.sock` and `inspect.sock` (state owner → one signer
//! or inspector instance); and of `apply.sock` (state owner → one root
//! applier instance, ADR-029 point 2, P4-003a). Same rules as the rest of the protocol
//! (ADR-029 point 5): `schema_version` 1 and `type`, unknown fields
//! refused, no defaults, one request type per channel.

use serde::{Deserialize, Serialize};

use super::protocol::ErrorBody;

/// An object of the CAS by its pinned identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    /// 64 lowercase hex digits.
    pub sha256: String,
    pub size: u64,
}

/// `fetch.sock`: the only request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FetchRequest {
    Fetch(ObjectRef),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FetchFailure {
    /// The HTTP status the reader answers with (500, 502, 504, 507).
    pub http_status: u16,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stored {
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FetchResponse {
    /// The object is in the CAS now; the reader reads and hashes it there.
    Stored(Stored),
    Failed(FetchFailure),
    Error(ErrorBody),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignText {
    /// The `Release` text to clear-sign.
    pub text: String,
}

/// `sign.sock`: one request per signer instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignRequest {
    Clearsign(SignText),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignResponse {
    Signed(Signed),
    /// The signer could not sign (no key, `gpg` failed); nothing was signed.
    Failed(Refusal),
    Error(ErrorBody),
}

/// `inspect.sock`: one request per inspector instance. The instance opens
/// the object in the CAS read-only and checks its digest itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InspectRequest {
    InspectDeb(ObjectRef),
}

/// The container of a DEB, as the inspector checked it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DebFormatWire {
    pub version: String,
    pub control_compression: String,
    pub control_member_bytes: u64,
    pub data_compression: String,
    pub data_member_bytes: u64,
    pub ignored_members: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DebInspected {
    pub format: DebFormatWire,
    /// The control paragraph, field for field: `[name, value]`.
    pub fields: Vec<(String, String)>,
    pub control_members: Vec<String>,
    pub maintainer_scripts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectRefusal {
    /// The reason code when the package itself is refused
    /// (`E_ARTIFACT_MALFORMED`, `E_PLATFORM_UNSUPPORTED`), absent for an
    /// environment failure that admits nothing.
    pub reason_code: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InspectResponse {
    Deb(DebInspected),
    Refused(InspectRefusal),
    Error(ErrorBody),
}

/// One logical repository of a source and its activated names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AptRepositoryWire {
    pub label: String,
    pub activated: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AptSourceWire {
    pub source_key: String,
    pub repositories: Vec<AptRepositoryWire>,
}

/// The desired APT configuration: the applier renders the files from it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AptConfigWire {
    pub port: u16,
    /// The local keyring, lowercase hex.
    pub keyring_hex: String,
    pub sources: Vec<AptSourceWire>,
}

/// A managed file and the SHA-256 Pakomichi last wrote to it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedDigestWire {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyApt {
    /// The `admin_operation` row this apply belongs to (32 lowercase hex).
    pub operation_id: String,
    pub desired: AptConfigWire,
    /// Restored when the apply fails.
    pub previous: AptConfigWire,
    /// What the state owner recorded: the digests the files should hold.
    pub known: Vec<ManagedDigestWire>,
}

/// `apply.sock`: one request per applier instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApplyRequest {
    ApplyApt(ApplyApt),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedWire {
    pub known: Vec<ManagedDigestWire>,
    pub changed: Vec<String>,
}

/// An apply that did not leave the desired state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotAppliedWire {
    /// What the managed files hold now, as Pakomichi wrote them.
    pub known: Vec<ManagedDigestWire>,
    pub reason_code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriftWire {
    pub path: String,
    /// `changed` (our file has other bytes or is gone) or `foreign` (a file
    /// Pakomichi did not write, or not a regular file).
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriftedWire {
    pub drift: Vec<DriftWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApplyResponse {
    Applied(AppliedWire),
    /// The previous configuration is in place again.
    RolledBack(NotAppliedWire),
    /// Files are not as Pakomichi left them; nothing was written.
    Drifted(DriftedWire),
    /// The request does not render; nothing was read or written.
    Invalid(Refusal),
    /// The restore failed too; `known` says what is on disk.
    Failed(NotAppliedWire),
    Error(ErrorBody),
}

#[cfg(test)]
#[path = "channels_tests.rs"]
mod tests;
