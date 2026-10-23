// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned, secret-resistant reason events shared by CLI and local APIs.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Version of a reason event without a sub-reason.
pub const REASON_SCHEMA_VERSION: u16 = 1;
/// Version of a reason event that carries `reason.subcode` (ADR-031); only
/// `E_ATTESTATION_INVALID` has one.
pub const REASON_SCHEMA_VERSION_SUBCODE: u16 = 2;

/// The sub-reasons of `E_ATTESTATION_INVALID` (ADR-030 point 7), the only
/// values `reason.subcode` may take.
pub const ATTESTATION_SUBCODES: [&str; 26] = [
    "bundle_too_large",
    "too_many_bundles",
    "bundle_malformed",
    "bundle_unsupported",
    "signature_invalid",
    "artifact_digest_mismatch",
    "certificate_untrusted",
    "certificate_time",
    "sct_invalid",
    "tlog_inclusion",
    "tlog_checkpoint",
    "tlog_promise",
    "tlog_entry",
    "timestamp_invalid",
    "no_verified_time",
    "identity_mismatch",
    "repository_id_mismatch",
    "owner_id_mismatch",
    "release_mismatch",
    "subject_mismatch",
    "workflow_mismatch",
    "ref_mismatch",
    "commit_mismatch",
    "runner_not_hosted",
    "statement_invalid",
    "trust_root_invalid",
];

/// Largest serialized reason event accepted by [`ReasonEvent::from_json`].
pub const MAX_REASON_EVENT_JSON_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    ERepoIdChanged,
    EOwnerTransfer,
    EAssetMutated,
    EAttestationInvalid,
    ESignaturePolicy,
    EFamilyUnapproved,
    ESystemPackageConflict,
    ESourceAmbiguous,
    EDependencyUnsatisfiable,
    EPlatformUnsupported,
    ESnapshotInconsistent,
    ECacheDigestMismatch,
    ESourceStale,
    EForgeUnavailable,
    EAdminApplyFailed,
    EDiskExhausted,
    EArtifactMalformed,
    EEvidenceDowngrade,
    EReleaseApprovalRequired,
    EExecutionPolicy,
    ESecurityContext,
    EChannelUnclear,
    ESystemNamespaceUnknown,
}

impl ReasonCode {
    pub const ALL: [Self; 23] = [
        Self::ERepoIdChanged,
        Self::EOwnerTransfer,
        Self::EAssetMutated,
        Self::EAttestationInvalid,
        Self::ESignaturePolicy,
        Self::EFamilyUnapproved,
        Self::ESystemPackageConflict,
        Self::ESourceAmbiguous,
        Self::EDependencyUnsatisfiable,
        Self::EPlatformUnsupported,
        Self::ESnapshotInconsistent,
        Self::ECacheDigestMismatch,
        Self::ESourceStale,
        Self::EForgeUnavailable,
        Self::EAdminApplyFailed,
        Self::EDiskExhausted,
        Self::EArtifactMalformed,
        Self::EEvidenceDowngrade,
        Self::EReleaseApprovalRequired,
        Self::EExecutionPolicy,
        Self::ESecurityContext,
        Self::EChannelUnclear,
        Self::ESystemNamespaceUnknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ERepoIdChanged => "E_REPO_ID_CHANGED",
            Self::EOwnerTransfer => "E_OWNER_TRANSFER",
            Self::EAssetMutated => "E_ASSET_MUTATED",
            Self::EAttestationInvalid => "E_ATTESTATION_INVALID",
            Self::ESignaturePolicy => "E_SIGNATURE_POLICY",
            Self::EFamilyUnapproved => "E_FAMILY_UNAPPROVED",
            Self::ESystemPackageConflict => "E_SYSTEM_PACKAGE_CONFLICT",
            Self::ESourceAmbiguous => "E_SOURCE_AMBIGUOUS",
            Self::EDependencyUnsatisfiable => "E_DEPENDENCY_UNSATISFIABLE",
            Self::EPlatformUnsupported => "E_PLATFORM_UNSUPPORTED",
            Self::ESnapshotInconsistent => "E_SNAPSHOT_INCONSISTENT",
            Self::ECacheDigestMismatch => "E_CACHE_DIGEST_MISMATCH",
            Self::ESourceStale => "E_SOURCE_STALE",
            Self::EForgeUnavailable => "E_FORGE_UNAVAILABLE",
            Self::EAdminApplyFailed => "E_ADMIN_APPLY_FAILED",
            Self::EDiskExhausted => "E_DISK_EXHAUSTED",
            Self::EArtifactMalformed => "E_ARTIFACT_MALFORMED",
            Self::EEvidenceDowngrade => "E_EVIDENCE_DOWNGRADE",
            Self::EReleaseApprovalRequired => "E_RELEASE_APPROVAL_REQUIRED",
            Self::EExecutionPolicy => "E_EXECUTION_POLICY",
            Self::ESecurityContext => "E_SECURITY_CONTEXT",
            Self::EChannelUnclear => "E_CHANNEL_UNCLEAR",
            Self::ESystemNamespaceUnknown => "E_SYSTEM_NAMESPACE_UNKNOWN",
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Source,
    Package,
    Release,
    Artifact,
    Snapshot,
    Operation,
    Cache,
    Platform,
}

impl ObjectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Package => "package",
            Self::Release => "release",
            Self::Artifact => "artifact",
            Self::Snapshot => "snapshot",
            Self::Operation => "operation",
            Self::Cache => "cache",
            Self::Platform => "platform",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafeValueError {
    Empty,
    TooLong {
        maximum: usize,
    },
    ControlCharacter,
    InvalidIdentifierCharacter,
    SuspectedSecret,
    UnsupportedSchemaVersion {
        actual: u16,
    },
    /// Not one of [`ATTESTATION_SUBCODES`].
    UnknownSubcode,
    /// A sub-reason with another code than `E_ATTESTATION_INVALID`.
    SubcodeNotAllowed,
    /// Version 1 with a sub-reason, or version 2 without one.
    SubcodeVersionMismatch,
}

impl fmt::Display for SafeValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("value must not be empty"),
            Self::TooLong { maximum } => write!(formatter, "value exceeds {maximum} bytes"),
            Self::ControlCharacter => formatter.write_str("control characters are not allowed"),
            Self::InvalidIdentifierCharacter => {
                formatter.write_str("identifier contains a disallowed character")
            }
            Self::SuspectedSecret => formatter.write_str("value resembles sensitive data"),
            Self::UnsupportedSchemaVersion { actual } => {
                write!(formatter, "unsupported reason schema version {actual}")
            }
            Self::UnknownSubcode => formatter.write_str("unknown reason subcode"),
            Self::SubcodeNotAllowed => {
                formatter.write_str("only E_ATTESTATION_INVALID carries a subcode")
            }
            Self::SubcodeVersionMismatch => formatter.write_str(
                "a subcode needs reason schema version 2, and version 2 needs a subcode",
            ),
        }
    }
}

impl std::error::Error for SafeValueError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeText(String);

impl SafeText {
    pub fn new(value: impl Into<String>) -> Result<Self, SafeValueError> {
        let value = value.into();
        validate_common(&value, 512)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for SafeText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SafeText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeIdentifier(String);

impl SafeIdentifier {
    pub fn new(value: impl Into<String>) -> Result<Self, SafeValueError> {
        let value = value.into();
        validate_common(&value, 160)?;

        if !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:+".contains(character))
        {
            return Err(SafeValueError::InvalidIdentifierCharacter);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for SafeIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SafeIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// A sub-reason of `E_ATTESTATION_INVALID`, one of [`ATTESTATION_SUBCODES`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReasonSubcode(&'static str);

impl ReasonSubcode {
    pub fn new(value: &str) -> Result<Self, SafeValueError> {
        ATTESTATION_SUBCODES
            .iter()
            .find(|known| **known == value)
            .map(|known| Self(known))
            .ok_or(SafeValueError::UnknownSubcode)
    }

    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ReasonSubcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Serialize for ReasonSubcode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for ReasonSubcode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReference {
    kind: ObjectKind,
    id: SafeIdentifier,
}

impl ObjectReference {
    pub const fn new(kind: ObjectKind, id: SafeIdentifier) -> Self {
        Self { kind, id }
    }

    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    pub fn id(&self) -> &SafeIdentifier {
        &self.id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    code: ReasonCode,
    object: ObjectReference,
    message: SafeText,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subcode: Option<ReasonSubcode>,
}

impl Reason {
    pub const fn new(code: ReasonCode, object: ObjectReference, message: SafeText) -> Self {
        Self {
            code,
            object,
            message,
            subcode: None,
        }
    }

    /// `E_ATTESTATION_INVALID` with its sub-reason (ADR-030 point 7,
    /// ADR-031).
    pub const fn attestation_invalid(
        object: ObjectReference,
        message: SafeText,
        subcode: ReasonSubcode,
    ) -> Self {
        Self {
            code: ReasonCode::EAttestationInvalid,
            object,
            message,
            subcode: Some(subcode),
        }
    }

    pub const fn subcode(&self) -> Option<ReasonSubcode> {
        self.subcode
    }

    pub const fn code(&self) -> ReasonCode {
        self.code
    }

    pub fn object(&self) -> &ObjectReference {
        &self.object
    }

    pub fn message(&self) -> &SafeText {
        &self.message
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] {} {}: {}",
            self.code,
            self.object.kind.as_str(),
            self.object.id,
            self.message
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EventKind {
    Reason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReasonEvent {
    schema_version: u16,
    event: EventKind,
    reason: Reason,
}

impl ReasonEvent {
    /// Version 2 when the reason carries a sub-reason, otherwise version 1,
    /// so every event without one stays readable by a version 1 reader.
    pub const fn new(reason: Reason) -> Self {
        let schema_version = if reason.subcode.is_some() {
            REASON_SCHEMA_VERSION_SUBCODE
        } else {
            REASON_SCHEMA_VERSION
        };
        Self {
            schema_version,
            event: EventKind::Reason,
            reason,
        }
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn reason(&self) -> &Reason {
        &self.reason
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parses one reason event. Input longer than
    /// [`MAX_REASON_EVENT_JSON_BYTES`] is rejected before parsing (ADR-019).
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        if json.len() > MAX_REASON_EVENT_JSON_BYTES {
            return Err(serde_json::Error::custom(format!(
                "reason event is {} bytes; the limit is {MAX_REASON_EVENT_JSON_BYTES}",
                json.len()
            )));
        }
        serde_json::from_str(json)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasonEventWire {
    schema_version: u16,
    event: EventKind,
    reason: Reason,
}

impl TryFrom<ReasonEventWire> for ReasonEvent {
    type Error = SafeValueError;

    fn try_from(wire: ReasonEventWire) -> Result<Self, Self::Error> {
        let with_subcode = match wire.schema_version {
            REASON_SCHEMA_VERSION => false,
            REASON_SCHEMA_VERSION_SUBCODE => true,
            actual => return Err(SafeValueError::UnsupportedSchemaVersion { actual }),
        };
        if wire.reason.subcode.is_some() != with_subcode {
            return Err(SafeValueError::SubcodeVersionMismatch);
        }
        if with_subcode && wire.reason.code != ReasonCode::EAttestationInvalid {
            return Err(SafeValueError::SubcodeNotAllowed);
        }

        Ok(Self {
            schema_version: wire.schema_version,
            event: wire.event,
            reason: wire.reason,
        })
    }
}

impl<'de> Deserialize<'de> for ReasonEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReasonEventWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(D::Error::custom)
    }
}

fn validate_common(value: &str, maximum: usize) -> Result<(), SafeValueError> {
    if value.is_empty() {
        return Err(SafeValueError::Empty);
    }
    if value.len() > maximum {
        return Err(SafeValueError::TooLong { maximum });
    }
    if value.chars().any(char::is_control) {
        return Err(SafeValueError::ControlCharacter);
    }
    if resembles_sensitive_data(value) {
        return Err(SafeValueError::SuspectedSecret);
    }
    Ok(())
}

/// Rejects common credential shapes.
///
/// Markers match a structure (an assignment, a header, an armor line, or a
/// prefixed token of realistic length) rather than a bare word, so names such
/// as `slovakia-maps` or a sentence about a signing key are not rejected.
fn resembles_sensitive_data(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    const ASSIGNMENT_MARKERS: [&str; 12] = [
        "authorization:",
        "bearer ",
        "token=",
        "token:",
        "password=",
        "password:",
        "passwd=",
        "secret=",
        "secret:",
        "api_key=",
        "apikey=",
        "-----begin ",
    ];

    if ASSIGNMENT_MARKERS
        .iter()
        .any(|marker| lowercase.contains(marker))
    {
        return true;
    }

    // Prefixes are case-sensitive: the issuers emit them exactly like this.
    const TOKEN_PREFIXES: [TokenRule; 8] = [
        ("github_pat_", 20, is_token_character),
        ("ghp_", 20, is_token_character),
        ("gho_", 20, is_token_character),
        ("ghu_", 20, is_token_character),
        ("ghs_", 20, is_token_character),
        ("ghr_", 20, is_token_character),
        ("xox", 12, is_token_character),
        ("AKIA", 16, is_access_key_character),
    ];

    if TOKEN_PREFIXES
        .iter()
        .any(|&(prefix, minimum, allowed)| has_prefixed_token(value, prefix, minimum, allowed))
    {
        return true;
    }

    url_has_userinfo(&lowercase)
}

/// A token prefix, the minimum run of allowed characters after it, and that set.
type TokenRule = (&'static str, usize, fn(char) -> bool);

fn is_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '-'
}

fn is_access_key_character(character: char) -> bool {
    character.is_ascii_uppercase() || character.is_ascii_digit()
}

/// Whether `prefix` is followed by at least `minimum` allowed characters.
fn has_prefixed_token(
    value: &str,
    prefix: &str,
    minimum: usize,
    allowed: fn(char) -> bool,
) -> bool {
    value.match_indices(prefix).any(|(start, _)| {
        value[start + prefix.len()..]
            .chars()
            .take_while(|character| allowed(*character))
            .count()
            >= minimum
    })
}

/// Any user information in a URL authority (`user@`, `token@`, or
/// `user:password@`) can carry a credential, so it is rejected outright.
fn url_has_userinfo(lowercase: &str) -> bool {
    lowercase.match_indices("://").any(|(scheme_end, _)| {
        lowercase[scheme_end + 3..]
            .split(['/', '?', '#', ' '])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    })
}
