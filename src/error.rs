// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned, secret-resistant reason events shared by CLI and local APIs.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const REASON_SCHEMA_VERSION: u16 = 1;

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
}

impl ReasonCode {
    pub const ALL: [Self; 16] = [
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
    TooLong { maximum: usize },
    ControlCharacter,
    InvalidIdentifierCharacter,
    SuspectedSecret,
    UnsupportedSchemaVersion { actual: u16 },
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
}

impl Reason {
    pub const fn new(code: ReasonCode, object: ObjectReference, message: SafeText) -> Self {
        Self {
            code,
            object,
            message,
        }
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
    pub const fn new(reason: Reason) -> Self {
        Self {
            schema_version: REASON_SCHEMA_VERSION,
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

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
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
        if wire.schema_version != REASON_SCHEMA_VERSION {
            return Err(SafeValueError::UnsupportedSchemaVersion {
                actual: wire.schema_version,
            });
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
