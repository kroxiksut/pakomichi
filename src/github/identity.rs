// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository identity and the pinning rule.
//!
//! A source is bound to GitHub's numeric repository ID and owner ID, never
//! to its name: `gh attestation verify` binds by name only (R-003), a rename
//! keeps the repository ID, and a new repository created under an old name
//! receives a new ID. The first resolution pins both IDs; every later
//! observation is compared with the pin and classified by
//! [`PinnedRepository::compare`].

use std::fmt;

use crate::error::{ObjectReference, Reason, ReasonCode, SafeText, SafeValueError};

/// The forge column value of `forge_repository` for this adapter.
pub const FORGE: &str = "github";

/// Origin of canonical repository URLs (`forge_repository.canonical_url`).
pub const WEB_ORIGIN: &str = "https://github.com";

/// A value from the API or from the user does not form a valid identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    ZeroId,
    EmptyName,
    NameTooLong { maximum: usize },
    InvalidNameCharacter,
    ReservedName,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroId => formatter.write_str("identifier must be a positive integer"),
            Self::EmptyName => formatter.write_str("name must not be empty"),
            Self::NameTooLong { maximum } => write!(formatter, "name exceeds {maximum} bytes"),
            Self::InvalidNameCharacter => {
                formatter.write_str("name contains a disallowed character")
            }
            Self::ReservedName => formatter.write_str("name is reserved"),
        }
    }
}

impl std::error::Error for IdentityError {}

macro_rules! numeric_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// GitHub never issues the ID 0, so it is refused.
            pub const fn new(value: u64) -> Result<Self, IdentityError> {
                if value == 0 {
                    return Err(IdentityError::ZeroId);
                }
                Ok(Self(value))
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        /// Decimal text, the form stored in the SQLite `TEXT` columns.
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0)
            }
        }
    };
}

numeric_id!(
    /// `forge_repository.repository_id`: immutable across renames and transfers.
    RepositoryId
);
numeric_id!(
    /// `forge_repository.owner_id`: changes when the repository is transferred.
    OwnerId
);
numeric_id!(
    /// `release_record.forge_release_id`.
    ReleaseId
);
numeric_id!(
    /// `artifact.asset_id`.
    AssetId
);

/// A user or organization login. It is case-insensitive on GitHub and may be
/// renamed; it is an address, not an identity. Validation keeps it a safe
/// URL path segment.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OwnerLogin(String);

impl OwnerLogin {
    /// 39 characters for ordinary accounts, plus room for the `_shortcode`
    /// suffix of enterprise managed users.
    pub const MAX_BYTES: usize = 100;

    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        validate_name(&value, Self::MAX_BYTES, |character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        })?;
        if value.starts_with('-') {
            return Err(IdentityError::InvalidNameCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OwnerLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A repository name: ASCII letters, digits, `.`, `-`, `_`, at most 100 bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RepositoryName(String);

impl RepositoryName {
    pub const MAX_BYTES: usize = 100;

    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        validate_name(&value, Self::MAX_BYTES, |character| {
            character.is_ascii_alphanumeric() || "-_.".contains(character)
        })?;
        if value == "." || value == ".." {
            return Err(IdentityError::ReservedName);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepositoryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn validate_name(
    value: &str,
    maximum: usize,
    allowed: fn(char) -> bool,
) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::EmptyName);
    }
    if value.len() > maximum {
        return Err(IdentityError::NameTooLong { maximum });
    }
    if !value.chars().all(allowed) {
        return Err(IdentityError::InvalidNameCharacter);
    }
    Ok(())
}

/// One validated observation of a repository from the API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryIdentity {
    repository_id: RepositoryId,
    owner_id: OwnerId,
    owner: OwnerLogin,
    name: RepositoryName,
}

impl RepositoryIdentity {
    pub const fn new(
        repository_id: RepositoryId,
        owner_id: OwnerId,
        owner: OwnerLogin,
        name: RepositoryName,
    ) -> Self {
        Self {
            repository_id,
            owner_id,
            owner,
            name,
        }
    }

    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    pub const fn owner_id(&self) -> OwnerId {
        self.owner_id
    }

    pub fn owner(&self) -> &OwnerLogin {
        &self.owner
    }

    pub fn name(&self) -> &RepositoryName {
        &self.name
    }

    /// `owner/name` as GitHub spells it.
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    /// Built from the validated owner and name, never copied from the API's
    /// `html_url`.
    pub fn canonical_url(&self) -> String {
        format!("{WEB_ORIGIN}/{}/{}", self.owner, self.name)
    }

    fn same_address(&self, other: &Self) -> bool {
        self.owner == other.owner && self.name == other.name
    }
}

/// The identity recorded when a source was added (`forge_repository`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedRepository(RepositoryIdentity);

impl PinnedRepository {
    /// The first resolution pins the repository ID and owner ID.
    pub const fn pin(identity: RepositoryIdentity) -> Self {
        Self(identity)
    }

    pub fn identity(&self) -> &RepositoryIdentity {
        &self.0
    }

    pub const fn repository_id(&self) -> RepositoryId {
        self.0.repository_id
    }

    pub const fn owner_id(&self) -> OwnerId {
        self.0.owner_id
    }

    /// Classifies a later observation. The repository ID is compared first,
    /// so a replacement is never reported as a rename or transfer.
    pub fn compare(&self, observed: &RepositoryIdentity) -> IdentityOutcome {
        let pinned = &self.0;
        if observed.repository_id != pinned.repository_id {
            return IdentityOutcome::Replaced {
                expected: pinned.repository_id,
                observed: observed.repository_id,
            };
        }
        if observed.owner_id != pinned.owner_id {
            return IdentityOutcome::Transferred {
                previous_owner_id: pinned.owner_id,
                current: observed.clone(),
            };
        }
        if !observed.same_address(pinned) {
            return IdentityOutcome::Renamed {
                previous_url: pinned.canonical_url(),
                current: observed.clone(),
            };
        }
        IdentityOutcome::Unchanged
    }

    /// Applies an accepted rename: the IDs stay, the address moves. The
    /// returned URL belongs in `repository_previous_address`. Any other
    /// outcome is returned unchanged as the error.
    pub fn follow_rename(
        &self,
        outcome: IdentityOutcome,
    ) -> Result<(Self, String), IdentityOutcome> {
        match outcome {
            IdentityOutcome::Renamed {
                previous_url,
                current,
            } if current.repository_id == self.0.repository_id
                && current.owner_id == self.0.owner_id =>
            {
                Ok((Self(current), previous_url))
            }
            other => Err(other),
        }
    }
}

/// Result of comparing an observation with the pinned identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityOutcome {
    Unchanged,
    /// Same repository ID and owner ID, new owner login or repository name.
    /// Allowed; the previous address is recorded.
    Renamed {
        previous_url: String,
        current: RepositoryIdentity,
    },
    /// Same repository ID, different owner ID. The source is suspended.
    Transferred {
        previous_owner_id: OwnerId,
        current: RepositoryIdentity,
    },
    /// A different repository ID: another repository now answers at this
    /// address or for this request. Refused, never followed.
    Replaced {
        expected: RepositoryId,
        observed: RepositoryId,
    },
}

impl IdentityOutcome {
    /// Whether synchronization may continue with this repository.
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Unchanged | Self::Renamed { .. })
    }

    /// The stable reason for a blocking outcome; `None` when accepted.
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::Unchanged | Self::Renamed { .. } => None,
            Self::Transferred { .. } => Some(ReasonCode::EOwnerTransfer),
            Self::Replaced { .. } => Some(ReasonCode::ERepoIdChanged),
        }
    }

    /// A reason event for a blocking outcome. The message contains only
    /// numeric IDs, never a name taken from the API.
    pub fn reason(&self, source: ObjectReference) -> Result<Option<Reason>, SafeValueError> {
        let (code, message) = match self {
            Self::Unchanged | Self::Renamed { .. } => return Ok(None),
            Self::Transferred {
                previous_owner_id,
                current,
            } => (
                ReasonCode::EOwnerTransfer,
                format!(
                    "repository {} moved from owner ID {previous_owner_id} to {}; source suspended",
                    current.repository_id, current.owner_id
                ),
            ),
            Self::Replaced { expected, observed } => (
                ReasonCode::ERepoIdChanged,
                format!("expected repository ID {expected}, the API returned {observed}; refused"),
            ),
        };
        Ok(Some(Reason::new(code, source, SafeText::new(message)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        repository: u64,
        owner: u64,
        login: &str,
        name: &str,
    ) -> Result<RepositoryIdentity, IdentityError> {
        Ok(RepositoryIdentity::new(
            RepositoryId::new(repository)?,
            OwnerId::new(owner)?,
            OwnerLogin::new(login)?,
            RepositoryName::new(name)?,
        ))
    }

    #[test]
    fn names_are_safe_path_segments() {
        assert!(OwnerLogin::new("octo-org").is_ok());
        assert!(OwnerLogin::new("user_corp").is_ok());
        assert_eq!(OwnerLogin::new(""), Err(IdentityError::EmptyName));
        assert_eq!(
            OwnerLogin::new("-x"),
            Err(IdentityError::InvalidNameCharacter)
        );
        assert_eq!(
            OwnerLogin::new("a/b"),
            Err(IdentityError::InvalidNameCharacter)
        );
        assert_eq!(
            OwnerLogin::new("a.b"),
            Err(IdentityError::InvalidNameCharacter)
        );
        assert!(RepositoryName::new("tool.rs-ng_2").is_ok());
        assert_eq!(RepositoryName::new(".."), Err(IdentityError::ReservedName));
        assert_eq!(
            RepositoryName::new("a%2Fb"),
            Err(IdentityError::InvalidNameCharacter)
        );
        assert_eq!(
            RepositoryName::new("x".repeat(101)),
            Err(IdentityError::NameTooLong { maximum: 100 })
        );
        assert_eq!(RepositoryId::new(0), Err(IdentityError::ZeroId));
    }

    #[test]
    fn replacement_wins_over_rename_and_transfer() -> Result<(), IdentityError> {
        let pinned = PinnedRepository::pin(identity(100, 10, "alice", "tool")?);
        let outcome = pinned.compare(&identity(200, 11, "bob", "other")?);
        assert_eq!(
            outcome,
            IdentityOutcome::Replaced {
                expected: RepositoryId::new(100)?,
                observed: RepositoryId::new(200)?
            }
        );
        assert!(pinned.follow_rename(outcome).is_err());
        Ok(())
    }

    #[test]
    fn a_case_only_change_is_a_rename() -> Result<(), IdentityError> {
        let pinned = PinnedRepository::pin(identity(100, 10, "alice", "tool")?);
        let outcome = pinned.compare(&identity(100, 10, "Alice", "tool")?);
        assert!(matches!(outcome, IdentityOutcome::Renamed { .. }));
        assert!(outcome.is_accepted());
        Ok(())
    }
}
