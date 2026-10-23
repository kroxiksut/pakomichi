// SPDX-License-Identifier: MIT OR Apache-2.0

//! Confirmed owner IDs of a source (migration 0002, R-003).
//!
//! A transfer changes a repository's owner ID, and attestations made earlier
//! keep the owner ID of their time, so a source keeps every owner ID an
//! administrator confirmed (`github::PinnedRepository`). The schema records
//! one append-only row per confirmation: the owner pinned when the source was
//! added, then each confirmed transfer. Recording a transfer moves the
//! current owner (`forge_repository.owner_id`); the owner ID changes in no
//! other way. Confirming a transfer is an explicit, interactive administrator
//! action; this module only records it.

use std::collections::BTreeSet;

use rusqlite::{ErrorCode, OptionalExtension, params};

use super::owner::{StateError, StateOwner};
use crate::github::{
    FORGE, OwnerId, OwnerLogin, PinnedRepository, RepositoryId, RepositoryIdentity, RepositoryName,
    WEB_ORIGIN,
};

/// How an owner ID was confirmed (`repository_owner_confirmation.kind`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerConfirmationKind {
    /// The owner when the source was added.
    Pinned,
    /// An administrator confirmed a transfer to this owner.
    Transfer,
}

impl OwnerConfirmationKind {
    const fn from_column(text: &str) -> Option<Self> {
        match text.as_bytes() {
            b"pinned" => Some(Self::Pinned),
            b"transfer" => Some(Self::Transfer),
            _ => None,
        }
    }
}

/// One recorded confirmation, as stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerConfirmation {
    pub owner_id: String,
    pub kind: OwnerConfirmationKind,
    pub confirmed_at: String,
}

/// Trigger messages of migration 0002 that refuse a transfer confirmation.
const TRANSFER_RULES: [&str; 2] = [
    "a transfer needs a pinned source",
    "a transfer confirms another owner",
];

impl StateOwner {
    /// Every owner confirmation of the source, oldest first. The last one
    /// names the current owner; an unknown source has none.
    pub fn owner_confirmations(
        &mut self,
        source_id: &str,
    ) -> Result<Vec<OwnerConfirmation>, StateError> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT owner_id, kind, confirmed_at FROM repository_owner_confirmation \
             WHERE source_id = ?1 ORDER BY id",
        )?;
        let rows = statement.query_map([source_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut confirmations = Vec::new();
        for row in rows {
            let (owner_id, kind, confirmed_at) = row?;
            let kind =
                OwnerConfirmationKind::from_column(&kind).ok_or(StateError::InvalidDatabase {
                    problem: "unknown owner confirmation kind",
                })?;
            confirmations.push(OwnerConfirmation {
                owner_id,
                kind,
                confirmed_at,
            });
        }
        Ok(confirmations)
    }

    /// The distinct confirmed owner IDs of the source.
    pub fn confirmed_owner_ids(&mut self, source_id: &str) -> Result<BTreeSet<String>, StateError> {
        Ok(self
            .owner_confirmations(source_id)?
            .into_iter()
            .map(|confirmation| confirmation.owner_id)
            .collect())
    }

    /// Records an administrator's confirmation of a transfer of the source
    /// to `owner_id` and makes it the current owner, in one statement. The
    /// schema refuses a source without a pinned owner and a confirmation of
    /// the current owner ([`StateError::OwnerConfirmationRefused`]); a
    /// move back to an earlier owner is recorded as a transfer again.
    pub fn confirm_owner_transfer(
        &mut self,
        source_id: &str,
        owner_id: &str,
        confirmed_at: &str,
    ) -> Result<(), StateError> {
        self.connection()
            .execute(
                "INSERT INTO repository_owner_confirmation \
                 (source_id, owner_id, kind, confirmed_at) VALUES (?1, ?2, 'transfer', ?3)",
                params![source_id, owner_id, confirmed_at],
            )
            .map_err(refused)?;
        Ok(())
    }

    /// Restores the pin of a GitHub source: its stored repository ID, current
    /// owner ID, owner login and name, plus every confirmed owner ID. An
    /// unknown source has none; a stored row that does not form a valid
    /// identity, or whose current owner was never confirmed, is
    /// [`StateError::InvalidDatabase`].
    pub fn pinned_repository(
        &mut self,
        source_id: &str,
    ) -> Result<Option<PinnedRepository>, StateError> {
        let row = self
            .connection()
            .query_row(
                "SELECT forge, repository_id, owner_id, canonical_url FROM forge_repository \
                 WHERE id = ?1",
                [source_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((forge, repository_id, owner_id, canonical_url)) = row else {
            return Ok(None);
        };
        if forge != FORGE {
            return Err(invalid("forge_repository.forge is not github"));
        }
        let repository_id = RepositoryId::new(decimal(&repository_id))
            .map_err(|_| invalid("forge_repository.repository_id is not a positive integer"))?;
        let owner_id = OwnerId::new(decimal(&owner_id))
            .map_err(|_| invalid("forge_repository.owner_id is not a positive integer"))?;
        let (owner, name) = canonical_path(&canonical_url)
            .ok_or_else(|| invalid("forge_repository.canonical_url is not a repository URL"))?;
        let owner = OwnerLogin::new(owner)
            .map_err(|_| invalid("forge_repository.canonical_url has an invalid owner login"))?;
        let name = RepositoryName::new(name).map_err(|_| {
            invalid("forge_repository.canonical_url has an invalid repository name")
        })?;
        let earlier = self
            .confirmed_owner_ids(source_id)?
            .iter()
            .map(|id| {
                OwnerId::new(decimal(id)).map_err(|_| {
                    invalid("repository_owner_confirmation.owner_id is not a positive integer")
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if !earlier.contains(&owner_id) {
            return Err(invalid(
                "forge_repository.owner_id is not a confirmed owner of the source",
            ));
        }
        let current = RepositoryIdentity::new(repository_id, owner_id, owner, name);
        Ok(Some(PinnedRepository::restore(current, earlier)))
    }
}

const fn invalid(problem: &'static str) -> StateError {
    StateError::InvalidDatabase { problem }
}

/// Parses stored decimal text; anything else (signs, spaces, overflow) gives
/// 0, which no identifier accepts.
fn decimal(text: &str) -> u64 {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return 0;
    }
    text.parse().unwrap_or(0)
}

/// The owner and name segments of `https://github.com/{owner}/{name}`.
fn canonical_path(url: &str) -> Option<(&str, &str)> {
    let path = url.strip_prefix(WEB_ORIGIN)?.strip_prefix('/')?;
    let (owner, name) = path.split_once('/')?;
    if name.contains('/') {
        return None;
    }
    Some((owner, name))
}

/// Maps a refusal by a migration 0002 trigger to its rule; any other error
/// stays a SQLite error.
fn refused(error: rusqlite::Error) -> StateError {
    if let rusqlite::Error::SqliteFailure(failure, Some(message)) = &error
        && failure.code == ErrorCode::ConstraintViolation
        && let Some(rule) = TRANSFER_RULES.iter().find(|rule| message.contains(**rule))
    {
        return StateError::OwnerConfirmationRefused { rule };
    }
    error.into()
}

#[cfg(test)]
#[path = "owners_tests.rs"]
mod tests;
