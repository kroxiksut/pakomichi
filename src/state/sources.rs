// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sources (`forge_repository`, P4-001a).
//!
//! A source is added with the repository ID and owner ID of its first
//! resolution (ADR-005); the address is only how it was found. The schema
//! keeps the identity immutable and records the pinned owner
//! (migrations 0001, 0002). A repository is a source at most once: adding
//! it again under another address (a rename, a redirect) is refused with
//! the existing source named, never recorded twice.
//!
//! The Attested signer the administrator confirmed with the source is kept
//! in `attested_signer` (migration 0004, ADR-036 point 1): append-only, the
//! latest row is the signer.

use rusqlite::{OptionalExtension, params};

use super::owner::{StateError, StateOwner};
use crate::attest::{AttestedSigner, SignerRef};
use crate::github::{FORGE, PinnedRepository};

/// One source as listed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRow {
    pub id: String,
    pub repository_id: String,
    pub owner_id: String,
    pub canonical_url: String,
    pub state: String,
    pub trust_floor: Option<String>,
    pub pinned_consent: bool,
    pub last_verified_at: Option<String>,
    pub signer: Option<AttestedSigner>,
}

/// The source identifier of a GitHub repository: stable, derived from the
/// repository ID, never from a name.
pub fn source_id(pinned: &PinnedRepository) -> String {
    format!("{FORGE}-{}", pinned.repository_id())
}

impl StateOwner {
    /// Records a new source, with its confirmed Attested signer when there
    /// is one. `observe` keeps it out of activation offers.
    pub fn add_source(
        &mut self,
        pinned: &PinnedRepository,
        observe: bool,
        signer: Option<&AttestedSigner>,
        at: &str,
    ) -> Result<String, StateError> {
        let id = source_id(pinned);
        let identity = pinned.identity();
        let transaction = self.connection().transaction()?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT id FROM forge_repository WHERE forge = ?1 AND repository_id = ?2",
                params![FORGE, identity.repository_id().to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return Err(StateError::SourceExists { id: existing });
        }
        transaction.execute(
            "INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, \
             first_seen_at, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                FORGE,
                identity.repository_id().to_string(),
                identity.owner_id().to_string(),
                identity.canonical_url(),
                at,
                if observe { "observing" } else { "registered" },
            ],
        )?;
        if let Some(signer) = signer {
            insert_signer(&transaction, &id, signer, at)?;
        }
        transaction.commit()?;
        Ok(id)
    }

    /// Records a new confirmed signer of `source`; the earlier ones stay.
    pub fn confirm_signer(
        &mut self,
        source: &str,
        signer: &AttestedSigner,
        at: &str,
    ) -> Result<(), StateError> {
        insert_signer(self.connection(), source, signer, at)
    }

    /// Marks a source `active` while it serves an activated name, and back
    /// to `registered` when none is left.
    /// An observed, suspended, or disabled source keeps its state.
    pub fn set_source_activity(&mut self, source: &str, active: bool) -> Result<(), StateError> {
        self.connection().execute(
            "UPDATE forge_repository SET state = ?2 \
             WHERE id = ?1 AND state IN ('registered', 'active')",
            params![source, if active { "active" } else { "registered" }],
        )?;
        Ok(())
    }

    /// The confirmed Attested signer of `source`, if it has one.
    pub fn attested_signer(&mut self, source: &str) -> Result<Option<AttestedSigner>, StateError> {
        let row: Option<(String, String)> = self
            .connection()
            .query_row(
                "SELECT workflow, signer_ref FROM attested_signer WHERE source_id = ?1 \
                 ORDER BY id DESC LIMIT 1",
                [source],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(workflow, rule)| parse_signer(&workflow, &rule))
            .transpose()
    }

    /// Every source, in the order they were added.
    pub fn sources(&mut self) -> Result<Vec<SourceRow>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT id, repository_id, owner_id, canonical_url, state, trust_floor, \
             pinned_consent_at IS NOT NULL, last_verified_at FROM forge_repository ORDER BY rowid",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(SourceRow {
                    id: row.get(0)?,
                    repository_id: row.get(1)?,
                    owner_id: row.get(2)?,
                    canonical_url: row.get(3)?,
                    state: row.get(4)?,
                    trust_floor: row.get(5)?,
                    pinned_consent: row.get(6)?,
                    last_verified_at: row.get(7)?,
                    signer: None,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        rows.into_iter()
            .map(|mut row| {
                row.signer = self.attested_signer(&row.id)?;
                Ok(row)
            })
            .collect()
    }
}

fn insert_signer(
    connection: &rusqlite::Connection,
    source: &str,
    signer: &AttestedSigner,
    at: &str,
) -> Result<(), StateError> {
    connection.execute(
        "INSERT INTO attested_signer (source_id, workflow, signer_ref, confirmed_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            source,
            signer.workflow(),
            signer.source_ref().to_string(),
            at
        ],
    )?;
    Ok(())
}

fn parse_signer(workflow: &str, rule: &str) -> Result<AttestedSigner, StateError> {
    let corrupt = |problem| StateError::CorruptRow {
        table: "attested_signer",
        problem,
    };
    let rule = SignerRef::parse(rule).map_err(|_| corrupt("signer_ref"))?;
    AttestedSigner::new(workflow, rule).map_err(|_| corrupt("workflow"))
}

#[cfg(test)]
#[path = "sources_tests.rs"]
mod tests;
