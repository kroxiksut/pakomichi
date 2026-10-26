// SPDX-License-Identifier: MIT OR Apache-2.0

//! The attestation bundles evidence was verified from (migration 0007,
//! ADR-034 point 1).
//!
//! The bundle bytes live in the blob store under their SHA-256; these rows
//! name them, so that evidence can be verified again offline and the
//! collector keeps them ([`StateOwner::referenced_bundles`] feeds
//! [`crate::cas::GcRoots`]). Rows are append-only and belong to the source
//! of their evidence; a piece of evidence names at most 16 bundles.

use std::collections::BTreeSet;

use rusqlite::{ErrorCode, OptionalExtension, params};

use super::owner::{StateError, StateOwner};
use crate::cas::Sha256Digest;

/// The trigger message of migration 0007 that bounds the bundles.
const BOUND_RULE: &str = "at most 16 bundles";

fn corrupt() -> StateError {
    StateError::CorruptRow {
        table: "evidence_bundle",
        problem: "bundle digest",
    }
}

impl StateOwner {
    /// Records that the evidence `evidence_id` of `source_id` was verified
    /// from `bundles`, all or nothing. Recording a bundle again changes
    /// nothing. Evidence that is not recorded for this source is
    /// [`StateError::UnknownEvidence`]; more than 16 bundles in all is
    /// [`StateError::TooManyBundles`].
    pub fn record_evidence_bundles(
        &mut self,
        source_id: &str,
        evidence_id: &str,
        bundles: &[Sha256Digest],
    ) -> Result<(), StateError> {
        let transaction = self.connection().transaction()?;
        let known = transaction
            .query_row(
                "SELECT 1 FROM trust_evidence WHERE id = ?1 AND source_id = ?2",
                params![evidence_id, source_id],
                |_| Ok(()),
            )
            .optional()?;
        if known.is_none() {
            return Err(StateError::UnknownEvidence);
        }
        for bundle in bundles {
            transaction
                .execute(
                    "INSERT INTO evidence_bundle (evidence_id, source_id, bundle_sha256) \
                     VALUES (?1, ?2, ?3) ON CONFLICT (evidence_id, bundle_sha256) DO NOTHING",
                    params![evidence_id, source_id, bundle.to_hex()],
                )
                .map_err(refused)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// The bundles recorded for `evidence_id`, in digest order; none for
    /// unknown evidence or evidence recorded before migration 0007.
    pub fn evidence_bundles(&mut self, evidence_id: &str) -> Result<Vec<Sha256Digest>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT bundle_sha256 FROM evidence_bundle WHERE evidence_id = ?1 \
             ORDER BY bundle_sha256",
        )?;
        let rows = statement.query_map([evidence_id], |row| row.get::<_, String>(0))?;
        rows.map(|row| Sha256Digest::from_hex(&row?).map_err(|_| corrupt()))
            .collect()
    }

    /// Every bundle that any evidence references: the collector must keep
    /// each of them (`GcRoots::pin`).
    pub fn referenced_bundles(&mut self) -> Result<BTreeSet<Sha256Digest>, StateError> {
        let mut statement = self
            .connection()
            .prepare("SELECT DISTINCT bundle_sha256 FROM evidence_bundle")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| Sha256Digest::from_hex(&row?).map_err(|_| corrupt()))
            .collect()
    }
}

/// Maps the migration 0007 bound to [`StateError::TooManyBundles`]; any
/// other error stays a SQLite error.
fn refused(error: rusqlite::Error) -> StateError {
    if let rusqlite::Error::SqliteFailure(failure, Some(message)) = &error
        && failure.code == ErrorCode::ConstraintViolation
        && message.contains(BOUND_RULE)
    {
        return StateError::TooManyBundles;
    }
    error.into()
}

#[cfg(test)]
#[path = "bundles_tests.rs"]
mod tests;
