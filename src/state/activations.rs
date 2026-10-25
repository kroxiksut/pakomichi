// SPDX-License-Identifier: MIT OR Apache-2.0

//! The activation journal (`name_activation`, migration 0003; P2-009b,
//! ADR-022 point 3).
//!
//! A name is activated by a source once the apply that published its pin
//! was verified, and stays activated until it is deactivated. While it is
//! open, the name keeps its publisher when the distribution or another
//! source later offers it (`policy::ArtifactFacts::activated_earlier`). A
//! name is open in one source at most; the schema refuses a second.

use rusqlite::{OptionalExtension, params};

use super::owner::{StateError, StateOwner};
use crate::inventory::Ecosystem;

/// Whether an activation was recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activation {
    Recorded,
    /// The name was already open in this source.
    AlreadyOpen,
}

const fn ecosystem(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Deb => "deb",
        Ecosystem::Rpm => "rpm",
    }
}

impl StateOwner {
    fn open_activation(
        &mut self,
        kind: Ecosystem,
        name: &str,
    ) -> Result<Option<(i64, String)>, StateError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT id, source_id FROM name_activation \
                 WHERE ecosystem = ?1 AND native_name = ?2 AND ended_at IS NULL",
                params![ecosystem(kind), name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// Records that `source_id` activated `name`. A name open in another
    /// source is refused.
    pub fn record_activation(
        &mut self,
        source_id: &str,
        kind: Ecosystem,
        name: &str,
        at: &str,
    ) -> Result<Activation, StateError> {
        match self.open_activation(kind, name)? {
            Some((_, owner)) if owner == source_id => return Ok(Activation::AlreadyOpen),
            Some(_) => return Err(StateError::NameActivatedElsewhere),
            None => {}
        }
        self.connection().execute(
            "INSERT INTO name_activation (source_id, ecosystem, native_name, activated_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![source_id, ecosystem(kind), name, at],
        )?;
        Ok(Activation::Recorded)
    }

    /// Ends the open activation of `name` in `source_id`; `false` when there
    /// was none.
    pub fn end_activation(
        &mut self,
        source_id: &str,
        kind: Ecosystem,
        name: &str,
        at: &str,
    ) -> Result<bool, StateError> {
        let changed = self.connection().execute(
            "UPDATE name_activation SET ended_at = ?4 \
             WHERE source_id = ?1 AND ecosystem = ?2 AND native_name = ?3 AND ended_at IS NULL",
            params![source_id, ecosystem(kind), name, at],
        )?;
        Ok(changed == 1)
    }

    /// Every name open in `source_id` now.
    pub fn open_activations(
        &mut self,
        source_id: &str,
    ) -> Result<Vec<(Ecosystem, String)>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT ecosystem, native_name FROM name_activation \
             WHERE source_id = ?1 AND ended_at IS NULL ORDER BY ecosystem, native_name",
        )?;
        let rows = statement.query_map([source_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut open = Vec::new();
        for row in rows {
            let (kind, name) = row?;
            let kind = match kind.as_str() {
                "deb" => Ecosystem::Deb,
                "rpm" => Ecosystem::Rpm,
                _ => {
                    return Err(StateError::CorruptRow {
                        table: "name_activation",
                        problem: "ecosystem",
                    });
                }
            };
            open.push((kind, name));
        }
        Ok(open)
    }

    /// Whether `source_id` has `name` activated now: then it activated the
    /// name before anything that offers it later.
    pub fn activated_earlier(
        &mut self,
        source_id: &str,
        kind: Ecosystem,
        name: &str,
    ) -> Result<bool, StateError> {
        Ok(self
            .open_activation(kind, name)?
            .is_some_and(|(_, owner)| owner == source_id))
    }
}

#[cfg(test)]
#[path = "activations_tests.rs"]
mod tests;
