// SPDX-License-Identifier: MIT OR Apache-2.0

//! The intent journal of administrative applies (`admin_operation` of
//! migration 0001, ADR-013, P4-003a).
//!
//! SQLite and `/etc/apt` are not one transaction. The state owner writes
//! the intent first (`planned`, with the desired configuration, the one to
//! restore, and the digests the files hold), then asks the root applier,
//! then records how it ended and the digests the applier reports. A row
//! still `planned` after a crash means the outcome is unknown: it is
//! finished by sending the same request again before anything new starts.
//!
//! Columns: `desired_state_json` holds `{"backend":"apt","desired":…,
//! "previous":…}` in the `apply.sock` wire form; `previous_hashes_json` the
//! digests before; `staged_files_json` the digests the operation leaves
//! (the target while `planned`, what the applier reported afterwards).
//! Statuses used by APT: `planned`, `verified` (applied, read back, and
//! accepted by APT), `reconciled` (an interrupted operation finished on
//! recovery), `rolled_back` (the previous configuration is back), `failed`
//! (drift, an invalid request, or a failed restore). `staged`, `applied`
//! and `rolling_back` are not used: the applier performs those steps
//! inside one request.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::owner::{StateError, StateOwner};
use crate::apt::config::Desired;
use crate::apt::wire::{desired_from_wire, desired_to_wire, digests_from_wire, digests_to_wire};
use crate::cas::Sha256Digest;
use crate::ipc::channels::{AptConfigWire, ManagedDigestWire};

pub type Digests = BTreeMap<String, Sha256Digest>;

/// How an operation ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    Planned,
    Verified,
    Reconciled,
    RolledBack,
    Failed,
}

impl OperationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Verified => "verified",
            Self::Reconciled => "reconciled",
            Self::RolledBack => "rolled_back",
            Self::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::Planned,
            Self::Verified,
            Self::Reconciled,
            Self::RolledBack,
            Self::Failed,
        ]
        .into_iter()
        .find(|status| status.as_str() == text)
    }

    /// The desired configuration is what the files hold.
    const fn reached_desired(self) -> bool {
        matches!(self, Self::Verified | Self::Reconciled)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    backend: String,
    desired: AptConfigWire,
    previous: AptConfigWire,
}

/// One APT operation as recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AptOperation {
    pub id: String,
    pub desired: Desired,
    /// What a failed apply restores.
    pub previous: Desired,
    /// The digests the files held when the operation was planned.
    pub before: Digests,
    /// The target while planned; afterwards what the applier reported.
    pub after: Digests,
    pub status: OperationStatus,
}

/// What the next operation starts from.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AptState {
    /// The configuration of the last operation that reached its desired
    /// state; empty before the first one. A failed apply restores it.
    pub last_good: Option<Desired>,
    /// The digests the files hold, as Pakomichi's writes left them.
    pub known: Digests,
}

fn corrupt(problem: &'static str) -> StateError {
    StateError::CorruptRow {
        table: "admin_operation",
        problem,
    }
}

fn digests_json(digests: &Digests) -> String {
    serde_json::to_string(&digests_to_wire(digests)).unwrap_or_else(|_| "[]".to_owned())
}

fn parse_digests(text: &str) -> Result<Digests, StateError> {
    let wire: Vec<ManagedDigestWire> =
        serde_json::from_str(text).map_err(|_| corrupt("digests are not JSON"))?;
    digests_from_wire(&wire).map_err(|_| corrupt("invalid digests"))
}

fn row(
    id: String,
    state: &str,
    before: &str,
    after: &str,
    status: &str,
) -> Result<AptOperation, StateError> {
    let stored: StoredState =
        serde_json::from_str(state).map_err(|_| corrupt("state is not JSON"))?;
    if stored.backend != "apt" {
        return Err(corrupt("not an APT operation"));
    }
    Ok(AptOperation {
        desired: desired_from_wire(&stored.desired).map_err(|_| corrupt("invalid state"))?,
        previous: desired_from_wire(&stored.previous).map_err(|_| corrupt("invalid state"))?,
        before: parse_digests(before)?,
        after: parse_digests(after)?,
        status: OperationStatus::parse(status).ok_or_else(|| corrupt("unknown status"))?,
        id,
    })
}

const COLUMNS: &str =
    "id, desired_state_json, previous_hashes_json, staged_files_json, status FROM admin_operation";

impl StateOwner {
    fn apt_operations(&mut self, filter: &str) -> Result<Vec<AptOperation>, StateError> {
        let mut statement = self
            .connection()
            .prepare(&format!("SELECT {COLUMNS} {filter} ORDER BY rowid"))?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut operations = Vec::new();
        for result in rows {
            let (id, state, before, after, status) = result?;
            operations.push(row(id, &state, &before, &after, &status)?);
        }
        Ok(operations)
    }

    /// Operations whose outcome is unknown, oldest first.
    pub fn unfinished_apt_operations(&mut self) -> Result<Vec<AptOperation>, StateError> {
        self.apt_operations("WHERE status = 'planned'")
    }

    /// What the next operation starts from. Refused while an operation is
    /// unfinished: its outcome decides what the files hold.
    pub fn apt_state(&mut self) -> Result<AptState, StateError> {
        let operations = self.apt_operations("")?;
        if operations
            .iter()
            .any(|op| op.status == OperationStatus::Planned)
        {
            return Err(StateError::OperationUnfinished);
        }
        let known = operations
            .last()
            .map(|op| op.after.clone())
            .unwrap_or_default();
        let last_good = operations
            .iter()
            .rev()
            .find(|op| op.status.reached_desired())
            .map(|op| op.desired.clone());
        Ok(AptState { last_good, known })
    }

    /// Records the intent before the applier is asked.
    pub fn begin_apt_operation(
        &mut self,
        id: &str,
        desired: &Desired,
        previous: &Desired,
        before: &Digests,
        target: &Digests,
        at: &str,
    ) -> Result<(), StateError> {
        let state = serde_json::to_string(&StoredState {
            backend: "apt".to_owned(),
            desired: desired_to_wire(desired),
            previous: desired_to_wire(previous),
        })
        .map_err(|_| corrupt("state does not serialize"))?;
        let transaction = self.connection().transaction()?;
        let open: Option<String> = transaction
            .query_row(
                "SELECT id FROM admin_operation WHERE status = 'planned' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if open.is_some() {
            return Err(StateError::OperationUnfinished);
        }
        transaction.execute(
            "INSERT INTO admin_operation (id, desired_state_json, previous_hashes_json, \
             staged_files_json, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, 'planned', ?5, ?5)",
            params![id, state, digests_json(before), digests_json(target), at],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Records how a planned operation ended and what the files hold.
    pub fn finish_apt_operation(
        &mut self,
        id: &str,
        status: OperationStatus,
        after: &Digests,
        at: &str,
    ) -> Result<(), StateError> {
        if status == OperationStatus::Planned {
            return Err(StateError::OperationNotPlanned);
        }
        let changed = self.connection().execute(
            "UPDATE admin_operation SET status = ?2, staged_files_json = ?3, updated_at = ?4 \
             WHERE id = ?1 AND status = 'planned'",
            params![id, status.as_str(), digests_json(after), at],
        )?;
        if changed != 1 {
            return Err(StateError::OperationNotPlanned);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
