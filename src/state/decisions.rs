// SPDX-License-Identifier: MIT OR Apache-2.0

//! The append-only decision log (P2-009b, `decision_log` of migration 0001).
//!
//! Every admission decision is written with the rule, its version, the
//! outcome, the reason code, the text, and the facts it was made from as
//! canonical JSON (`policy::Facts`). An `allow` has no reason code; the
//! column holds an empty string. A decision equal to the latest one of the
//! same object, made from the same facts, is not written again, so a
//! synchronization that changes nothing leaves the log as it is (owner
//! decision of 2026-10-23). A logged decision is replayed by deciding its
//! facts again: a row whose facts no longer give its outcome was not written
//! by this code and is reported.

use rusqlite::{OptionalExtension, params};

use super::owner::{StateError, StateOwner};
use crate::cas::Sha256Digest;
use crate::policy::{self, Decision, Facts, FactsError};

/// What a decision is about (`decision_log.object_type`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionObject {
    Artifact,
    Source,
}

impl DecisionObject {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::Source => "source",
        }
    }
}

/// Whether a decision was written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recorded {
    Written {
        event_id: String,
    },
    /// Same rule, outcome, reason, and facts as the latest decision.
    Unchanged {
        event_id: String,
    },
}

/// One row of the log, as stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoggedDecision {
    pub event_id: String,
    pub object_type: String,
    pub object_id: String,
    pub rule_id: String,
    pub rule_version: i64,
    pub outcome: String,
    /// Empty for `allow`.
    pub reason_code: String,
    pub reason_text: String,
    pub evidence_json: String,
    pub created_at: String,
}

/// The result of deciding a logged decision's facts again.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Replay {
    /// The facts give the logged rule, outcome, and reason.
    Same,
    /// The rule has another version now; the old decision stands as made.
    RuleChanged { logged: i64, current: u32 },
    /// The facts give another decision than the row says.
    Different { now: Decision },
    /// The facts cannot be read (unknown field, version, or not JSON).
    Unreadable(FactsError),
}

impl StateOwner {
    /// Writes a decision unless it repeats the latest one of the object.
    pub fn record_decision(
        &mut self,
        object: DecisionObject,
        object_id: &str,
        facts: &Facts,
        decision: &Decision,
        at: &str,
    ) -> Result<Recorded, StateError> {
        let evidence = facts.to_json();
        let reason = decision.reason.map_or("", |code| code.as_str());
        let transaction = self.connection().transaction()?;
        let latest: Option<(String, String, i64, String, String, String)> = transaction
            .query_row(
                "SELECT event_id, rule_id, rule_version, outcome, reason_code, evidence_json \
                 FROM decision_log WHERE object_type = ?1 AND object_id = ?2 \
                 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                params![object.as_str(), object_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some((event_id, rule_id, rule_version, outcome, reason_code, logged_evidence)) =
            latest
            && rule_id == decision.rule.id()
            && rule_version == i64::from(decision.rule.version())
            && outcome == decision.outcome.as_str()
            && reason_code == reason
            && logged_evidence == evidence
        {
            return Ok(Recorded::Unchanged { event_id });
        }
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM decision_log WHERE object_type = ?1 AND object_id = ?2",
            params![object.as_str(), object_id],
            |row| row.get(0),
        )?;
        // Unique per object and position, and reproducible from the row.
        let event_id = format!(
            "decision-{}",
            Sha256Digest::of(
                format!(
                    "{}\n{object_id}\n{count}\n{at}\n{}",
                    object.as_str(),
                    facts.digest()
                )
                .as_bytes()
            )
            .to_hex()
        );
        transaction.execute(
            "INSERT INTO decision_log (event_id, object_type, object_id, rule_id, rule_version, \
             outcome, reason_code, reason_text, evidence_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event_id,
                object.as_str(),
                object_id,
                decision.rule.id(),
                i64::from(decision.rule.version()),
                decision.outcome.as_str(),
                reason,
                decision.text,
                evidence,
                at,
            ],
        )?;
        transaction.commit()?;
        Ok(Recorded::Written { event_id })
    }

    /// Every decision about the object, oldest first.
    pub fn decisions(
        &mut self,
        object: DecisionObject,
        object_id: &str,
    ) -> Result<Vec<LoggedDecision>, StateError> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT event_id, object_type, object_id, rule_id, rule_version, outcome, reason_code, \
             reason_text, evidence_json, created_at FROM decision_log \
             WHERE object_type = ?1 AND object_id = ?2 ORDER BY created_at, rowid",
        )?;
        let rows = statement.query_map(params![object.as_str(), object_id], |row| {
            Ok(LoggedDecision {
                event_id: row.get(0)?,
                object_type: row.get(1)?,
                object_id: row.get(2)?,
                rule_id: row.get(3)?,
                rule_version: row.get(4)?,
                outcome: row.get(5)?,
                reason_code: row.get(6)?,
                reason_text: row.get(7)?,
                evidence_json: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// Decides a logged decision's facts again and compares.
pub fn replay(logged: &LoggedDecision) -> Replay {
    let facts = match Facts::from_json(&logged.evidence_json) {
        Ok(facts) => facts,
        Err(error) => return Replay::Unreadable(error),
    };
    let now = policy::decide(&facts);
    let current = now.rule.version();
    if now.rule.id() == logged.rule_id && i64::from(current) != logged.rule_version {
        return Replay::RuleChanged {
            logged: logged.rule_version,
            current,
        };
    }
    let reason = now.reason.map_or("", |code| code.as_str());
    if now.rule.id() == logged.rule_id
        && now.outcome.as_str() == logged.outcome
        && reason == logged.reason_code
    {
        Replay::Same
    } else {
        Replay::Different { now }
    }
}

#[cfg(test)]
#[path = "decisions_tests.rs"]
mod tests;
