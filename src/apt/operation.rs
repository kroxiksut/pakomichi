// SPDX-License-Identifier: MIT OR Apache-2.0

//! An APT apply as the state owner runs it (P4-003a, ADR-013):
//! intent → root applier → outcome, and recovery of an interrupted one.
//!
//! 1. Nothing starts while an operation is `planned`: recover it first.
//! 2. The intent is written with the desired configuration, the last one
//!    that reached its desired state (restored on failure; empty before
//!    the first), and the digests the files hold.
//! 3. The applier is asked over `apply.sock`. Its answer is recorded with
//!    the digests it reports. No answer, or an answer that does not parse,
//!    leaves the row `planned`: the outcome is unknown, and only sending
//!    the same request again (recovery) settles it.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use super::config::Desired;
use super::wire::{desired_to_wire, digests_from_wire, digests_to_wire};
use crate::ipc::channels::{ApplyApt, ApplyRequest, ApplyResponse, DriftWire};
use crate::ipc::oneshot::call;
use crate::ipc::server::random_operation_id;
use crate::state::{AptOperation, Digests, OperationStatus, StateError, StateOwner};

/// The root applier, as the state owner reaches it.
pub trait Applier {
    fn call(&self, request: &ApplyRequest) -> Result<ApplyResponse, String>;
}

/// `apply.sock`.
#[derive(Clone, Debug)]
pub struct SocketApplier {
    pub path: PathBuf,
    /// Writing, reading back, and `apt-cache policy` twice in the worst case.
    pub timeout: Duration,
}

impl Applier for SocketApplier {
    fn call(&self, request: &ApplyRequest) -> Result<ApplyResponse, String> {
        call(&self.path, request, self.timeout).map_err(|error| error.to_string())
    }
}

/// How an operation ended, as recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ended {
    /// The desired configuration is in place and APT accepts it.
    Verified { changed: Vec<String> },
    /// An interrupted operation was finished on recovery.
    Reconciled,
    /// The previous configuration is back.
    RolledBack {
        reason_code: String,
        message: String,
    },
    /// Files are not as Pakomichi left them; nothing was written.
    Drifted { drift: Vec<DriftWire> },
    /// The applier refused the request; nothing was written.
    Invalid { message: String },
    /// The restore failed too; the files are as recorded.
    Failed {
        reason_code: String,
        message: String,
    },
}

#[derive(Debug)]
pub enum OperationError {
    State(StateError),
    /// The configuration does not render; nothing was recorded.
    Invalid(String),
    /// No usable answer: the row stays `planned` until recovery.
    NoAnswer {
        operation: String,
        detail: String,
    },
    Io(std::io::Error),
}

impl fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Invalid(detail) => write!(formatter, "invalid configuration: {detail}"),
            Self::NoAnswer { operation, detail } => write!(
                formatter,
                "the applier did not answer operation {operation} ({detail}); \
                 its outcome is unknown until it is recovered"
            ),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for OperationError {}

impl From<StateError> for OperationError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

fn target(desired: &Desired) -> Result<Digests, OperationError> {
    Ok(desired
        .render()
        .map_err(|error| OperationError::Invalid(error.to_string()))?
        .into_iter()
        .map(|file| {
            let digest = crate::cas::Sha256Digest::of(&file.bytes);
            (file.path, digest)
        })
        .collect())
}

/// Sends the recorded request and records the answer. `recovering` marks a
/// success as `reconciled` instead of `verified`.
fn settle(
    owner: &mut StateOwner,
    applier: &dyn Applier,
    operation: &AptOperation,
    recovering: bool,
    at: &str,
) -> Result<Ended, OperationError> {
    let request = ApplyRequest::ApplyApt(ApplyApt {
        operation_id: operation.id.clone(),
        desired: desired_to_wire(&operation.desired),
        previous: desired_to_wire(&operation.previous),
        known: digests_to_wire(&operation.before),
    });
    let no_answer = |detail: String| OperationError::NoAnswer {
        operation: operation.id.clone(),
        detail,
    };
    let response = applier.call(&request).map_err(no_answer)?;
    let digests = |known| digests_from_wire(known).map_err(|error| no_answer(error.0));
    let (status, after, ended) = match response {
        ApplyResponse::Applied(applied) => (
            if recovering {
                OperationStatus::Reconciled
            } else {
                OperationStatus::Verified
            },
            digests(&applied.known)?,
            if recovering {
                Ended::Reconciled
            } else {
                Ended::Verified {
                    changed: applied.changed,
                }
            },
        ),
        ApplyResponse::RolledBack(back) => (
            OperationStatus::RolledBack,
            digests(&back.known)?,
            Ended::RolledBack {
                reason_code: back.reason_code,
                message: back.message,
            },
        ),
        ApplyResponse::Failed(failed) => (
            OperationStatus::Failed,
            digests(&failed.known)?,
            Ended::Failed {
                reason_code: failed.reason_code,
                message: failed.message,
            },
        ),
        // Nothing was written: the files hold what they held before.
        ApplyResponse::Drifted(drifted) => (
            OperationStatus::Failed,
            operation.before.clone(),
            Ended::Drifted {
                drift: drifted.drift,
            },
        ),
        ApplyResponse::Invalid(refusal) => (
            OperationStatus::Failed,
            operation.before.clone(),
            Ended::Invalid {
                message: refusal.message,
            },
        ),
        ApplyResponse::Error(error) => return Err(no_answer(error.message)),
    };
    owner.finish_apt_operation(&operation.id, status, &after, at)?;
    Ok(ended)
}

/// Applies `desired`: records the intent, asks the applier, records how it
/// ended.
pub fn apply_apt(
    owner: &mut StateOwner,
    applier: &dyn Applier,
    desired: &Desired,
    at: &str,
) -> Result<Ended, OperationError> {
    let state = owner.apt_state()?;
    let previous = state
        .last_good
        .unwrap_or_else(|| Desired::empty(desired.port));
    let target = target(desired)?;
    // The previous configuration must render too, or it could not be
    // restored.
    self::target(&previous)?;
    let id = random_operation_id()
        .map_err(OperationError::Io)?
        .to_string();
    owner.begin_apt_operation(&id, desired, &previous, &state.known, &target, at)?;
    let operation = AptOperation {
        id,
        desired: desired.clone(),
        previous,
        before: state.known,
        after: target,
        status: OperationStatus::Planned,
    };
    settle(owner, applier, &operation, false, at)
}

/// Finishes every operation left `planned` by sending its request again.
pub fn recover_apt(
    owner: &mut StateOwner,
    applier: &dyn Applier,
    at: &str,
) -> Result<Vec<(String, Ended)>, OperationError> {
    let mut finished = Vec::new();
    for operation in owner.unfinished_apt_operations()? {
        let ended = settle(owner, applier, &operation, true, at)?;
        finished.push((operation.id, ended));
    }
    Ok(finished)
}

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;
