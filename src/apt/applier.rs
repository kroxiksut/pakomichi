// SPDX-License-Identifier: MIT OR Apache-2.0

//! The root side of an APT apply (P4-003a, ADR-013, ADR-017 point 7).
//!
//! The applier gets the *desired* configuration of every source, not file
//! bytes: it renders the files itself with [`render`], so the only files it
//! can write are Pakomichi's paths, every source points at
//! `127.0.0.1:<port>`, and every pin names Pakomichi's origin. A state
//! owner that is wrong or compromised cannot make it write anything else.
//!
//! One apply: render the desired and the previous configuration (both must
//! render before anything is touched), plan against the files and the
//! digests the state owner recorded, refuse on drift, write, read every
//! file back, and ask APT whether it accepts the result. A failure at any
//! step after the first write restores the previous configuration the same
//! way, so what remains is either the desired state or the previous one,
//! never a mix; only when the restore fails too is the outcome
//! [`Outcome::Failed`], with the digests the files actually have.
//!
//! An apply interrupted by a crash is finished by sending the same request
//! again: files that already hold the desired bytes are adopted, files
//! that still hold the recorded ones are written, removed files stay
//! removed.

use std::io;
use std::path::Path;

pub use super::config::Desired;
use super::config::{ConfigError, ManagedFile, is_managed_path};
use super::files::{self, ApplyError, Change, Drift, Known};
use super::wire::{desired_from_wire, digests_from_wire, digests_to_wire, is_operation_id};
use crate::cas::Sha256Digest;
use crate::error::ReasonCode;
use crate::ipc::channels::{
    AppliedWire, ApplyRequest, ApplyResponse, DriftWire, DriftedWire, NotAppliedWire, Refusal,
};

impl Desired {
    /// The digest of every file this configuration renders: what a
    /// successful apply leaves recorded.
    pub fn digests(&self) -> Result<Known, ConfigError> {
        Ok(Known(
            self.render()?
                .into_iter()
                .map(|file| (file.path, Sha256Digest::of(&file.bytes)))
                .collect(),
        ))
    }
}

/// Asks APT whether it accepts its configuration. Production runs
/// `apt-cache policy` ([`super::system::check_configuration`]).
pub trait AptCheck {
    fn check(&self) -> Result<(), String>;
}

/// The production check.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCheck;

impl AptCheck for SystemCheck {
    fn check(&self) -> Result<(), String> {
        super::system::check_configuration().map_err(|error| error.to_string())
    }
}

/// How an apply ended. Every variant carries the digests the managed files
/// have now, which the state owner records as they are.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The desired files are in place, read back, and APT accepts them.
    Applied { known: Known, changed: Vec<String> },
    /// The apply failed and the previous configuration is in place again.
    RolledBack {
        known: Known,
        reason: ReasonCode,
        detail: String,
    },
    /// Files are not as Pakomichi left them; nothing was written.
    Refused { drift: Vec<Drift> },
    /// The request does not render (an invalid name, label, or port);
    /// nothing was read or written.
    Invalid { detail: String },
    /// The apply failed and so did the restore: an explicit state for the
    /// state owner to show and recover from. `known` is what Pakomichi's
    /// completed writes left; a file someone changed meanwhile is drift on
    /// the next plan.
    Failed {
        known: Known,
        reason: ReasonCode,
        detail: String,
    },
}

/// The reason for a failed write. As root, a refused write means that the
/// security context forbids it (an integrity level below `/etc/apt`'s on
/// Astra Linux, R-006), not that a package or Pakomichi is wrong.
fn reason_of(error: &ApplyError) -> ReasonCode {
    match error {
        ApplyError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            ReasonCode::ESecurityContext
        }
        _ => ReasonCode::EAdminApplyFailed,
    }
}

/// After a write: every desired file holds its bytes and nothing else of
/// ours is left (the plan against the result is empty).
fn read_back(root: &Path, files: &[ManagedFile], known: &Known) -> Result<(), String> {
    let again = files::plan(root, files, known);
    if !again.drift.is_empty() {
        return Err(format!("{} files differ after writing", again.drift.len()));
    }
    if let Some(change) = again.changes.first() {
        return Err(format!("{} is not as written", change.path()));
    }
    Ok(())
}

/// Applies `desired` over `previous`, starting from the digests the state
/// owner recorded.
pub fn apply(
    root: &Path,
    desired: &Desired,
    previous: &Desired,
    known: Known,
    check: &dyn AptCheck,
) -> Outcome {
    apply_with(root, desired, previous, known, check, &mut |_, _| Ok(()))
}

/// [`apply`] with a hook before every change of the forward plan, so tests
/// can stop it at each step.
pub(crate) fn apply_with(
    root: &Path,
    desired: &Desired,
    previous: &Desired,
    mut known: Known,
    check: &dyn AptCheck,
    before: &mut dyn FnMut(usize, &Change) -> io::Result<()>,
) -> Outcome {
    let (wanted, restore) = match (desired.render(), previous.render()) {
        (Ok(wanted), Ok(restore)) => (wanted, restore),
        (Err(error), _) | (_, Err(error)) => {
            return Outcome::Invalid {
                detail: error.to_string(),
            };
        }
    };
    // A recorded path that is not Pakomichi's would be removed by the plan
    // if its digest matched: never act on it.
    if let Some(path) = known.0.keys().find(|path| !is_managed_path(path)) {
        return Outcome::Invalid {
            detail: format!("{path:?} is not a file Pakomichi manages"),
        };
    }
    let plan = files::plan(root, &wanted, &known);
    if !plan.drift.is_empty() {
        return Outcome::Refused { drift: plan.drift };
    }
    let failure = match files::apply_with(root, &plan, &mut known, before) {
        Err(error) => Some((reason_of(&error), error.to_string())),
        Ok(()) => match read_back(root, &wanted, &known) {
            Err(detail) => Some((ReasonCode::EAdminApplyFailed, detail)),
            Ok(()) => match check.check() {
                Err(detail) => Some((
                    ReasonCode::EAdminApplyFailed,
                    format!("APT refuses the configuration: {detail}"),
                )),
                Ok(()) => None,
            },
        },
    };
    let Some((reason, detail)) = failure else {
        return Outcome::Applied {
            known,
            changed: plan.changes.iter().map(|c| c.path().to_owned()).collect(),
        };
    };
    // Restore the previous configuration from what is on disk now.
    let back = files::plan(root, &restore, &known);
    if !back.drift.is_empty() {
        return Outcome::Failed {
            known,
            reason,
            detail: format!(
                "{detail}; the previous configuration was not restored: {} files changed meanwhile",
                back.drift.len()
            ),
        };
    }
    if let Err(error) = files::apply(root, &back, &mut known) {
        return Outcome::Failed {
            known,
            reason,
            detail: format!("{detail}; restoring the previous configuration failed: {error}"),
        };
    }
    if let Err(problem) = read_back(root, &restore, &known) {
        return Outcome::Failed {
            known,
            reason,
            detail: format!("{detail}; the restored configuration {problem}"),
        };
    }
    // A previous configuration APT rejects too means the fault is not in
    // what this apply wrote; say so instead of hiding it.
    let detail = match check.check() {
        Ok(()) => detail,
        Err(again) => format!("{detail}; APT also refuses the previous configuration: {again}"),
    };
    Outcome::RolledBack {
        known,
        reason,
        detail,
    }
}

fn drift_wire(drift: &Drift) -> DriftWire {
    match drift {
        Drift::Changed { path, .. } => DriftWire {
            path: path.clone(),
            kind: "changed".to_owned(),
        },
        Drift::Foreign { path } => DriftWire {
            path: path.clone(),
            kind: "foreign".to_owned(),
        },
    }
}

/// Answers one `apply.sock` request: every value is checked before any
/// file is read, then [`apply`] runs on `root`.
pub fn answer(root: &Path, request: ApplyRequest, check: &dyn AptCheck) -> ApplyResponse {
    let ApplyRequest::ApplyApt(request) = request;
    let invalid = |message: String| ApplyResponse::Invalid(Refusal { message });
    if !is_operation_id(&request.operation_id) {
        return invalid("not an operation identifier".to_owned());
    }
    let parsed = desired_from_wire(&request.desired).and_then(|desired| {
        Ok((
            desired,
            desired_from_wire(&request.previous)?,
            digests_from_wire(&request.known)?,
        ))
    });
    let (desired, previous, known) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => return invalid(error.to_string()),
    };
    match apply(root, &desired, &previous, Known(known), check) {
        Outcome::Applied { known, changed } => ApplyResponse::Applied(AppliedWire {
            known: digests_to_wire(&known.0),
            changed,
        }),
        Outcome::RolledBack {
            known,
            reason,
            detail,
        } => ApplyResponse::RolledBack(NotAppliedWire {
            known: digests_to_wire(&known.0),
            reason_code: reason.as_str().to_owned(),
            message: detail,
        }),
        Outcome::Refused { drift } => ApplyResponse::Drifted(DriftedWire {
            drift: drift.iter().map(drift_wire).collect(),
        }),
        Outcome::Invalid { detail } => invalid(detail),
        Outcome::Failed {
            known,
            reason,
            detail,
        } => ApplyResponse::Failed(NotAppliedWire {
            known: digests_to_wire(&known.0),
            reason_code: reason.as_str().to_owned(),
            message: detail,
        }),
    }
}

#[cfg(test)]
#[path = "applier_tests.rs"]
mod tests;
