// SPDX-License-Identifier: MIT OR Apache-2.0

//! The administrative service of the state owner (P4-001a): what
//! `admin.sock` plans and runs, and what `status.sock` reports.
//!
//! - **Plans are pure.** A plan reads state and asks GitHub, writes nothing,
//!   and the same state gives the same plan, so the digest the
//!   administrator confirmed still matches when the action runs (ADR-029
//!   point 8). The run recomputes what it checks and refuses when the world
//!   moved since the plan.
//! - **One operation at a time owns the state.** A plan asked while an
//!   operation runs is refused at once instead of waiting for it.
//! - **Status never waits.** It is served from a snapshot that every
//!   operation refreshes.
//!
//! `source add` finds or takes the Attested signer and confirms it with the
//! source (ADR-036 point 1). `source activate` and `sync` run the
//! synchronization pipeline (`pipeline`); a service built without one
//! refuses them.

mod pipeline;
mod signer;

use std::sync::{Arc, Mutex, PoisonError, RwLock, TryLockError};

use tokio::runtime::Handle;

pub use pipeline::Pipeline;
pub use signer::{Discovery, MAX_DISCOVERY_ASSETS, discover_signer};

use crate::attest::{AttestationVerifier, AttestedSigner};
use crate::github::{
    GitHubClient, PinnedRepository, RepositoryIdentity, Transport, parse_repository_address,
};
use crate::ipc::protocol::{
    ActionRefusal, AdminAction, ChangeKind, OperationOutcome, Plan, PlanChange, SourceStatus,
};
use crate::ipc::server::Service;
use crate::state::{StateError, StateOwner};

/// The clock of the journal: RFC 3339 in UTC.
pub type Now = fn() -> String;

pub struct StateService<T> {
    /// Shared with the lazy-fetch channel; one database, one owner.
    owner: Arc<Mutex<StateOwner>>,
    github: GitHubClient<T>,
    /// `None` when the trusted roots could not be had at start: no
    /// attestation is checked, and plans say so.
    verifier: Option<Arc<AttestationVerifier>>,
    runtime: Handle,
    /// `None`: activation and synchronization are refused.
    pipeline: Option<Box<dyn Pipeline>>,
    snapshot: RwLock<Vec<SourceStatus>>,
    now: Now,
}

fn refused(message: impl Into<String>) -> ActionRefusal {
    ActionRefusal {
        reason_code: None,
        message: message.into(),
    }
}

fn failed(message: impl Into<String>) -> OperationOutcome {
    OperationOutcome {
        message: message.into(),
        reason_codes: Vec::new(),
    }
}

/// The signer a new source gets, and how the plan explains it (ADR-036
/// point 1). Discovery never chooses between signers, and a named signer
/// must agree with a verified one.
fn choose_signer(
    named: Option<AttestedSigner>,
    discovery: Discovery,
) -> Result<(Option<AttestedSigner>, String), ActionRefusal> {
    let list = |signers: &[AttestedSigner]| {
        signers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    match (named, discovery) {
        (Some(named), Discovery::Found(found)) if named == found => {
            let note = format!("Attested signer {named}, as the latest release shows");
            Ok((Some(named), note))
        }
        (Some(named), Discovery::Found(found)) => Err(refused(format!(
            "the latest release is signed by {found}, not by {named}"
        ))),
        (Some(named), Discovery::Ambiguous(found)) if found.contains(&named) => {
            let note = format!("Attested signer {named}, one of {}", list(&found));
            Ok((Some(named), note))
        }
        (Some(named), Discovery::Ambiguous(found)) => Err(refused(format!(
            "the latest release is signed by {}, not by {named}",
            list(&found)
        ))),
        (Some(named), Discovery::NotFound(why)) => {
            let note = format!("Attested signer {named}, not seen in a release yet ({why})");
            Ok((Some(named), note))
        }
        (None, Discovery::Found(found)) => {
            let note = format!("Attested signer {found}, found in the latest release");
            Ok((Some(found), note))
        }
        (None, Discovery::Ambiguous(found)) => Err(refused(format!(
            "the latest release is signed by several workflows ({}); name one with \
             --workflow and --ref",
            list(&found)
        ))),
        (None, Discovery::NotFound(why)) => Ok((
            None,
            format!(
                "no Attested signer ({why}), so releases are admitted at Strict or Pinned only"
            ),
        )),
    }
}

/// How the plan names the pinned identity; the run must find the same.
fn pinned_identity(identity: &RepositoryIdentity) -> String {
    format!(
        "repository {} owner {} ({})",
        identity.repository_id(),
        identity.owner_id(),
        identity.full_name()
    )
}

impl<T: Transport> StateService<T> {
    pub fn new(
        owner: Arc<Mutex<StateOwner>>,
        github: GitHubClient<T>,
        verifier: Option<Arc<AttestationVerifier>>,
        runtime: Handle,
        now: Now,
    ) -> Result<Self, StateError> {
        let service = Self {
            owner,
            github,
            verifier,
            runtime,
            pipeline: None,
            snapshot: RwLock::new(Vec::new()),
            now,
        };
        {
            let mut owner = service.owner.lock().unwrap_or_else(PoisonError::into_inner);
            service.refresh(&mut owner)?;
        }
        Ok(service)
    }

    /// Activation and synchronization through `pipeline`.
    #[must_use]
    pub fn with_pipeline(mut self, pipeline: Box<dyn Pipeline>) -> Self {
        self.pipeline = Some(pipeline);
        self
    }

    fn refresh(&self, owner: &mut StateOwner) -> Result<(), StateError> {
        let mut sources = Vec::new();
        for row in owner.sources()? {
            let activated = owner
                .open_activations(&row.id)?
                .into_iter()
                .map(|(_, name)| name)
                .collect();
            sources.push(SourceStatus {
                source_id: row.id,
                url: row.canonical_url,
                state: row.state,
                trust_floor: row.trust_floor,
                pinned_consent: row.pinned_consent,
                last_verified_at: row.last_verified_at,
                signer: row.signer.map(|signer| signer.to_string()),
                activated,
            });
        }
        *self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner) = sources;
        Ok(())
    }

    /// The repository behind `url`, as GitHub resolves it now.
    fn resolve(&self, url: &str) -> Result<RepositoryIdentity, String> {
        let (owner, name) = parse_repository_address(url).map_err(|error| error.to_string())?;
        self.runtime
            .block_on(self.github.resolve_by_name(&owner, &name))
            .map(|resolved| resolved.identity)
            .map_err(|error| format!("GitHub: {error}"))
    }

    fn plan_source_add(
        &self,
        url: &str,
        observe: bool,
        named: Option<&str>,
    ) -> Result<Plan, ActionRefusal> {
        let named = named
            .map(|text| {
                AttestedSigner::parse(text).ok_or_else(|| {
                    refused("the signer is not .github/workflows/<file>@tag|refs/heads/<branch>")
                })
            })
            .transpose()?;
        let identity = self.resolve(url).map_err(refused)?;
        let pinned = PinnedRepository::pin(identity.clone());
        let id = crate::state::source_id(&pinned);
        let known = self
            .snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|source| source.source_id == id);
        if known {
            return Err(refused(format!("the repository is already source {id}")));
        }
        let discovery = self
            .runtime
            .block_on(discover_signer(
                &self.github,
                self.verifier.as_deref(),
                &pinned,
            ))
            .map_err(|error| refused(format!("GitHub: {error}")))?;
        let (signer, note) = choose_signer(named, discovery)?;
        let mut changes = vec![PlanChange {
            kind: ChangeKind::AddSource,
            target: id.clone(),
            before: None,
            after: Some(pinned_identity(&identity)),
            risks: Vec::new(),
        }];
        if let Some(signer) = &signer {
            changes.push(PlanChange {
                kind: ChangeKind::SetSigner,
                target: id.clone(),
                before: None,
                after: Some(signer.to_string()),
                risks: Vec::new(),
            });
        }
        Ok(Plan {
            summary: format!(
                "add source {id}: {} pinned by its IDs{}; {note}; nothing is activated",
                identity.canonical_url(),
                if observe { ", observed only" } else { "" }
            ),
            changes,
        })
    }

    fn run_source_add(
        &self,
        owner: &mut StateOwner,
        url: &str,
        observe: bool,
        plan: &Plan,
    ) -> Result<OperationOutcome, OperationOutcome> {
        let identity = self.resolve(url).map_err(failed)?;
        // The repository behind the address must still be the one shown.
        let shown = plan
            .changes
            .first()
            .and_then(|change| change.after.as_deref());
        if shown != Some(pinned_identity(&identity).as_str()) {
            return Err(failed(
                "the repository behind the address changed since the plan; nothing was added",
            ));
        }
        // The plan is the server's own, recomputed at confirmation: the
        // signer stored is exactly the one shown.
        let signer = match plan
            .changes
            .iter()
            .find(|change| change.kind == ChangeKind::SetSigner)
        {
            None => None,
            Some(change) => Some(
                change
                    .after
                    .as_deref()
                    .and_then(AttestedSigner::parse)
                    .ok_or_else(|| failed("the plan names no valid signer; nothing was added"))?,
            ),
        };
        let id = owner
            .add_source(
                &PinnedRepository::pin(identity),
                observe,
                signer.as_ref(),
                &(self.now)(),
            )
            .map_err(|error| failed(error.to_string()))?;
        Ok(OperationOutcome {
            message: match signer {
                Some(signer) => format!("added source {id} with Attested signer {signer}"),
                None => format!("added source {id} without an Attested signer"),
            },
            reason_codes: Vec::new(),
        })
    }
}

impl<T: Transport + 'static> Service for StateService<T> {
    fn plan(&self, action: &AdminAction) -> Result<Plan, ActionRefusal> {
        // A plan never waits for a running operation.
        let mut owner = match self.owner.try_lock() {
            Ok(owner) => owner,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(refused(
                    "another operation is running; try again when it ends",
                ));
            }
        };
        match action {
            AdminAction::SourceAdd(add) => {
                self.plan_source_add(&add.url, add.observe, add.signer.as_deref())
            }
            AdminAction::SourceActivate(activate) => self.plan_activate(&mut owner, activate),
            AdminAction::Sync(target) => self.plan_sync(target),
            AdminAction::DoctorRepair(_) => {
                Err(refused("doctor --repair is not part of this build yet"))
            }
        }
    }

    fn run(&self, action: &AdminAction, plan: &Plan) -> Result<OperationOutcome, OperationOutcome> {
        let mut owner = self.owner.lock().unwrap_or_else(PoisonError::into_inner);
        let result = match action {
            AdminAction::SourceAdd(add) => {
                self.run_source_add(&mut owner, &add.url, add.observe, plan)
            }
            AdminAction::SourceActivate(activate) => self.run_activate(&mut owner, activate, plan),
            AdminAction::Sync(target) => self.run_sync(&mut owner, target),
            AdminAction::DoctorRepair(_) => {
                Err(failed("not part of this build yet; nothing was changed"))
            }
        };
        if let Err(error) = self.refresh(&mut owner) {
            return Err(failed(format!("the state could not be read back: {error}")));
        }
        result
    }

    fn sources(&self) -> Vec<SourceStatus> {
        self.snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
