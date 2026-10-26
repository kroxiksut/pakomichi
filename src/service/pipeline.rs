// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pchi source activate` and `pchi sync` (P4-001a step 1b, ADR-036
//! point 3).
//!
//! An activation shows the family revision, every name and architecture
//! the source offers, and the names to activate. Its confirmation saves
//! the next revision of the family (the names approved before plus the
//! listed ones), records the names' mode, synchronizes the source, and
//! applies the APT configuration. A name the source never offered, or a
//! source never synchronized, is refused at planning. A synchronization
//! changes nothing the administrator has not confirmed: it publishes new
//! versions of activated names only, as the policy admits them.

use std::collections::{BTreeMap, BTreeSet};

use super::{StateService, failed, refused};
use crate::apt::operation::Ended;
use crate::apt::policy::{Finding, Held};
use crate::error::ReasonCode;
use crate::family::{Family, FamilyState, MemberKey};
use crate::github::Transport;
use crate::inventory::Ecosystem;
use crate::ipc::protocol::{
    ActionRefusal, ActivationPolicy, ChangeKind, OperationOutcome, Plan, PlanChange,
    SourceActivate, SyncTarget,
};
use crate::policy::SourceMode;
use crate::state::StateOwner;
use crate::sync::publish::{Configured, HeldFamily};
use crate::sync::selection::SourceAptView;
use crate::sync::{ArtifactOutcome, SyncError, SyncReport};

/// The synchronization pipeline as the service uses it; the production one
/// talks to GitHub, the inspector, the signer, and the root applier.
pub trait Pipeline: Send + Sync {
    /// One pass of `source_id`; `force` asks the forge about every
    /// release's evidence (`pchi sync --force`, ADR-037 point 1).
    fn synchronize(
        &self,
        owner: &mut StateOwner,
        source_id: &str,
        at: &str,
        force: bool,
    ) -> Result<SyncReport, SyncError>;
    /// Applies the APT configuration every source asks for, with the pins
    /// APT can keep (`sync::publish::gate_pins`), and keeps the activation
    /// journal.
    fn configure(&self, owner: &mut StateOwner, at: &str) -> Result<Configured, String>;
    /// What APT will choose now for every source's names, judged against
    /// what Pakomichi promised (ADR-022 point 3); the error says why APT
    /// could not be asked.
    fn apt_view(&self, owner: &mut StateOwner) -> Result<BTreeMap<String, SourceAptView>, String>;
    /// The loopback port the APT sources name (ADR-036 point 2).
    fn loopback_port(&self) -> u16;
}

/// What the administrator is told about a family whose pin is not written.
fn held_line(family: &HeldFamily) -> String {
    let members: Vec<&str> = family.members.iter().map(String::as_str).collect();
    let members = members.join(", ");
    match &family.held {
        Held::NotListed { name } => format!(
            "{}: {members} published, not pinned yet: APT does not list {name} from this \
             source; run apt update, then pchi sync",
            family.source_id
        ),
        Held::Ambiguous(Finding::EqualVersionElsewhere {
            name,
            version,
            other,
        }) => format!(
            "{}: {members} not pinned ({}): {name} {version} is also offered by {other}",
            family.source_id,
            ReasonCode::ESourceAmbiguous.as_str()
        ),
        Held::Ambiguous(finding) => format!(
            "{}: {members} not pinned ({}): {finding:?}",
            family.source_id,
            finding.reason().as_str()
        ),
    }
}

const fn mode_of(policy: ActivationPolicy) -> SourceMode {
    match policy {
        ActivationPolicy::Supplemental => SourceMode::Supplemental,
        ActivationPolicy::Preferred => SourceMode::Preferred,
    }
}

const fn policy_text(policy: ActivationPolicy) -> &'static str {
    match policy {
        ActivationPolicy::Supplemental => "supplemental",
        ActivationPolicy::Preferred => "preferred",
    }
}

fn describe(family: &Family) -> String {
    let members: Vec<String> = family
        .members()
        .iter()
        .map(|(key, arches)| {
            let arches: Vec<&str> = arches.iter().map(String::as_str).collect();
            format!("{}({})", key.name, arches.join(","))
        })
        .collect();
    let state = match family.state() {
        FamilyState::Approved => "approved",
        FamilyState::Proposed => "proposed",
    };
    format!(
        "revision {} {state}: {}",
        family.revision(),
        members.join(", ")
    )
}

/// The family an activation would save, the one it replaces, and what the
/// source offers.
struct Activation {
    current: Option<Family>,
    next: Family,
    seen: BTreeMap<MemberKey, BTreeSet<String>>,
    names: Vec<MemberKey>,
}

fn activation(
    owner: &mut StateOwner,
    activate: &SourceActivate,
) -> Result<Activation, ActionRefusal> {
    let source = &activate.source_id;
    let row = owner
        .sources()
        .map_err(|error| refused(error.to_string()))?
        .into_iter()
        .find(|row| row.id == *source)
        .ok_or_else(|| refused(format!("no source {source}")))?;
    if row.state == "observing" {
        return Err(refused(format!(
            "source {source} was added with --observe and is never offered for activation"
        )));
    }
    // A source with Pinned consent is Pinned for the mode limits, whatever
    // its floor (ADR-027 point 5, P2-011a).
    if row.pinned_consent && activate.policy == ActivationPolicy::Preferred {
        return Err(refused(format!(
            "source {source} has Pinned consent and can be activated only with --policy \
             supplemental (ADR-027)"
        )));
    }
    let seen = owner
        .seen_names(source)
        .map_err(|error| refused(error.to_string()))?;
    if seen.is_empty() {
        return Err(refused(format!(
            "source {source} has not been synchronized yet; run pchi sync {source} first"
        )));
    }
    let mut names = Vec::new();
    for name in &activate.packages {
        let key = MemberKey::new(Ecosystem::Deb, name);
        if !seen.contains_key(&key) {
            return Err(refused(format!("source {source} never offered {name}")));
        }
        if !names.contains(&key) {
            names.push(key);
        }
    }
    if names.is_empty() {
        return Err(refused("name at least one package"));
    }
    let current = owner
        .family(source)
        .map_err(|error| refused(error.to_string()))?
        .map(|(_, family)| family);
    let mut members: BTreeMap<MemberKey, BTreeSet<String>> = match &current {
        Some(family) if family.state() == FamilyState::Approved => family.members().clone(),
        _ => BTreeMap::new(),
    };
    for key in &names {
        let arches = seen.get(key).cloned().unwrap_or_default();
        members.entry(key.clone()).or_default().extend(arches);
    }
    let revision = current.as_ref().map_or(0, Family::revision) + 1;
    let next = Family::restore(revision, FamilyState::Approved, members)
        .map_err(|error| refused(error.to_string()))?;
    Ok(Activation {
        current,
        next,
        seen,
        names,
    })
}

pub(super) fn report_lines(report: &SyncReport) -> String {
    let published: Vec<String> = report
        .generations
        .iter()
        .map(|(level, generation)| format!("{} generation {generation}", level.as_str()))
        .collect();
    let held = report
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.outcome,
                ArtifactOutcome::Held(..) | ArtifactOutcome::Rejected(..)
            )
        })
        .count();
    // A Pinned release waits for the administrator: say how to approve it.
    let mut waiting: Vec<(u64, &str)> = report
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.outcome,
                ArtifactOutcome::Held(ReasonCode::EReleaseApprovalRequired, _)
            )
        })
        .map(|artifact| (artifact.release_id, artifact.tag.as_str()))
        .collect();
    waiting.sort_unstable();
    waiting.dedup();
    let approvals: String = waiting
        .iter()
        .map(|(id, tag)| {
            format!(
                "\n{}: release {tag} waits for approval: pchi release approve {} {id}",
                report.source_id, report.source_id
            )
        })
        .collect();
    format!(
        "{}: {} release(s){}; published: {}; held or rejected: {held}{approvals}",
        report.source_id,
        report.releases,
        if report.truncated {
            " (older ones not listed)"
        } else {
            ""
        },
        if published.is_empty() {
            "nothing".to_owned()
        } else {
            published.join(", ")
        },
    )
}

impl<T: Transport> StateService<T> {
    pub(super) fn plan_activate(
        &self,
        owner: &mut StateOwner,
        activate: &SourceActivate,
    ) -> Result<Plan, ActionRefusal> {
        if self.pipeline.is_none() {
            return Err(refused(
                "this service runs without the synchronization pipeline",
            ));
        }
        let found = activation(owner, activate)?;
        let offered: Vec<String> = found
            .seen
            .iter()
            .map(|(key, arches)| {
                let arches: Vec<&str> = arches.iter().map(String::as_str).collect();
                format!("{}({})", key.name, arches.join(","))
            })
            .collect();
        let mut changes = vec![PlanChange {
            kind: ChangeKind::ApproveFamily,
            target: activate.source_id.clone(),
            before: found.current.as_ref().map(describe),
            after: Some(describe(&found.next)),
            risks: Vec::new(),
        }];
        for key in &found.names {
            changes.push(PlanChange {
                kind: ChangeKind::ActivateName,
                target: key.name.clone(),
                before: None,
                after: Some(policy_text(activate.policy).to_owned()),
                risks: Vec::new(),
            });
        }
        Ok(Plan {
            summary: format!(
                "activate {} in source {} ({}); the source offers {}; then synchronize it and \
                 apply the APT configuration",
                found
                    .names
                    .iter()
                    .map(|key| key.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                activate.source_id,
                policy_text(activate.policy),
                offered.join(", ")
            ),
            changes,
        })
    }

    pub(super) fn run_activate(
        &self,
        owner: &mut StateOwner,
        activate: &SourceActivate,
        plan: &Plan,
    ) -> Result<OperationOutcome, OperationOutcome> {
        let pipeline = self
            .pipeline
            .as_deref()
            .ok_or_else(|| failed("no synchronization pipeline; nothing was changed"))?;
        let found = activation(owner, activate).map_err(|refusal| failed(refusal.message))?;
        let shown = plan
            .changes
            .iter()
            .find(|change| change.kind == ChangeKind::ApproveFamily)
            .and_then(|change| change.after.clone());
        if shown != Some(describe(&found.next)) {
            return Err(failed(
                "the family changed since the plan; nothing was changed",
            ));
        }
        let at = (self.now)();
        owner
            .save_family(&activate.source_id, &found.next)
            .map_err(|error| failed(format!("{error}; nothing was changed")))?;
        for key in &found.names {
            owner
                .set_name_mode(&activate.source_id, key, mode_of(activate.policy), &at)
                .map_err(|error| failed(error.to_string()))?;
        }
        let mut lines = vec![format!(
            "family of {} is now {}",
            activate.source_id,
            describe(&found.next)
        )];
        let mut outcome = self.synchronize_and_configure(
            pipeline,
            owner,
            std::slice::from_ref(&activate.source_id),
            &at,
            false,
            &mut lines,
        );
        let message = lines.join("\n");
        match &mut outcome {
            Ok(done) | Err(done) => done.message = message,
        }
        outcome
    }

    pub(super) fn plan_sync(&self, target: &SyncTarget) -> Result<Plan, ActionRefusal> {
        if self.pipeline.is_none() {
            return Err(refused(
                "this service runs without the synchronization pipeline",
            ));
        }
        let sources = self.sync_targets(target)?;
        Ok(Plan {
            summary: format!(
                "synchronize {}: new releases are verified and admitted by the policy, activated \
                 names are published, and the APT configuration is applied; nothing new is \
                 activated{}",
                sources.join(", "),
                if target.force {
                    "; the evidence of every release is checked again with the forge"
                } else {
                    ""
                }
            ),
            changes: sources
                .into_iter()
                .map(|source| PlanChange {
                    kind: ChangeKind::SyncSource,
                    target: source,
                    before: None,
                    after: None,
                    risks: Vec::new(),
                })
                .collect(),
        })
    }

    pub(super) fn run_sync(
        &self,
        owner: &mut StateOwner,
        target: &SyncTarget,
    ) -> Result<OperationOutcome, OperationOutcome> {
        let pipeline = self
            .pipeline
            .as_deref()
            .ok_or_else(|| failed("no synchronization pipeline; nothing was changed"))?;
        let sources = self
            .sync_targets(target)
            .map_err(|refusal| failed(refusal.message))?;
        let at = (self.now)();
        let mut lines = Vec::new();
        let mut outcome = self.synchronize_and_configure(
            pipeline,
            owner,
            &sources,
            &at,
            target.force,
            &mut lines,
        );
        let message = lines.join("\n");
        match &mut outcome {
            Ok(done) | Err(done) => done.message = message,
        }
        outcome
    }

    fn sync_targets(&self, target: &SyncTarget) -> Result<Vec<String>, ActionRefusal> {
        let known: Vec<String> = self
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|source| source.source_id.clone())
            .collect();
        match &target.source_id {
            Some(id) if known.contains(id) => Ok(vec![id.clone()]),
            Some(id) => Err(refused(format!("no source {id}"))),
            None if known.is_empty() => Err(refused("there are no sources")),
            None => Ok(known),
        }
    }

    /// Every source in turn, then the APT configuration once. A source that
    /// fails does not stop the others; what it published before stays.
    pub(super) fn synchronize_and_configure(
        &self,
        pipeline: &dyn Pipeline,
        owner: &mut StateOwner,
        sources: &[String],
        at: &str,
        force: bool,
        lines: &mut Vec<String>,
    ) -> Result<OperationOutcome, OperationOutcome> {
        let mut codes = Vec::new();
        let mut failures = 0;
        for source in sources {
            match pipeline.synchronize(owner, source, at, force) {
                Ok(report) => {
                    lines.push(report_lines(&report));
                    codes.extend(report.reason_codes());
                }
                Err(error) => {
                    failures += 1;
                    lines.push(format!("{source}: not synchronized: {error}"));
                    codes.extend(error.reason_code());
                }
            }
        }
        let configured = pipeline.configure(owner, at).map(|configured| {
            for family in &configured.held {
                lines.push(held_line(family));
                if let Held::Ambiguous(finding) = &family.held {
                    codes.push(finding.reason());
                }
            }
            configured.ended
        });
        match configured {
            Ok(Ended::Verified { changed }) => lines.push(if changed.is_empty() {
                "APT configuration unchanged".to_owned()
            } else {
                format!("APT configuration applied: {}", changed.join(", "))
            }),
            Ok(Ended::Reconciled) => lines.push("APT configuration reconciled".to_owned()),
            Ok(other) => {
                failures += 1;
                lines.push(format!("APT configuration not applied: {other:?}"));
                codes.push(crate::error::ReasonCode::EAdminApplyFailed);
            }
            Err(error) => {
                failures += 1;
                lines.push(format!("APT configuration not applied: {error}"));
                codes.push(crate::error::ReasonCode::EAdminApplyFailed);
            }
        }
        let mut unique = BTreeSet::new();
        codes.retain(|code| unique.insert(code.as_str()));
        let outcome = OperationOutcome {
            message: String::new(),
            reason_codes: codes,
        };
        if failures == 0 {
            Ok(outcome)
        } else {
            Err(outcome)
        }
    }
}
