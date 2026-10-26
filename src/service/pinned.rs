// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pchi source allow-pinned` and `pchi release approve` (ADR-027 point 4,
//! P2-011b).
//!
//! The Pinned level has no cryptographic provenance, so both steps belong
//! to the administrator: the consent names the risk and holds for one
//! source; the approval shows one release and the exact digests of its
//! artifacts and approves only those. A run recomputes the plan and
//! refuses when the release changed since it was shown. The approval is
//! followed by a synchronization of the source, so the approved bytes are
//! published as the policy admits them.

use super::pipeline::Pipeline;
use super::{StateService, failed, refused};
use crate::cas::Sha256Digest;
use crate::github::Transport;
use crate::ipc::protocol::{
    ActionRefusal, ChangeKind, OperationOutcome, Plan, PlanChange, ReleaseApprove,
};
use crate::state::{SourceRow, StateOwner};

/// What the consent accepts (ADR-027 point 4.1), shown before the `yes`.
pub const PINNED_RISK: &str = "a compromised publisher account, token, or CI can publish a \
                               malicious release that Pakomichi cannot detect";

fn source_row(owner: &mut StateOwner, source_id: &str) -> Result<SourceRow, ActionRefusal> {
    owner
        .sources()
        .map_err(|error| refused(error.to_string()))?
        .into_iter()
        .find(|row| row.id == source_id)
        .ok_or_else(|| refused(format!("no source {source_id}")))
}

impl<T: Transport> StateService<T> {
    pub(super) fn plan_allow_pinned(
        &self,
        owner: &mut StateOwner,
        source_id: &str,
    ) -> Result<Plan, ActionRefusal> {
        let row = source_row(owner, source_id)?;
        if row.pinned_consent {
            return Err(refused(format!(
                "source {source_id} has Pinned consent already"
            )));
        }
        Ok(Plan {
            summary: format!(
                "allow the Pinned level for {source_id}: releases without verified provenance \
                 can be admitted, and only repository-ID pinning and digest freezing protect \
                 them. Risk: {PINNED_RISK}. Every release still needs `pchi release approve`, \
                 only its approved digests are published, and the source can be activated only \
                 with --policy supplemental"
            ),
            changes: vec![PlanChange {
                kind: ChangeKind::AllowPinned,
                target: source_id.to_owned(),
                before: None,
                after: Some("pinned consent".to_owned()),
                risks: Vec::new(),
            }],
        })
    }

    pub(super) fn run_allow_pinned(
        &self,
        owner: &mut StateOwner,
        source_id: &str,
    ) -> Result<OperationOutcome, OperationOutcome> {
        source_row(owner, source_id).map_err(|refusal| failed(refusal.message))?;
        match owner.grant_pinned_consent(source_id, &(self.now)()) {
            Ok(true) => Ok(OperationOutcome {
                message: format!(
                    "Pinned consent recorded for {source_id}; approve each release with \
                     pchi release approve {source_id} <release-id>"
                ),
                reason_codes: Vec::new(),
            }),
            Ok(false) => Err(failed(format!(
                "source {source_id} had Pinned consent already; nothing was changed"
            ))),
            Err(error) => Err(failed(error.to_string())),
        }
    }

    pub(super) fn plan_release_approve(
        &self,
        owner: &mut StateOwner,
        approve: &ReleaseApprove,
    ) -> Result<Plan, ActionRefusal> {
        let source = &approve.source_id;
        let row = source_row(owner, source)?;
        if !row.pinned_consent {
            return Err(refused(format!(
                "source {source} has no Pinned consent; run pchi source allow-pinned {source} \
                 first"
            )));
        }
        let (release_row, tag) = owner
            .release_by_forge_id(source, approve.release_id)
            .map_err(|error| refused(error.to_string()))?
            .ok_or_else(|| {
                refused(format!(
                    "release {} of {source} has not been synchronized; run pchi sync {source} \
                     first",
                    approve.release_id
                ))
            })?;
        let approved = owner
            .approved_digests(source, &release_row)
            .map_err(|error| refused(error.to_string()))?;
        let changes: Vec<PlanChange> = owner
            .release_artifacts(source, &release_row)
            .map_err(|error| refused(error.to_string()))?
            .into_iter()
            .filter(|artifact| !approved.contains(&artifact.sha256.to_hex()))
            .map(|artifact| PlanChange {
                kind: ChangeKind::ApproveRelease,
                target: artifact.filename,
                before: None,
                after: Some(artifact.sha256.to_hex()),
                risks: Vec::new(),
            })
            .collect();
        if changes.is_empty() {
            return Err(refused(format!(
                "release {tag} of {source} has nothing left to approve"
            )));
        }
        Ok(Plan {
            summary: format!(
                "approve release {tag} ({}) of {source} at the Pinned level: exactly the {} \
                 digests below are published, and other bytes later behind the same assets are \
                 refused (E_ASSET_MUTATED). Risk: {PINNED_RISK}",
                approve.release_id,
                changes.len()
            ),
            changes,
        })
    }

    pub(super) fn run_release_approve(
        &self,
        pipeline: &dyn Pipeline,
        owner: &mut StateOwner,
        approve: &ReleaseApprove,
        plan: &Plan,
    ) -> Result<OperationOutcome, OperationOutcome> {
        // The plan is recomputed: approved are exactly the digests shown.
        let now = self
            .plan_release_approve(owner, approve)
            .map_err(|refusal| failed(format!("{}; nothing was approved", refusal.message)))?;
        if now.changes != plan.changes {
            return Err(failed(
                "the release changed since the plan; nothing was approved",
            ));
        }
        let digests: Vec<Sha256Digest> = plan
            .changes
            .iter()
            .filter_map(|change| change.after.as_deref())
            .map(Sha256Digest::from_hex)
            .collect::<Result<_, _>>()
            .map_err(|_| failed("the plan names an invalid digest; nothing was approved"))?;
        let (release_row, tag) = owner
            .release_by_forge_id(&approve.source_id, approve.release_id)
            .map_err(|error| failed(error.to_string()))?
            .ok_or_else(|| failed("the release is gone; nothing was approved"))?;
        let at = (self.now)();
        owner
            .approve_release(&approve.source_id, &release_row, &digests, &at)
            .map_err(|error| failed(format!("{error}; nothing was approved")))?;
        let mut lines = vec![format!(
            "approved {} artifacts of {tag} in {}",
            digests.len(),
            approve.source_id
        )];
        let mut outcome = self.synchronize_and_configure(
            pipeline,
            owner,
            std::slice::from_ref(&approve.source_id),
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
}
