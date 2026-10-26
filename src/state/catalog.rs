// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a synchronization records about a source (P4-001a step 1b):
//! its package family, releases, verified evidence, artifacts, the trust
//! floor, and when it was last verified.
//!
//! The schema keeps the promises that matter (migration 0001): evidence is
//! append-only and covers exactly its artifact's bytes, an artifact's
//! identity and accepted evidence never change, and the trust floor never
//! drops. These writers record what was found and never rewrite history:
//! recording the same release, evidence, or artifact again returns the
//! existing row.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{OptionalExtension, params};

use super::owner::{StateError, StateOwner};
use crate::cas::Sha256Digest;
use crate::family::{Family, FamilyState, MemberKey};
use crate::inventory::Ecosystem;
use crate::policy::level::Level;

fn corrupt(problem: &'static str) -> StateError {
    StateError::CorruptRow {
        table: "package_family",
        problem,
    }
}

pub(super) const fn ecosystem_column(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Deb => "deb",
        Ecosystem::Rpm => "rpm",
    }
}

pub(super) fn ecosystem_of(text: &str) -> Option<Ecosystem> {
    match text {
        "deb" => Some(Ecosystem::Deb),
        "rpm" => Some(Ecosystem::Rpm),
        _ => None,
    }
}

/// One release as the synchronization saw it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRow<'a> {
    pub forge_release_id: u64,
    pub tag: &'a str,
    pub commit: Option<&'a str>,
    pub published_at: &'a str,
    pub channel: &'a str,
    pub immutable: bool,
}

/// Evidence recorded before for the same bytes of the same asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedEvidence {
    pub id: String,
    pub level: Level,
    /// The certificate identity: the release workflow of GitHub (Strict) or
    /// `https://github.com/<owner>/<repo>/<workflow>@<ref>` (Attested).
    pub signer_identity: String,
}

/// Verified provenance of one artifact's bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRow<'a> {
    pub level: Level,
    pub repository_id: u64,
    pub subject: Sha256Digest,
    pub signer_identity: &'a str,
    pub predicate_type: &'a str,
    /// The SHA-256 of the bundle that verified; part of the identifier.
    pub bundle_sha256: Sha256Digest,
    /// The stored bundle or its record (ADR-034), as JSON.
    pub record_json: &'a str,
    pub verifier_version: &'a str,
}

/// One artifact of a release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRow<'a> {
    pub release_row: &'a str,
    pub asset_id: u64,
    pub family_id: &'a str,
    pub ecosystem: Ecosystem,
    pub name: &'a str,
    pub version: &'a str,
    pub architecture: &'a str,
    pub filename: &'a str,
    pub sha256: Sha256Digest,
    pub size: u64,
}

/// The lifecycle of an artifact (`artifact.state`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactState {
    Candidate,
    Verified,
    Eligible,
    Published,
    Held,
    Rejected,
}

impl ArtifactState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Verified => "verified",
            Self::Eligible => "eligible",
            Self::Published => "published",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

impl StateOwner {
    /// The family of a source, if one was recorded.
    pub fn family(&mut self, source_id: &str) -> Result<Option<(String, Family)>, StateError> {
        let row: Option<(String, i64, bool)> = self
            .connection()
            .query_row(
                "SELECT id, revision, user_approved FROM package_family WHERE source_id = ?1",
                [source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((id, revision, approved)) = row else {
            return Ok(None);
        };
        let mut statement = self.connection().prepare(
            "SELECT ecosystem, native_name, allowed_arches_json FROM package_identity i \
             WHERE family_id = ?1 AND NOT EXISTS (SELECT 1 FROM family_outsider o \
             WHERE o.family_id = i.family_id AND o.ecosystem = i.ecosystem \
             AND o.native_name = i.native_name) ORDER BY ecosystem, native_name",
        )?;
        let rows = statement.query_map([&id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut members = Vec::new();
        for row in rows {
            let (ecosystem, name, arches) = row?;
            let ecosystem = ecosystem_of(&ecosystem).ok_or_else(|| corrupt("unknown ecosystem"))?;
            let arches: BTreeSet<String> =
                serde_json::from_str(&arches).map_err(|_| corrupt("arches are not JSON"))?;
            members.push((MemberKey::new(ecosystem, &name), arches));
        }
        let revision = u32::try_from(revision).map_err(|_| corrupt("revision out of range"))?;
        let state = if approved {
            FamilyState::Approved
        } else {
            FamilyState::Proposed
        };
        let family =
            Family::restore(revision, state, members).map_err(|_| corrupt("not a valid family"))?;
        Ok(Some((id, family)))
    }

    /// Records the family of a source: its revision, whether it is
    /// approved, and exactly its members. A revision lower than the stored
    /// one is refused; members are replaced only with a new revision.
    pub fn save_family(&mut self, source_id: &str, family: &Family) -> Result<String, StateError> {
        let id = format!("{source_id}-family");
        let revision = i64::from(family.revision());
        let approved = family.state() == FamilyState::Approved;
        let transaction = self.connection().transaction()?;
        let stored: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM package_family WHERE id = ?1",
                [&id],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            Some(stored) if stored > revision => return Err(StateError::StaleRevision),
            Some(_) => {
                transaction.execute(
                    "UPDATE package_family SET revision = ?2, user_approved = ?3 WHERE id = ?1",
                    params![id, revision, approved],
                )?;
            }
            None => {
                transaction.execute(
                    "INSERT INTO package_family (id, source_id, name, purpose, revision, \
                     user_approved) VALUES (?1, ?2, ?3, 'source', ?4, ?5)",
                    params![id, source_id, source_id, revision, approved],
                )?;
            }
        }
        let members: BTreeMap<_, _> = family.members().clone();
        let mut known = transaction
            .prepare("SELECT ecosystem, native_name FROM package_identity WHERE family_id = ?1")?;
        let existing: Vec<(String, String)> = known
            .query_map([&id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        drop(known);
        for (ecosystem, name) in existing {
            let still = ecosystem_of(&ecosystem)
                .is_some_and(|eco| members.contains_key(&MemberKey::new(eco, &name)));
            if !still {
                // A former member keeps its row while artifacts name it,
                // marked as outside the family (migration 0005).
                let used: bool = transaction.query_row(
                    "SELECT EXISTS (SELECT 1 FROM artifact WHERE family_id = ?1 \
                     AND ecosystem = ?2 AND native_name = ?3)",
                    params![id, ecosystem, name],
                    |row| row.get(0),
                )?;
                if used {
                    transaction.execute(
                        "INSERT OR IGNORE INTO family_outsider (family_id, ecosystem, \
                         native_name) VALUES (?1, ?2, ?3)",
                        params![id, ecosystem, name],
                    )?;
                } else {
                    transaction.execute(
                        "DELETE FROM package_identity WHERE family_id = ?1 AND ecosystem = ?2 \
                         AND native_name = ?3",
                        params![id, ecosystem, name],
                    )?;
                }
            }
        }
        for (key, arches) in &members {
            let arches = serde_json::to_string(arches).map_err(|_| corrupt("arches"))?;
            transaction.execute(
                "INSERT INTO package_identity (family_id, ecosystem, native_name, \
                 allowed_arches_json) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT (family_id, ecosystem, native_name) \
                 DO UPDATE SET allowed_arches_json = excluded.allowed_arches_json",
                params![id, ecosystem_column(key.ecosystem), key.name, arches],
            )?;
            transaction.execute(
                "DELETE FROM family_outsider WHERE family_id = ?1 AND ecosystem = ?2 \
                 AND native_name = ?3",
                params![id, ecosystem_column(key.ecosystem), key.name],
            )?;
        }
        transaction.commit()?;
        Ok(id)
    }

    /// Records that the source offers `key` outside its family, so its
    /// artifacts can be recorded and held; it does not make it a member.
    pub fn record_seen_name(&mut self, source_id: &str, key: &MemberKey) -> Result<(), StateError> {
        let id = format!("{source_id}-family");
        let transaction = self.connection().transaction()?;
        let added = transaction.execute(
            "INSERT INTO package_identity (family_id, ecosystem, native_name, \
             allowed_arches_json) VALUES (?1, ?2, ?3, '[]') \
             ON CONFLICT (family_id, ecosystem, native_name) DO NOTHING",
            params![id, ecosystem_column(key.ecosystem), key.name],
        )?;
        // A member stays a member; only a new row is marked.
        if added == 1 {
            transaction.execute(
                "INSERT INTO family_outsider (family_id, ecosystem, native_name) \
                 VALUES (?1, ?2, ?3)",
                params![id, ecosystem_column(key.ecosystem), key.name],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Every name the source's recorded artifacts carry, with their
    /// architectures: what an activation may choose from.
    pub fn seen_names(
        &mut self,
        source_id: &str,
    ) -> Result<BTreeMap<MemberKey, BTreeSet<String>>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT DISTINCT ecosystem, native_name, architecture FROM artifact \
             WHERE source_id = ?1",
        )?;
        let rows = statement.query_map([source_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut seen: BTreeMap<MemberKey, BTreeSet<String>> = BTreeMap::new();
        for row in rows {
            let (ecosystem, name, arch) = row?;
            let ecosystem = ecosystem_of(&ecosystem).ok_or_else(|| corrupt("unknown ecosystem"))?;
            seen.entry(MemberKey::new(ecosystem, &name))
                .or_default()
                .insert(arch);
        }
        Ok(seen)
    }

    /// Records a release once; the first record stays.
    pub fn record_release(
        &mut self,
        source_id: &str,
        release: &ReleaseRow<'_>,
    ) -> Result<String, StateError> {
        let id = format!("{source_id}-release-{}", release.forge_release_id);
        self.connection().execute(
            "INSERT INTO release_record (id, source_id, forge_release_id, tag, commit_sha, \
             published_at, channel, immutable_claim) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT (source_id, forge_release_id) DO NOTHING",
            params![
                id,
                source_id,
                release.forge_release_id.to_string(),
                release.tag,
                release.commit,
                release.published_at,
                release.channel,
                release.immutable,
            ],
        )?;
        Ok(id)
    }

    /// Records verified evidence for exactly `subject`; the identifier
    /// follows from the bundle, so the same bundle is recorded once.
    pub fn record_evidence(
        &mut self,
        source_id: &str,
        evidence: &EvidenceRow<'_>,
        at: &str,
    ) -> Result<String, StateError> {
        let id = format!(
            "evidence-{}",
            Sha256Digest::of(
                format!(
                    "{source_id}\n{}\n{}\n{}",
                    evidence.level.as_str(),
                    evidence.subject.to_hex(),
                    evidence.bundle_sha256.to_hex()
                )
                .as_bytes()
            )
            .to_hex()
        );
        self.connection().execute(
            "INSERT INTO trust_evidence (id, source_id, evidence_type, root_chain_json, \
             signer_identity, repository_id, subject_sha256, predicate_type, verified_at, \
             verifier_version, record_json) VALUES (?1, ?2, ?3, '[]', ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT (id) DO NOTHING",
            params![
                id,
                source_id,
                evidence.level.as_str(),
                evidence.signer_identity,
                evidence.repository_id.to_string(),
                evidence.subject.to_hex(),
                evidence.predicate_type,
                at,
                evidence.verifier_version,
                evidence.record_json,
            ],
        )?;
        Ok(id)
    }

    /// The evidence recorded for exactly these bytes of this asset of
    /// `source_id`, if an artifact still carries it (ADR-037 point 1).
    pub fn recorded_evidence(
        &mut self,
        source_id: &str,
        asset_id: u64,
        sha256: Sha256Digest,
    ) -> Result<Option<RecordedEvidence>, StateError> {
        let row = self
            .connection()
            .query_row(
                "SELECT e.id, e.evidence_type, e.signer_identity FROM artifact a \
                 JOIN trust_evidence e ON e.id = a.evidence_id AND e.source_id = a.source_id \
                 WHERE a.source_id = ?1 AND a.asset_id = ?2 AND a.sha256 = ?3 \
                 AND a.state NOT IN ('rejected', 'revoked') ORDER BY e.verified_at LIMIT 1",
                params![source_id, asset_id.to_string(), sha256.to_hex()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(id, level, signer_identity)| {
            Ok(RecordedEvidence {
                id,
                level: Level::from_column(&level)
                    .ok_or_else(|| corrupt("unknown evidence type"))?,
                signer_identity,
            })
        })
        .transpose()
    }

    /// When the evidence of `source_id` was last checked in full.
    pub fn last_full_evidence_check(
        &mut self,
        source_id: &str,
    ) -> Result<Option<String>, StateError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT checked_at FROM evidence_full_check WHERE source_id = ?1",
                [source_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Records a full evidence check of `source_id` at `at`.
    pub fn record_full_evidence_check(
        &mut self,
        source_id: &str,
        at: &str,
    ) -> Result<(), StateError> {
        self.connection().execute(
            "INSERT INTO evidence_full_check (source_id, checked_at) VALUES (?1, ?2) \
             ON CONFLICT (source_id) DO UPDATE SET checked_at = excluded.checked_at",
            params![source_id, at],
        )?;
        Ok(())
    }

    /// Records an artifact in `state`, or moves an existing one to it. The
    /// same asset with other bytes is another artifact (ADR-005).
    pub fn record_artifact(
        &mut self,
        source_id: &str,
        artifact: &ArtifactRow<'_>,
        evidence_id: Option<&str>,
        state: ArtifactState,
    ) -> Result<String, StateError> {
        self.record_accepted_artifact(
            source_id,
            artifact,
            evidence_id.map_or(Accepted::Nothing, Accepted::Evidence),
            state,
        )
    }

    /// [`Self::record_artifact`] with what accepted the bytes: evidence, or
    /// an approval of a Pinned release (ADR-027), never both. What was
    /// attached once stays.
    pub fn record_accepted_artifact(
        &mut self,
        source_id: &str,
        artifact: &ArtifactRow<'_>,
        accepted: Accepted<'_>,
        state: ArtifactState,
    ) -> Result<String, StateError> {
        let (evidence_id, approval_id) = match accepted {
            Accepted::Evidence(id) => (Some(id), None),
            Accepted::Approval(id) => (None, Some(id)),
            Accepted::Nothing => (None, None),
        };
        let id = format!(
            "artifact-{}-{}",
            artifact.asset_id,
            &artifact.sha256.to_hex()[..16]
        );
        let transaction = self.connection().transaction()?;
        let existing: Option<(String, Option<String>, Option<String>)> = transaction
            .query_row(
                "SELECT id, evidence_id, approval_id FROM artifact WHERE source_id = ?1 \
                 AND release_id = ?2 AND asset_id = ?3 AND sha256 = ?4",
                params![
                    source_id,
                    artifact.release_row,
                    artifact.asset_id.to_string(),
                    artifact.sha256.to_hex()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let id = match existing {
            Some((existing, stored_evidence, stored_approval)) => {
                // What accepted the bytes never changes; it may be attached
                // once, and never next to the other kind.
                let evidence = stored_evidence
                    .as_deref()
                    .or(evidence_id.filter(|_| stored_approval.is_none()));
                let approval = stored_approval
                    .as_deref()
                    .or(approval_id.filter(|_| evidence.is_none()));
                transaction.execute(
                    "UPDATE artifact SET state = ?2, evidence_id = ?3, approval_id = ?4 \
                     WHERE id = ?1",
                    params![existing, state.as_str(), evidence, approval],
                )?;
                existing
            }
            None => {
                transaction.execute(
                    "INSERT INTO artifact (id, source_id, release_id, asset_id, family_id, \
                     ecosystem, native_name, native_version, architecture, filename, sha256, \
                     byte_size, evidence_id, approval_id, state) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        id,
                        source_id,
                        artifact.release_row,
                        artifact.asset_id.to_string(),
                        artifact.family_id,
                        ecosystem_column(artifact.ecosystem),
                        artifact.name,
                        artifact.version,
                        artifact.architecture,
                        artifact.filename,
                        artifact.sha256.to_hex(),
                        i64::try_from(artifact.size).unwrap_or(i64::MAX),
                        evidence_id,
                        approval_id,
                        state.as_str(),
                    ],
                )?;
                id
            }
        };
        transaction.commit()?;
        Ok(id)
    }

    /// The trust floor rises to `level` when that is higher; the schema
    /// refuses a lower one.
    pub fn raise_trust_floor(&mut self, source_id: &str, level: Level) -> Result<(), StateError> {
        let current: Option<String> = self.connection().query_row(
            "SELECT trust_floor FROM forge_repository WHERE id = ?1",
            [source_id],
            |row| row.get(0),
        )?;
        if current.as_deref().and_then(Level::from_column) >= Some(level) {
            return Ok(());
        }
        self.connection().execute(
            "UPDATE forge_repository SET trust_floor = ?2 WHERE id = ?1",
            params![source_id, level.as_str()],
        )?;
        Ok(())
    }

    /// The source's identity was verified against GitHub at `at`.
    pub fn record_verified(&mut self, source_id: &str, at: &str) -> Result<(), StateError> {
        self.connection().execute(
            "UPDATE forge_repository SET last_verified_at = ?2 WHERE id = ?1",
            params![source_id, at],
        )?;
        Ok(())
    }

    /// The digests the user approved in a release of a Pinned source
    /// (`release_approval`).
    pub fn approved_digests(
        &mut self,
        source_id: &str,
        release_row: &str,
    ) -> Result<BTreeSet<String>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT subject_sha256 FROM release_approval WHERE source_id = ?1 AND release_id = ?2",
        )?;
        let rows = statement.query_map(params![source_id, release_row], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The recorded release of `source_id` with the forge's `release_id`,
    /// as its row identifier and tag.
    pub fn release_by_forge_id(
        &mut self,
        source_id: &str,
        release_id: u64,
    ) -> Result<Option<(String, String)>, StateError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT id, tag FROM release_record WHERE source_id = ?1 AND forge_release_id = ?2",
                params![source_id, release_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// The artifacts recorded for a release that may still be approved:
    /// every one but the rejected and revoked, by file name.
    pub fn release_artifacts(
        &mut self,
        source_id: &str,
        release_row: &str,
    ) -> Result<Vec<ReleaseArtifact>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT filename, native_name, native_version, sha256 FROM artifact \
             WHERE source_id = ?1 AND release_id = ?2 AND state NOT IN ('rejected', 'revoked') \
             ORDER BY filename, sha256",
        )?;
        let rows = statement.query_map(params![source_id, release_row], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut artifacts = Vec::new();
        for row in rows {
            let (filename, name, version, sha256) = row?;
            artifacts.push(ReleaseArtifact {
                filename,
                name,
                version,
                sha256: Sha256Digest::from_hex(&sha256).map_err(|_| corrupt("artifact digest"))?,
            });
        }
        Ok(artifacts)
    }

    /// Approves exactly `digests` of a release (ADR-027 point 4.2). The
    /// schema refuses it while the source has no Pinned consent; an
    /// approval is never changed or removed.
    pub fn approve_release(
        &mut self,
        source_id: &str,
        release_row: &str,
        digests: &[Sha256Digest],
        at: &str,
    ) -> Result<(), StateError> {
        let transaction = self.connection().transaction()?;
        for digest in digests {
            let id = format!(
                "approval-{}",
                Sha256Digest::of(
                    format!("{source_id}\n{release_row}\n{}", digest.to_hex()).as_bytes()
                )
                .to_hex()
            );
            transaction.execute(
                "INSERT INTO release_approval (id, source_id, release_id, subject_sha256, \
                 approved_at, record_json) VALUES (?1, ?2, ?3, ?4, ?5, '{}') \
                 ON CONFLICT (id) DO NOTHING",
                params![id, source_id, release_row, digest.to_hex(), at],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// The approval of exactly these bytes in this release, if any.
    pub fn approval_for(
        &mut self,
        source_id: &str,
        release_row: &str,
        sha256: Sha256Digest,
    ) -> Result<Option<String>, StateError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT id FROM release_approval WHERE source_id = ?1 AND release_id = ?2 \
                 AND subject_sha256 = ?3",
                params![source_id, release_row, sha256.to_hex()],
                |row| row.get(0),
            )
            .optional()?)
    }
}

/// What accepted the bytes of an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Accepted<'a> {
    /// Strict or Attested evidence (`trust_evidence.id`).
    Evidence(&'a str),
    /// The approval of a Pinned release (`release_approval.id`).
    Approval(&'a str),
    Nothing,
}

/// One artifact of a recorded release, as an approval shows it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseArtifact {
    pub filename: String,
    pub name: String,
    pub version: String,
    pub sha256: Sha256Digest,
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
