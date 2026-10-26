// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the administrator asked for each name, and what was published for
//! it (P4-001a step 1b).
//!
//! `source_policy` holds the requested mode of a name: an activation writes
//! `supplemental` or `preferred`, and the APT configuration pins exactly the
//! names with such a mode. The activation journal (`name_activation`)
//! records when that pin was verified; this table is the intent, the
//! journal is the effect.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::params;

use super::catalog::{ecosystem_column, ecosystem_of};
use super::owner::{StateError, StateOwner};
use crate::cas::Sha256Digest;
use crate::family::MemberKey;
use crate::policy::SourceMode;
use crate::policy::level::Level;

fn corrupt(table: &'static str, problem: &'static str) -> StateError {
    StateError::CorruptRow { table, problem }
}

const fn mode_column(mode: SourceMode) -> &'static str {
    match mode {
        SourceMode::Observing => "observing",
        SourceMode::Supplemental => "supplemental",
        SourceMode::Preferred => "preferred",
        SourceMode::Suspended => "suspended",
    }
}

fn mode_of(text: &str) -> Option<SourceMode> {
    match text {
        "observing" => Some(SourceMode::Observing),
        "supplemental" => Some(SourceMode::Supplemental),
        "preferred" => Some(SourceMode::Preferred),
        "suspended" => Some(SourceMode::Suspended),
        _ => None,
    }
}

/// One published artifact of a source, with the level it is served at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedArtifact {
    pub key: MemberKey,
    pub version: String,
    pub architecture: String,
    pub level: Level,
}

impl StateOwner {
    /// Sets the requested mode of a family member, confirmed by the
    /// administrator. The name must be a member of the source's family.
    pub fn set_name_mode(
        &mut self,
        source_id: &str,
        key: &MemberKey,
        mode: SourceMode,
        at: &str,
    ) -> Result<(), StateError> {
        let family_id = format!("{source_id}-family");
        let id = format!(
            "{source_id}-{}-{}",
            ecosystem_column(key.ecosystem),
            key.name
        );
        self.connection().execute(
            "INSERT INTO source_policy (id, source_id, family_id, ecosystem, native_name, mode, \
             allowed_channel, accepted_trust_modes_json, restrictions_json, user_approved, \
             updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'stable', '[]', '{}', 1, ?7) \
             ON CONFLICT (source_id, family_id, ecosystem, native_name) \
             DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at",
            params![
                id,
                source_id,
                family_id,
                ecosystem_column(key.ecosystem),
                key.name,
                mode_column(mode),
                at
            ],
        )?;
        Ok(())
    }

    /// The requested mode of every name the administrator set one for.
    pub fn name_modes(
        &mut self,
        source_id: &str,
    ) -> Result<BTreeMap<MemberKey, SourceMode>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT ecosystem, native_name, mode FROM source_policy WHERE source_id = ?1",
        )?;
        let rows = statement.query_map([source_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut modes = BTreeMap::new();
        for row in rows {
            let (ecosystem, name, mode) = row?;
            let ecosystem =
                ecosystem_of(&ecosystem).ok_or(corrupt("source_policy", "ecosystem"))?;
            let mode = mode_of(&mode).ok_or(corrupt("source_policy", "mode"))?;
            modes.insert(MemberKey::new(ecosystem, &name), mode);
        }
        Ok(modes)
    }

    /// Every published artifact of the source with the level of its
    /// evidence.
    pub fn published_artifacts(
        &mut self,
        source_id: &str,
    ) -> Result<Vec<PublishedArtifact>, StateError> {
        let mut statement = self.connection().prepare(
            // The level is the evidence's, or Pinned for an approved
            // release (ADR-027 point 8); the schema allows one, never both.
            "SELECT a.ecosystem, a.native_name, a.native_version, a.architecture, \
             CASE WHEN a.approval_id IS NOT NULL THEN 'pinned' ELSE e.evidence_type END \
             FROM artifact a LEFT JOIN trust_evidence e ON e.id = a.evidence_id \
             WHERE a.source_id = ?1 AND a.state = 'published' \
             AND (a.evidence_id IS NOT NULL OR a.approval_id IS NOT NULL) \
             ORDER BY a.native_name, a.native_version",
        )?;
        let rows = statement.query_map([source_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut published = Vec::new();
        for row in rows {
            let (ecosystem, name, version, architecture, level) = row?;
            published.push(PublishedArtifact {
                key: MemberKey::new(
                    ecosystem_of(&ecosystem).ok_or(corrupt("artifact", "ecosystem"))?,
                    &name,
                ),
                version,
                architecture,
                level: Level::from_column(&level).ok_or(corrupt("trust_evidence", "level"))?,
            });
        }
        Ok(published)
    }

    /// The digests recorded for each file name of each release (by the
    /// forge's release ID), except rejected ones. GitHub replaces an asset
    /// by deleting it and uploading another file of the same name, which
    /// gets a new asset ID (R-003 step 3), so other bytes under a recorded
    /// name are a replaced asset too (ADR-005).
    pub fn recorded_release_file_digests(
        &mut self,
        source_id: &str,
    ) -> Result<BTreeMap<(u64, String), BTreeSet<Sha256Digest>>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT r.forge_release_id, a.filename, a.sha256 FROM artifact a \
             JOIN release_record r ON r.id = a.release_id AND r.source_id = a.source_id \
             WHERE a.source_id = ?1 AND a.state <> 'rejected'",
        )?;
        let rows = statement.query_map([source_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut digests: BTreeMap<(u64, String), BTreeSet<Sha256Digest>> = BTreeMap::new();
        for row in rows {
            let (release, filename, sha256) = row?;
            let release = release
                .parse::<u64>()
                .map_err(|_| corrupt("release_record", "forge_release_id"))?;
            let sha256 =
                Sha256Digest::from_hex(&sha256).map_err(|_| corrupt("artifact", "sha256"))?;
            digests
                .entry((release, filename))
                .or_default()
                .insert(sha256);
        }
        Ok(digests)
    }

    /// The digests recorded for each asset of the source, except rejected
    /// ones: a later download with other bytes is a replaced asset.
    pub fn recorded_asset_digests(
        &mut self,
        source_id: &str,
    ) -> Result<BTreeMap<u64, BTreeSet<Sha256Digest>>, StateError> {
        let mut statement = self.connection().prepare(
            "SELECT asset_id, sha256 FROM artifact WHERE source_id = ?1 AND state <> 'rejected'",
        )?;
        let rows = statement.query_map([source_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut digests: BTreeMap<u64, BTreeSet<Sha256Digest>> = BTreeMap::new();
        for row in rows {
            let (asset, sha256) = row?;
            let asset = asset
                .parse::<u64>()
                .map_err(|_| corrupt("artifact", "asset_id"))?;
            let sha256 =
                Sha256Digest::from_hex(&sha256).map_err(|_| corrupt("artifact", "sha256"))?;
            digests.entry(asset).or_default().insert(sha256);
        }
        Ok(digests)
    }
}
