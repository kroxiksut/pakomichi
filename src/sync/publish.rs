// SPDX-License-Identifier: MIT OR Apache-2.0

//! Publication of a level's generation, and the APT configuration of every
//! source (ADR-022 point 3, ADR-036 point 3).
//!
//! An activated name is pinned to exactly one logical repository: the
//! level that serves its newest published version. The floor only rises,
//! so that is normally the strongest level; an older version left in a
//! weaker repository is never pinned. The activation journal follows the
//! verified apply: a name is recorded as activated only when the root
//! applier verified the configuration that pins it, and a name no longer
//! pinned is ended there.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use super::LevelPublisher;
use crate::apt::config::{Desired, LogicalSource, SourceConfig};
use crate::apt::operation::{Applier, Ended, OperationError, apply_apt};
use crate::cas::Store;
use crate::error::ReasonCode;
use crate::family::{MemberKey, NativeVersion};
use crate::policy::SourceMode;
use crate::policy::level::{Level, logical_repository};
use crate::publish::apt::{AptPackage, AptRepository, Freshness};
use crate::publish::sign::{MetadataSigner, MetadataVerifier};
use crate::publish::{AptGeneration, GenerationStore, RepoName, SourceId, publish_apt};
use crate::state::{StateError, StateOwner};

/// [`LevelPublisher`] over the generation store, the CAS, and the signer.
pub struct AptPublisher<'a> {
    pub store: &'a mut GenerationStore,
    pub cas: &'a Store,
    pub signer: &'a dyn MetadataSigner,
    pub verifier: &'a dyn MetadataVerifier,
    /// The target's native architecture; `all` packages are listed in it.
    pub architecture: String,
    pub max_freshness: u64,
    pub now: SystemTime,
}

impl LevelPublisher for AptPublisher<'_> {
    fn publish(
        &mut self,
        source_key: &str,
        level: Level,
        packages: &[AptPackage],
    ) -> Result<u64, (ReasonCode, String)> {
        let invalid = |detail: String| (ReasonCode::ESnapshotInconsistent, detail);
        let repository =
            logical_repository(source_key, level).map_err(|error| invalid(format!("{error:?}")))?;
        let label = repository.apt_label;
        let apt = AptRepository::new(&label, &[self.architecture.as_str()])
            .map_err(|error| invalid(format!("{error:?}")))?;
        let generation = AptGeneration {
            repo: RepoName::new(&label).map_err(|error| invalid(error.to_string()))?,
            source: SourceId::new(source_key).map_err(|error| invalid(error.to_string()))?,
            apt: &apt,
            packages,
            freshness: Freshness {
                confirmed_at: self
                    .now
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |since| since.as_secs()),
                max_freshness: self.max_freshness,
            },
        };
        publish_apt(
            self.store,
            self.cas,
            self.signer,
            self.verifier,
            generation,
            self.now,
        )
        .map(|id| id.get())
        .map_err(|error| (error.reason(), error.to_string()))
    }
}

/// The label of the level serving the newest published version of each
/// published name of `source_id`.
fn newest_levels(
    owner: &mut StateOwner,
    source_id: &str,
) -> Result<BTreeMap<MemberKey, Level>, StateError> {
    let mut newest: BTreeMap<MemberKey, (NativeVersion, Level)> = BTreeMap::new();
    for artifact in owner.published_artifacts(source_id)? {
        let Ok(version) = NativeVersion::parse(artifact.key.ecosystem, &artifact.version) else {
            continue;
        };
        let replace = match newest.get(&artifact.key) {
            None => true,
            Some((known, level)) => match version.compare(known) {
                Some(Ordering::Greater) => true,
                // The same version at two levels: the stronger serves it.
                Some(Ordering::Equal) => artifact.level > *level,
                _ => false,
            },
        };
        if replace {
            newest.insert(artifact.key.clone(), (version, artifact.level));
        }
    }
    Ok(newest
        .into_iter()
        .map(|(key, (_, level))| (key, level))
        .collect())
}

/// The APT configuration every source asks for: one logical repository per
/// published level, and a pin for each activated name in the level that
/// serves its newest version. A source that is only observed, or whose
/// names are not activated, gets no pins.
pub fn desired_apt(
    owner: &mut StateOwner,
    port: u16,
    keyring: Vec<u8>,
) -> Result<Desired, StateError> {
    let mut sources = Vec::new();
    for row in owner.sources()? {
        let levels = newest_levels(owner, &row.id)?;
        if levels.is_empty() {
            continue;
        }
        let modes = owner.name_modes(&row.id)?;
        let mut repositories: BTreeMap<Level, BTreeSet<String>> = BTreeMap::new();
        for level in levels.values() {
            repositories.entry(*level).or_default();
        }
        if row.state != "observing" && row.state != "suspended" {
            for (key, level) in &levels {
                let activated = matches!(
                    modes.get(key),
                    Some(SourceMode::Supplemental | SourceMode::Preferred)
                );
                if activated {
                    repositories
                        .entry(*level)
                        .or_default()
                        .insert(key.name.clone());
                }
            }
        }
        let mut logical = Vec::new();
        for (level, activated) in repositories {
            let Ok(repository) = logical_repository(&row.id, level) else {
                continue;
            };
            logical.push(LogicalSource {
                label: repository.apt_label,
                activated,
            });
        }
        sources.push(SourceConfig {
            source_key: row.id.clone(),
            repositories: logical,
        });
    }
    Ok(Desired {
        port,
        keyring,
        sources,
    })
}

/// Applies `desired` through the root applier; when the applier verified
/// it, the activation journal follows: every pinned name is opened in its
/// source, and every name of a source no longer pinned is ended.
pub fn apply_and_record(
    owner: &mut StateOwner,
    applier: &dyn Applier,
    desired: &Desired,
    at: &str,
) -> Result<Ended, OperationError> {
    let ended = apply_apt(owner, applier, desired, at)?;
    if matches!(ended, Ended::Verified { .. } | Ended::Reconciled) {
        record_journal(owner, desired, at).map_err(OperationError::State)?;
    }
    Ok(ended)
}

fn record_journal(owner: &mut StateOwner, desired: &Desired, at: &str) -> Result<(), StateError> {
    let ecosystem = crate::inventory::Ecosystem::Deb;
    let mut pinned: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for source in &desired.sources {
        let names = pinned.entry(source.source_key.as_str()).or_default();
        for repository in &source.repositories {
            names.extend(repository.activated.iter().map(String::as_str));
        }
    }
    let sources: Vec<String> = owner.sources()?.into_iter().map(|row| row.id).collect();
    // Every end first: a name moving between sources is opened in the
    // new one only after it is closed in the old one.
    for source in &sources {
        let names = pinned.get(source.as_str()).cloned().unwrap_or_default();
        for (kind, name) in owner.open_activations(source)? {
            if kind == ecosystem && !names.contains(name.as_str()) {
                owner.end_activation(source, kind, &name, at)?;
            }
        }
    }
    for source in &sources {
        let names = pinned.get(source.as_str()).cloned().unwrap_or_default();
        for name in &names {
            owner.record_activation(source, ecosystem, name, at)?;
        }
        // The status follows what APT now does.
        owner.set_source_activity(source, !names.is_empty())?;
    }
    Ok(())
}
