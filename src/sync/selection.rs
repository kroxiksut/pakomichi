// SPDX-License-Identifier: MIT OR Apache-2.0

//! What APT will choose now, against what Pakomichi promised (ADR-022
//! point 3, N-027).
//!
//! Every activated name must stay with its source under the ordinary
//! update command, and a newer version of it in another source, including
//! a distribution security update, is a notice that names that source and
//! version: the publisher stays, and switching is the user's decision.
//! The status shows both, per source. The promise is the configuration the
//! administrator confirmed ([`desired_apt`]), not the files on disk: a
//! pin that was not applied is exactly what the status must show.

use std::collections::{BTreeMap, BTreeSet};

use super::publish::desired_apt;
use crate::apt::policy::{Finding, Notice, OurRepository, PackagePolicy, judge};
use crate::inventory::Ecosystem;
use crate::policy::level::{Level, logical_repository};
use crate::state::{StateError, StateOwner};

/// What one source's names look like to APT now.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceAptView {
    /// A newer version of an activated name elsewhere.
    pub updates_elsewhere: Vec<Notice>,
    /// A promise APT does not keep now.
    pub problems: Vec<Finding>,
}

/// The names Pakomichi answers for, and where each one must come from.
#[derive(Clone, Debug, Default)]
pub struct AptPromises {
    /// Activated name → its source and the repository its pin names.
    activated: BTreeMap<String, (String, OurRepository)>,
    /// Published name → the sources that publish it.
    published: BTreeMap<String, BTreeSet<String>>,
    /// Every logical repository of every source.
    ours: Vec<OurRepository>,
}

impl AptPromises {
    /// The promises of every source, as the APT configuration asks for
    /// them on `port`.
    pub fn read(owner: &mut StateOwner, port: u16) -> Result<Self, StateError> {
        let desired = desired_apt(owner, port, Vec::new())?;
        let mut promises = Self::default();
        for source in &desired.sources {
            for repository in &source.repositories {
                for name in &repository.activated {
                    promises.activated.insert(
                        name.clone(),
                        (
                            source.source_key.clone(),
                            OurRepository::new(port, &repository.label),
                        ),
                    );
                }
            }
        }
        for row in owner.sources()? {
            promises.ours.extend(our_repositories(&row.id, port));
            for artifact in owner.published_artifacts(&row.id)? {
                if artifact.key.ecosystem != Ecosystem::Deb {
                    continue;
                }
                // An activated name is judged by its activation; `judge`
                // and `sources_of` look there first.
                promises
                    .published
                    .entry(artifact.key.name)
                    .or_default()
                    .insert(row.id.clone());
            }
        }
        Ok(promises)
    }

    /// Every name to ask APT about.
    pub fn names(&self) -> Vec<String> {
        self.activated
            .keys()
            .chain(self.published.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The sources a judgement about `name` belongs to: the one it is
    /// activated in, otherwise every source that publishes it.
    fn sources_of(&self, name: &str) -> Vec<String> {
        match self.activated.get(name) {
            Some((source, _)) => vec![source.clone()],
            None => self
                .published
                .get(name)
                .map(|sources| sources.iter().cloned().collect())
                .unwrap_or_default(),
        }
    }

    /// Judges APT's answer for [`Self::names`], per source; every source
    /// with a name gets a view, empty when APT keeps every promise.
    pub fn judge(&self, policies: &[PackagePolicy]) -> BTreeMap<String, SourceAptView> {
        let activated: BTreeMap<String, OurRepository> = self
            .activated
            .iter()
            .map(|(name, (_, repository))| (name.clone(), repository.clone()))
            .collect();
        let published: Vec<String> = self.published.keys().cloned().collect();
        let selection = judge(policies, &activated, &published, &self.ours);
        let mut views: BTreeMap<String, SourceAptView> = BTreeMap::new();
        for name in self.names() {
            for source in self.sources_of(&name) {
                views.entry(source).or_default();
            }
        }
        for notice in selection.notices {
            for source in self.sources_of(&notice.name) {
                views
                    .entry(source)
                    .or_default()
                    .updates_elsewhere
                    .push(notice.clone());
            }
        }
        for finding in selection.findings {
            for source in self.sources_of(finding.name()) {
                views
                    .entry(source)
                    .or_default()
                    .problems
                    .push(finding.clone());
            }
        }
        views
    }
}

/// Every logical repository a source may have, on `port`.
pub(crate) fn our_repositories(source_id: &str, port: u16) -> Vec<OurRepository> {
    Level::ALL
        .iter()
        .filter_map(|level| logical_repository(source_id, *level).ok())
        .map(|repository| OurRepository::new(port, &repository.apt_label))
        .collect()
}
