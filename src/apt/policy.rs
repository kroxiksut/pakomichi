// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading back what APT will select (`apt-cache policy NAME...` with
//! `LC_ALL=C`) and judging it against what Pakomichi promised
//! (ADR-022 points 1 and 3).
//!
//! A configuration file that was written is only a signal; the promise is
//! about APT's choice. For every activated name the candidate must be a
//! version from the name's own logical repository at the 990 pin, and that
//! version must exist in no other source: APT merges equal versions and
//! the pin then raises a version whose file may come from the other source
//! (R-001). A higher version elsewhere, including a distribution security
//! update, is a notice: the publisher stays, and switching is the user's
//! decision. A published name that is not activated must never be the
//! candidate over another source's version.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::config::PIN_PRIORITY;
use crate::error::ReasonCode;
use crate::family::version::DebVersion;

const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// One place a version comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionSource {
    pub priority: i32,
    /// The URI, or `/var/lib/dpkg/status` for the installed copy.
    pub location: String,
    /// `<suite>/<component>`, absent for the dpkg status.
    pub dist: Option<String>,
}

/// One version of a package and the places it comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionEntry {
    pub version: String,
    pub priority: i32,
    pub sources: Vec<VersionSource>,
}

/// What `apt-cache policy` says about one package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePolicy {
    pub name: String,
    pub installed: Option<String>,
    pub candidate: Option<String>,
    pub versions: Vec<VersionEntry>,
}

/// The output does not have the expected form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyParseError {
    pub line: usize,
    pub what: &'static str,
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "apt-cache policy line {}: {}",
            self.line, self.what
        )
    }
}

impl std::error::Error for PolicyParseError {}

fn optional(value: &str) -> Option<String> {
    (value != "(none)").then(|| value.to_owned())
}

/// Parses the per-package form of `apt-cache policy` (APT 2.6, 2.8, 3.0).
pub fn parse_policy(text: &str) -> Result<Vec<PackagePolicy>, PolicyParseError> {
    let mut packages: Vec<PackagePolicy> = Vec::new();
    let mut in_table = false;
    for (index, line) in text.lines().enumerate() {
        let error = |what| PolicyParseError {
            line: index + 1,
            what,
        };
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            let name = line.strip_suffix(':').ok_or(error("package line"))?;
            packages.push(PackagePolicy {
                name: name.to_owned(),
                installed: None,
                candidate: None,
                versions: Vec::new(),
            });
            in_table = false;
            continue;
        }
        let package = packages.last_mut().ok_or(error("line before a package"))?;
        if let Some(value) = line.strip_prefix("  Installed: ") {
            package.installed = optional(value.trim());
        } else if let Some(value) = line.strip_prefix("  Candidate: ") {
            package.candidate = optional(value.trim());
        } else if line == "  Version table:" {
            in_table = true;
        } else if in_table
            && (line.starts_with(" *** ") || line.starts_with("     "))
            && !line.starts_with("      ")
        {
            let fields: Vec<&str> = line[5..].split_whitespace().collect();
            let [version, priority] = fields.as_slice() else {
                return Err(error("version line"));
            };
            package.versions.push(VersionEntry {
                version: (*version).to_owned(),
                priority: priority.parse().map_err(|_| error("version priority"))?,
                sources: Vec::new(),
            });
        } else if in_table && line.starts_with("        ") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let entry = package
                .versions
                .last_mut()
                .ok_or(error("source before a version"))?;
            let (priority, location, dist) = match fields.as_slice() {
                [priority, location] if *location == DPKG_STATUS => (priority, location, None),
                [priority, location, dist, ..] => (priority, location, Some((*dist).to_owned())),
                _ => return Err(error("source line")),
            };
            entry.sources.push(VersionSource {
                priority: priority.parse().map_err(|_| error("source priority"))?,
                location: (*location).to_owned(),
                dist,
            });
        } else if !line.starts_with("  Package pin: ") {
            return Err(error("unexpected line"));
        }
    }
    Ok(packages)
}

/// A logical repository of Pakomichi as APT lists it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OurRepository {
    pub uri: String,
    pub label: String,
}

impl OurRepository {
    pub fn new(port: u16, label: &str) -> Self {
        Self {
            uri: format!("http://127.0.0.1:{port}/{label}"),
            label: label.to_owned(),
        }
    }

    fn is(&self, source: &VersionSource) -> bool {
        source.location == self.uri
            && source
                .dist
                .as_deref()
                .is_some_and(|dist| dist.split('/').next() == Some(self.label.as_str()))
    }
}

fn is_pakomichi(source: &VersionSource, ours: &[OurRepository]) -> bool {
    ours.iter().any(|repository| repository.is(source))
}

fn is_installed_copy(source: &VersionSource) -> bool {
    source.location == DPKG_STATUS
}

/// A broken promise: the state is unsafe and is shown, never hidden.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Finding {
    /// The candidate of an activated name is not its own repository's
    /// version at the 990 pin (a missing pin, a foreign preference, a
    /// missing source).
    NotProtected {
        name: String,
        candidate: Option<String>,
        priority: Option<i32>,
    },
    /// The candidate version is also offered by another source.
    EqualVersionElsewhere {
        name: String,
        version: String,
        other: String,
    },
    /// A published name that is not activated is the candidate over a
    /// version from another source.
    TakesOver { name: String, version: String },
}

impl Finding {
    pub const fn reason(&self) -> ReasonCode {
        match self {
            Self::EqualVersionElsewhere { .. } => ReasonCode::ESourceAmbiguous,
            Self::NotProtected { .. } | Self::TakesOver { .. } => ReasonCode::EAdminApplyFailed,
        }
    }
}

/// A newer version of an activated name in another source: the publisher
/// stays, and the user is told (ADR-022 point 3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notice {
    pub name: String,
    pub version: String,
    pub source: String,
}

/// The judgement of one read-back.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Selection {
    pub findings: Vec<Finding>,
    pub notices: Vec<Notice>,
}

fn newer(left: &str, right: &str) -> bool {
    match (DebVersion::parse(left), DebVersion::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right) == Ordering::Greater,
        // A version APT shows that we cannot compare is reported.
        _ => left != right,
    }
}

fn describe(source: &VersionSource) -> String {
    match &source.dist {
        Some(dist) => format!("{} {dist}", source.location),
        None => source.location.clone(),
    }
}

fn same_version(left: &str, right: &str) -> bool {
    match (DebVersion::parse(left), DebVersion::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right) == Ordering::Equal,
        _ => left == right,
    }
}

/// Every version of the repository that another source also offers,
/// whether APT merged the two (APT 2.6) or lists them apart (2.8+).
fn equal_versions(policy: &PackagePolicy, repository: &OurRepository) -> Vec<Finding> {
    let mut findings = Vec::new();
    for own in policy
        .versions
        .iter()
        .filter(|entry| entry.sources.iter().any(|source| repository.is(source)))
    {
        for entry in policy
            .versions
            .iter()
            .filter(|entry| same_version(&entry.version, &own.version))
        {
            for other in entry
                .sources
                .iter()
                .filter(|source| !repository.is(source) && !is_installed_copy(source))
            {
                let finding = Finding::EqualVersionElsewhere {
                    name: policy.name.clone(),
                    version: own.version.clone(),
                    other: describe(other),
                };
                if !findings.contains(&finding) {
                    findings.push(finding);
                }
            }
        }
    }
    findings
}

/// An activated family: its repository and every member (ADR-022 point 3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Family {
    pub repository: OurRepository,
    pub members: BTreeSet<String>,
}

/// Why a family's pin is not written yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Held {
    /// Another source offers a version equal to one of the repository's
    /// (`E_SOURCE_AMBIGUOUS`, ADR-022 point 1).
    Ambiguous(Finding),
    /// APT does not list the member in its repository yet (no `apt update`
    /// since the source was added): equality cannot be ruled out.
    NotListed { name: String },
}

/// The pins to write (name → its repository) and the families held back.
pub type PinDecision = (
    BTreeMap<String, OurRepository>,
    Vec<(BTreeSet<String>, Held)>,
);

/// Which families may be pinned now. A family is pinned whole or not at
/// all: a member left without the pin changes publisher on the next
/// upgrade (P3-002a). A member is pinnable only when APT already lists it
/// in its repository and no other source offers an equal version.
pub fn pins_to_write(policies: &[PackagePolicy], families: &[Family]) -> PinDecision {
    let by_name: BTreeMap<&str, &PackagePolicy> = policies
        .iter()
        .map(|policy| (policy.name.as_str(), policy))
        .collect();
    let mut pins = BTreeMap::new();
    let mut held = Vec::new();
    for family in families {
        let reason = family.members.iter().find_map(|name| {
            let listed = by_name.get(name.as_str()).filter(|policy| {
                policy.versions.iter().any(|entry| {
                    entry
                        .sources
                        .iter()
                        .any(|source| family.repository.is(source))
                })
            });
            match listed {
                None => Some(Held::NotListed { name: name.clone() }),
                Some(policy) => equal_versions(policy, &family.repository)
                    .into_iter()
                    .next()
                    .map(Held::Ambiguous),
            }
        });
        match reason {
            Some(reason) => held.push((family.members.clone(), reason)),
            None => {
                for name in &family.members {
                    pins.insert(name.clone(), family.repository.clone());
                }
            }
        }
    }
    (pins, held)
}
/// The entry of `candidate`, if APT lists it.
fn candidate_entry(policy: &PackagePolicy) -> Option<&VersionEntry> {
    let candidate = policy.candidate.as_deref()?;
    policy
        .versions
        .iter()
        .find(|entry| entry.version == candidate)
}

/// Judges `policies` against the activated names (name → its repository)
/// and the names published but not activated in `ours`.
pub fn judge(
    policies: &[PackagePolicy],
    activated: &BTreeMap<String, OurRepository>,
    published: &[String],
    ours: &[OurRepository],
) -> Selection {
    let mut selection = Selection::default();
    let by_name: BTreeMap<&str, &PackagePolicy> = policies
        .iter()
        .map(|policy| (policy.name.as_str(), policy))
        .collect();
    for (name, repository) in activated {
        let Some(policy) = by_name.get(name.as_str()) else {
            selection.findings.push(Finding::NotProtected {
                name: name.clone(),
                candidate: None,
                priority: None,
            });
            continue;
        };
        let from_repository =
            |entry: &&VersionEntry| entry.sources.iter().any(|source| repository.is(source));
        let candidate = candidate_entry(policy);
        let own_candidate = candidate.filter(from_repository);
        if own_candidate.is_none_or(|entry| entry.priority != i32::from(PIN_PRIORITY)) {
            selection.findings.push(Finding::NotProtected {
                name: name.clone(),
                candidate: policy.candidate.clone(),
                priority: candidate.map(|entry| entry.priority),
            });
        }
        selection
            .findings
            .extend(equal_versions(policy, repository));
        // Newer versions elsewhere, against the repository's newest one.
        let mut own_versions = policy.versions.iter().filter(from_repository);
        let Some(first) = own_versions.next() else {
            continue;
        };
        let newest = own_versions.fold(first, |best, entry| {
            if newer(&entry.version, &best.version) {
                entry
            } else {
                best
            }
        });
        for entry in policy
            .versions
            .iter()
            .filter(|entry| newer(&entry.version, &newest.version))
        {
            for source in entry
                .sources
                .iter()
                .filter(|source| !is_pakomichi(source, ours) && !is_installed_copy(source))
            {
                selection.notices.push(Notice {
                    name: name.clone(),
                    version: entry.version.clone(),
                    source: describe(source),
                });
            }
        }
    }
    for name in published
        .iter()
        .filter(|name| !activated.contains_key(*name))
    {
        let Some(policy) = by_name.get(name.as_str()) else {
            continue;
        };
        let Some(candidate) = candidate_entry(policy) else {
            continue;
        };
        let from_us = candidate
            .sources
            .iter()
            .any(|source| is_pakomichi(source, ours));
        let elsewhere = policy.versions.iter().any(|entry| {
            entry
                .sources
                .iter()
                .any(|source| !is_pakomichi(source, ours) && !is_installed_copy(source))
        });
        let merged = candidate
            .sources
            .iter()
            .find(|source| !is_pakomichi(source, ours) && !is_installed_copy(source));
        if let (true, Some(other)) = (from_us, merged) {
            // One merged entry for our file and another source's: which
            // file APT downloads is not ours to promise (APT 2.6, R-001).
            selection.findings.push(Finding::EqualVersionElsewhere {
                name: name.clone(),
                version: candidate.version.clone(),
                other: describe(other),
            });
        } else if from_us && elsewhere && policy.candidate != policy.installed {
            // Keeping an installed copy is not a takeover; replacing it is.
            selection.findings.push(Finding::TakesOver {
                name: name.clone(),
                version: candidate.version.clone(),
            });
        }
    }
    selection
}
#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
