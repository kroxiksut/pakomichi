// SPDX-License-Identifier: MIT OR Apache-2.0

//! The system namespace check of ADR-022 point 2 (P2-014).
//!
//! The system namespace is the set of package names and `Provides` of the
//! distribution's own packages and of installed packages that did not come
//! from Pakomichi (`docs/en/specifications/system-namespace.md` says which
//! sources count). An artifact is held with
//! `E_SYSTEM_PACKAGE_CONFLICT` when any of its `Provides`, or any `Replaces`
//! (DEB) or `Obsoletes` (RPM) whatever its version constraint, names a
//! member. The native managers accept such packages (R-001 N-008/N-009),
//! so the check is Pakomichi's own, before publication.
//!
//! The own name is not a `Provides` conflict, but it is classified: a part
//! of the operating system is held, a distribution application or a package
//! installed from elsewhere needs an explicit migration.
//!
//! This module is the pure part: building the set and checking one
//! package's claims. Collecting the set from a system is separate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::error::ReasonCode;
use crate::inspect::{DebInspection, RpmInspection};

/// The name of one DEB relation entry: `foo`, `foo (>= 1.0)`, `foo(=1)`,
/// `foo:any`. `None` for an empty entry.
pub fn deb_relation_name(entry: &str) -> Option<&str> {
    let name = entry
        .trim()
        .split(|character: char| character.is_whitespace() || character == '(' || character == ':')
        .next()?;
    (!name.is_empty()).then_some(name)
}

/// The name of one RPM capability as text: `foo`, `foo >= 1.0`,
/// `libc.so.6()(64bit)`, `config(foo) = 1`, `/usr/bin/foo`. Parentheses
/// belong to RPM capability names, so only the first whitespace-separated
/// token is taken. `None` for an empty entry.
pub fn rpm_relation_name(entry: &str) -> Option<&str> {
    entry.split_whitespace().next()
}

/// What a package of the namespace is to the system (owner decisions of
/// 2026-10-21, `specifications/system-namespace.md`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackageRole {
    /// Installed but not from a distribution source or from Pakomichi
    /// (PPA, COPR, by hand).
    InstalledElsewhere,
    /// An application packaged by the distribution.
    DistributionApplication,
    /// Part of the operating system: DEB `Essential: yes` or
    /// `Priority: required`/`important`, a DNF protected package, or a
    /// package that provides a shared library (soname).
    OsPart,
}

/// Names and capabilities of the distribution's packages and of installed
/// packages that did not come from Pakomichi.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SystemNamespace {
    capabilities: BTreeSet<String>,
    packages: BTreeMap<String, PackageRole>,
}

impl SystemNamespace {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a package by name. A name seen in several roles keeps the
    /// strongest one (`OsPart` over `DistributionApplication` over
    /// `InstalledElsewhere`).
    pub fn insert_package(&mut self, name: &str, role: PackageRole) {
        if name.is_empty() {
            return;
        }
        let entry = self.packages.entry(name.to_owned()).or_insert(role);
        *entry = (*entry).max(role);
    }

    /// Adds a capability (a `Provides` name), already reduced by
    /// [`deb_relation_name`] or [`rpm_relation_name`].
    pub fn insert_capability(&mut self, name: &str) {
        if !name.is_empty() {
            self.capabilities.insert(name.to_owned());
        }
    }

    /// A package name or a capability of the namespace.
    pub fn contains(&self, name: &str) -> bool {
        self.packages.contains_key(name) || self.capabilities.contains(name)
    }

    pub fn role(&self, package: &str) -> Option<PackageRole> {
        self.packages.get(package).copied()
    }

    pub fn len(&self) -> usize {
        self.packages.len() + self.capabilities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty() && self.capabilities.is_empty()
    }
}

/// Which relation of the artifact names a system member.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Relation {
    Provides,
    /// DEB `Replaces`.
    Replaces,
    /// RPM `Obsoletes`.
    Obsoletes,
}

impl fmt::Display for Relation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Provides => "Provides",
            Self::Replaces => "Replaces",
            Self::Obsoletes => "Obsoletes",
        })
    }
}

/// What one package claims, reduced to names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claims {
    pub name: String,
    pub provides: Vec<String>,
    /// DEB `Replaces` or RPM `Obsoletes`.
    pub replacements: Vec<String>,
    pub replacement_relation: Relation,
}

impl Claims {
    pub fn from_deb(inspection: &DebInspection) -> Self {
        let control = inspection.control();
        Self {
            name: control.package().to_owned(),
            provides: deb_list(control.provides().as_deref()),
            replacements: deb_list(control.replaces().as_deref()),
            replacement_relation: Relation::Replaces,
        }
    }

    pub fn from_rpm(inspection: &RpmInspection) -> Self {
        let names = |entries: &[crate::inspect::RpmDependency]| {
            entries
                .iter()
                .filter_map(|entry| rpm_relation_name(entry.name()))
                .map(str::to_owned)
                .collect()
        };
        Self {
            name: inspection.name().to_owned(),
            provides: names(inspection.provides()),
            replacements: names(inspection.obsoletes()),
            replacement_relation: Relation::Obsoletes,
        }
    }
}

/// A DEB `Provides` or `Replaces` list is comma-separated and has no
/// alternatives; a stray `|` is split as well, so nothing hides behind it.
fn deb_list(field: Option<&str>) -> Vec<String> {
    field
        .unwrap_or_default()
        .split([',', '|'])
        .filter_map(deb_relation_name)
        .map(str::to_owned)
        .collect()
}

/// One relation that names a system member.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Conflict {
    pub relation: Relation,
    pub name: String,
}

/// What the package's own name means on this system.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OwnName {
    /// No package of the namespace has this name.
    #[default]
    Free,
    /// A distribution application or a package installed from elsewhere
    /// has this name: the artifact stays `observing` until an explicit
    /// migration (ADR-022 point 3, ADR-012), which Strict and Attested
    /// sources may offer and Pinned sources never do (ADR-027 point 5).
    NeedsMigration,
    /// A part of the operating system has this name: held, no migration.
    OsPart,
}

/// The outcome of checking one package.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Check {
    /// `Provides`, `Replaces`, or `Obsoletes` entries that name a member.
    pub conflicts: Vec<Conflict>,
    pub own_name: OwnName,
}

impl Check {
    /// `E_SYSTEM_PACKAGE_CONFLICT` when a relation names a member or the
    /// own name is a part of the operating system. A name that was already
    /// activated before the distribution added it keeps its publisher
    /// (ADR-022 point 3); the policy core, which knows the activation,
    /// applies that exception.
    pub fn reason_code(&self) -> Option<ReasonCode> {
        (!self.conflicts.is_empty() || self.own_name == OwnName::OsPart)
            .then_some(ReasonCode::ESystemPackageConflict)
    }
}

/// Checks one package's claims against the namespace. RPM adds
/// `name = evr` and `name(arch)` to every package; that self-provide is not
/// a conflict, and the own name is reported separately.
pub fn check(namespace: &SystemNamespace, claims: &Claims) -> Check {
    let own = claims.name.as_str();
    let is_self = |name: &str| {
        name == own
            || name
                .strip_prefix(own)
                .and_then(|rest| rest.strip_prefix('('))
                .and_then(|rest| rest.strip_suffix(')'))
                .is_some_and(|arch| !arch.is_empty() && !arch.contains(['(', ')']))
    };
    let mut conflicts = BTreeSet::new();
    for name in &claims.provides {
        if !is_self(name) && namespace.contains(name) {
            conflicts.insert(Conflict {
                relation: Relation::Provides,
                name: name.clone(),
            });
        }
    }
    for name in &claims.replacements {
        if namespace.contains(name) {
            conflicts.insert(Conflict {
                relation: claims.replacement_relation,
                name: name.clone(),
            });
        }
    }
    let own_name = match namespace.role(own) {
        None => OwnName::Free,
        Some(PackageRole::OsPart) => OwnName::OsPart,
        Some(PackageRole::DistributionApplication | PackageRole::InstalledElsewhere) => {
            OwnName::NeedsMigration
        }
    };
    Check {
        conflicts: conflicts.into_iter().collect(),
        own_name,
    }
}

pub mod collect;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
