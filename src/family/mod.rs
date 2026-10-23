// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package families and their admission (P2-007, ADR-002, ADR-003).
//!
//! A family is the set of native package names one repository may deliver,
//! confirmed by the administrator; it is never a wildcard over a name
//! prefix (`docs/en/architecture/families-compatibility.md`). This module is
//! pure: it takes the family and the inspected artifacts and decides, for
//! one target ecosystem:
//!
//! 1. **Composition.** A name outside the confirmed set, or a confirmed name
//!    built for an architecture that was not confirmed, is held with
//!    `E_FAMILY_UNAPPROVED` and reported in a [`CompositionReview`]. Nothing
//!    the package claims (`Provides`, `Replaces`, `Obsoletes`, a dependency
//!    from a member) adds it to the family; only
//!    [`Family::extend`] does, after the administrator's confirmation.
//! 2. **Identity.** The same bytes twice keep the first artifact. Two
//!    different files of one name and architecture whose native versions
//!    compare equal are both held with `E_SOURCE_AMBIGUOUS`: `1.0` and
//!    `1.00` are the same dpkg version.
//! 3. **Family dependencies.** A dependency that only family members can
//!    satisfy must be satisfied by another admissible artifact of the
//!    family, with the native version rules; otherwise the dependent
//!    artifact is held with `E_DEPENDENCY_UNSATISFIABLE`. Dependencies on
//!    anything else are left to the native package manager (ADR-003).
//! 4. **Publication.** The newest admissible version of every name and
//!    architecture is published, together with every older artifact its
//!    family dependencies need, so the snapshot always holds a consistent
//!    family. The same version number is never required across members
//!    unless their dependencies require it.
//!
//! The system namespace (`crate::namespace`), the trust level, the channel,
//! and the OS compatibility are separate checks of the policy core; an
//! artifact one of them holds is passed in with [`Candidate::held`], stays
//! held, and never satisfies another member's dependency. A name the system
//! namespace contains is never "only the family's", so a dependency on it
//! is left to the native manager.

mod admit;
pub mod relation;
pub mod version;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub use admit::{FamilyAdmission, FamilyDecision, HoldDetail, admit_family};
use relation::{Atom, Clause, DebField, RelationError, RpmEntry, parse_deb_field, rpm_entry};
use version::{DebVersion, Op, RpmEvr, VersionError, rpm_ranges_overlap};

use crate::cas::Sha256Digest;
use crate::error::ReasonCode;
use crate::inspect::{DebInspection, RpmInspection};
use crate::inventory::Ecosystem;

/// A native version that compares with its ecosystem's rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeVersion {
    Deb(DebVersion),
    Rpm(RpmEvr),
}

impl NativeVersion {
    pub fn parse(ecosystem: Ecosystem, text: &str) -> Result<Self, VersionError> {
        match ecosystem {
            Ecosystem::Deb => DebVersion::parse(text).map(Self::Deb),
            Ecosystem::Rpm => RpmEvr::parse(text).map(Self::Rpm),
        }
    }

    /// `None` across ecosystems.
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Deb(left), Self::Deb(right)) => Some(left.cmp(right)),
            (Self::Rpm(left), Self::Rpm(right)) => Some(left.compare(right)),
            _ => None,
        }
    }
}

/// A capability one package offers: its own name at its own version, or a
/// `Provides` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Offer {
    name: String,
    constraint: Option<(Op, String)>,
}

/// What the family model needs from one inspected package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageMetadata {
    ecosystem: Ecosystem,
    name: String,
    version_text: String,
    version: NativeVersion,
    arch: String,
    /// DEB `Pre-Depends` and `Depends`; RPM `Requires` without file paths
    /// and `rpmlib()` features.
    depends: Vec<Clause>,
    provides: Vec<Offer>,
}

/// The package metadata is not well-formed for its ecosystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataError {
    Version(VersionError),
    Relation(RelationError),
}

impl MetadataError {
    /// Malformed metadata rejects the bytes (`specifications/errors.md`).
    pub const fn reason_code(&self) -> ReasonCode {
        ReasonCode::EArtifactMalformed
    }
}

impl fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version(error) => write!(formatter, "malformed version: {error}"),
            Self::Relation(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for MetadataError {}

impl From<RelationError> for MetadataError {
    fn from(error: RelationError) -> Self {
        Self::Relation(error)
    }
}

impl PackageMetadata {
    /// Reads a binary DEB. Every relationship field is validated, including
    /// the ones the family model does not use (`Conflicts`, `Breaks`,
    /// `Replaces`), so a malformed package is never published.
    pub fn from_deb(inspection: &DebInspection) -> Result<Self, MetadataError> {
        let control = inspection.control();
        let version = NativeVersion::parse(Ecosystem::Deb, control.version())
            .map_err(MetadataError::Version)?;
        let field = |field: DebField| {
            let value = match field {
                DebField::Depends => control.depends(),
                DebField::PreDepends => control.pre_depends(),
                DebField::Provides => control.provides(),
                DebField::Conflicts => control.conflicts(),
                DebField::Breaks => control.breaks(),
                DebField::Replaces => control.replaces(),
            };
            parse_deb_field(field, value.as_deref())
        };
        let mut depends = field(DebField::PreDepends)?;
        depends.extend(field(DebField::Depends)?);
        let provides = field(DebField::Provides)?
            .into_iter()
            .flat_map(|clause| match clause {
                Clause::Any(atoms) => atoms,
                Clause::Rich(_) => Vec::new(),
            })
            .map(|Atom { name, constraint }| Offer { name, constraint })
            .collect();
        for checked in [DebField::Conflicts, DebField::Breaks, DebField::Replaces] {
            field(checked)?;
        }
        Ok(Self {
            ecosystem: Ecosystem::Deb,
            name: control.package().to_owned(),
            version_text: control.version().to_owned(),
            version,
            arch: control.architecture().to_owned(),
            depends,
            provides,
        })
    }

    /// Reads a binary RPM. `Conflicts` and `Obsoletes` are validated too.
    pub fn from_rpm(inspection: &RpmInspection) -> Result<Self, MetadataError> {
        let version_text = inspection.evr();
        let version =
            NativeVersion::parse(Ecosystem::Rpm, &version_text).map_err(MetadataError::Version)?;
        let mut depends = Vec::new();
        for entry in inspection.requires() {
            match rpm_entry("Requires", entry)? {
                RpmEntry::Named(atom) => depends.push(Clause::Any(vec![atom])),
                RpmEntry::Rich(text) => depends.push(Clause::Rich(text)),
                RpmEntry::File(_) | RpmEntry::Rpmlib => {}
            }
        }
        let mut provides = Vec::new();
        for entry in inspection.provides() {
            if let RpmEntry::Named(Atom { name, constraint }) = rpm_entry("Provides", entry)? {
                provides.push(Offer { name, constraint });
            }
        }
        for entry in inspection.conflicts() {
            rpm_entry("Conflicts", entry)?;
        }
        for entry in inspection.obsoletes() {
            rpm_entry("Obsoletes", entry)?;
        }
        Ok(Self {
            ecosystem: Ecosystem::Rpm,
            name: inspection.name().to_owned(),
            version_text,
            version,
            arch: inspection.arch().to_owned(),
            depends,
            provides,
        })
    }

    pub const fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The native version as written.
    pub fn version(&self) -> &str {
        &self.version_text
    }

    pub const fn native_version(&self) -> &NativeVersion {
        &self.version
    }

    pub fn arch(&self) -> &str {
        &self.arch
    }

    pub fn depends(&self) -> &[Clause] {
        &self.depends
    }

    /// The names this package offers: its own and its `Provides`.
    fn offered_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str())
            .chain(self.provides.iter().map(|offer| offer.name.as_str()))
    }

    /// Whether this package satisfies one dependency atom, with the native
    /// rules of its ecosystem.
    pub fn satisfies(&self, atom: &Atom) -> bool {
        let own = Offer {
            name: self.name.clone(),
            constraint: Some((Op::Equal, self.version_text.clone())),
        };
        std::iter::once(&own)
            .chain(&self.provides)
            .filter(|offer| offer.name == atom.name)
            .any(|offer| self.offer_matches(offer, atom))
    }

    fn offer_matches(&self, offer: &Offer, atom: &Atom) -> bool {
        let Some((want_op, want)) = &atom.constraint else {
            return true;
        };
        match self.ecosystem {
            // dpkg: an unversioned Provides never satisfies a versioned
            // dependency; a versioned one is always `=`.
            Ecosystem::Deb => match &offer.constraint {
                Some((Op::Equal, have)) => DebVersion::parse(have)
                    .ok()
                    .zip(DebVersion::parse(want).ok())
                    .is_some_and(|(have, want)| want_op.accepts(have.cmp(&want))),
                _ => false,
            },
            // RPM: an unversioned Provides matches every version; otherwise
            // the two ranges must overlap.
            Ecosystem::Rpm => match &offer.constraint {
                None => true,
                Some((have_op, have)) => RpmEvr::parse(have)
                    .ok()
                    .zip(RpmEvr::parse(want).ok())
                    .is_some_and(|(have, want)| {
                        rpm_ranges_overlap(&have, *have_op, &want, *want_op)
                    }),
            },
        }
    }
}

/// One confirmed name of a family.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemberKey {
    pub ecosystem: Ecosystem,
    pub name: String,
}

impl MemberKey {
    pub fn new(ecosystem: Ecosystem, name: &str) -> Self {
        Self {
            ecosystem,
            name: name.to_owned(),
        }
    }
}

impl fmt::Display for MemberKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.ecosystem, self.name)
    }
}

/// Where the family is in its life cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FamilyState {
    /// Discovered on connection; nothing is admitted until the
    /// administrator confirms the set of names.
    Proposed,
    /// Confirmed at the current revision. New versions of these names
    /// follow the policy; a new name or architecture needs a review.
    Approved,
}

/// A family the administrator confirmed or is asked to confirm. Mirrors
/// `package_family` (`revision`, `user_approved`) and its
/// `package_identity` rows (`allowed_arches_json`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Family {
    revision: u32,
    state: FamilyState,
    members: BTreeMap<MemberKey, BTreeSet<String>>,
}

/// A change of the family the administrator must confirm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FamilyError {
    /// The review was made against another revision of the family.
    StaleReview { reviewed: u32, current: u32 },
    /// A family needs at least one name.
    Empty,
    /// The revision counter cannot grow.
    RevisionOverflow,
}

impl fmt::Display for FamilyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleReview { reviewed, current } => write!(
                formatter,
                "the review is for family revision {reviewed}, the family is at revision {current}"
            ),
            Self::Empty => formatter.write_str("a family needs at least one package name"),
            Self::RevisionOverflow => formatter.write_str("family revision overflow"),
        }
    }
}

impl std::error::Error for FamilyError {}

/// Names and architectures that appeared outside the family, to show the
/// administrator. Confirming it is [`Family::extend`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompositionReview {
    /// The family revision the review was computed against.
    pub base_revision: u32,
    /// New names, and new architectures of known names.
    pub additions: BTreeMap<MemberKey, BTreeSet<String>>,
}

impl Family {
    /// A proposed family at revision 1, as found on the first connection.
    pub fn proposed(
        members: impl IntoIterator<Item = (MemberKey, BTreeSet<String>)>,
    ) -> Result<Self, FamilyError> {
        let mut family = Self {
            revision: 1,
            state: FamilyState::Proposed,
            members: BTreeMap::new(),
        };
        for (key, arches) in members {
            family.members.entry(key).or_default().extend(arches);
        }
        if family.members.is_empty() {
            return Err(FamilyError::Empty);
        }
        Ok(family)
    }

    /// Restores a family from the state store.
    pub fn restore(
        revision: u32,
        state: FamilyState,
        members: impl IntoIterator<Item = (MemberKey, BTreeSet<String>)>,
    ) -> Result<Self, FamilyError> {
        let mut family = Self::proposed(members)?;
        family.revision = revision.max(1);
        family.state = state;
        Ok(family)
    }

    pub const fn revision(&self) -> u32 {
        self.revision
    }

    pub const fn state(&self) -> FamilyState {
        self.state
    }

    pub fn members(&self) -> &BTreeMap<MemberKey, BTreeSet<String>> {
        &self.members
    }

    /// The architectures confirmed for a name, if the name is a member.
    pub fn arches(&self, key: &MemberKey) -> Option<&BTreeSet<String>> {
        self.members.get(key)
    }

    /// The administrator confirmed the proposed set as shown at
    /// `reviewed_revision`. Call only after an interactive confirmation
    /// (P4-001); an automatic `yes` is never a confirmation.
    pub fn approve(&mut self, reviewed_revision: u32) -> Result<(), FamilyError> {
        if reviewed_revision != self.revision {
            return Err(FamilyError::StaleReview {
                reviewed: reviewed_revision,
                current: self.revision,
            });
        }
        self.state = FamilyState::Approved;
        Ok(())
    }

    /// The administrator confirmed the additions of `review`: the result is
    /// the next revision with those names and architectures, approved.
    /// Call only after an interactive confirmation.
    pub fn extend(&self, review: &CompositionReview) -> Result<Self, FamilyError> {
        if review.base_revision != self.revision {
            return Err(FamilyError::StaleReview {
                reviewed: review.base_revision,
                current: self.revision,
            });
        }
        let mut next = self.clone();
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(FamilyError::RevisionOverflow)?;
        for (key, arches) in &review.additions {
            next.members
                .entry(key.clone())
                .or_default()
                .extend(arches.iter().cloned());
        }
        next.state = FamilyState::Approved;
        Ok(next)
    }
}

/// One inspected artifact offered to the family admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate<K> {
    /// The caller's identity of the artifact (for example its database ID).
    pub key: K,
    pub sha256: Sha256Digest,
    pub package: PackageMetadata,
    /// The reason an earlier check of the policy core holds this artifact,
    /// if one does.
    pub held: Option<ReasonCode>,
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
