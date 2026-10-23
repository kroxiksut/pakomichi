// SPDX-License-Identifier: MIT OR Apache-2.0

//! The family admission algorithm (see the module documentation of
//! `family`).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use super::relation::{Atom, Clause};
use super::{Candidate, CompositionReview, Family, FamilyState, MemberKey};
use crate::cas::Sha256Digest;
use crate::error::ReasonCode;
use crate::inventory::Ecosystem;
use crate::namespace::SystemNamespace;

/// Why an artifact is held by the family admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HoldDetail<K> {
    /// The family is still proposed: nothing is admitted before the
    /// administrator confirms it.
    FamilyNotApproved,
    /// The name is not a member of the family.
    NewName,
    /// The name is a member, but not for this architecture.
    NewArchitecture,
    /// Another file of the same name and architecture has a natively equal
    /// version and different bytes.
    Ambiguous { with: Vec<K> },
    /// A dependency only the family can satisfy is not satisfied by any
    /// admissible family artifact.
    Dependency { clause: String },
    /// An RPM rich dependency names a family member; it is not evaluated,
    /// so the artifact is not published.
    RichDependency { clause: String },
    /// Held by an earlier check, with that check's reason.
    EarlierCheck,
}

/// The family's decision for one artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FamilyDecision<K> {
    /// Part of the consistent family set to publish.
    Publish,
    /// Admissible, but neither the newest of its name and architecture nor
    /// needed by a published artifact.
    Superseded,
    /// The same bytes as an earlier artifact.
    Duplicate { of: K },
    Held {
        reason: ReasonCode,
        detail: HoldDetail<K>,
    },
}

impl<K> FamilyDecision<K> {
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::Held { reason, .. } => Some(*reason),
            Self::Publish | Self::Superseded | Self::Duplicate { .. } => None,
        }
    }
}

/// The outcome for a set of artifacts, in input order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyAdmission<K> {
    pub decisions: Vec<(K, FamilyDecision<K>)>,
    /// Names and architectures to show the administrator, when any
    /// artifact is outside the family or the family is still proposed.
    pub review: Option<CompositionReview>,
}

impl<K> FamilyAdmission<K> {
    pub fn decision(&self, key: &K) -> Option<&FamilyDecision<K>>
    where
        K: PartialEq,
    {
        self.decisions
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, decision)| decision)
    }
}

/// Decides every artifact of one family. `candidates` are all the known
/// artifacts of the family for one target: new ones and the ones already
/// published, so that the publication set stays consistent. Artifacts that
/// an earlier check held (the system namespace, the trust level, the
/// channel) are passed with [`Candidate::held`]: they stay held and never
/// satisfy a family dependency. A dependency on a name that `system` also
/// offers is left to the native manager.
pub fn admit_family<K: Clone + Ord>(
    family: &Family,
    candidates: &[Candidate<K>],
    system: &SystemNamespace,
) -> FamilyAdmission<K> {
    let mut decisions: Vec<Option<FamilyDecision<K>>> = vec![None; candidates.len()];
    let mut additions: BTreeMap<MemberKey, BTreeSet<String>> = BTreeMap::new();
    let proposed = family.state() == FamilyState::Proposed;

    // 1. Composition.
    for (index, candidate) in candidates.iter().enumerate() {
        let package = &candidate.package;
        let key = MemberKey::new(package.ecosystem(), package.name());
        let detail = match family.arches(&key) {
            None => Some(HoldDetail::NewName),
            Some(arches) if !arches.contains(package.arch()) => Some(HoldDetail::NewArchitecture),
            Some(_) if proposed => Some(HoldDetail::FamilyNotApproved),
            Some(_) => None,
        };
        if let Some(detail) = detail {
            if !matches!(detail, HoldDetail::FamilyNotApproved) {
                additions
                    .entry(key)
                    .or_default()
                    .insert(package.arch().to_owned());
            }
            decisions[index] = Some(held(ReasonCode::EFamilyUnapproved, detail));
        } else if let Some(reason) = candidate.held {
            decisions[index] = Some(held(reason, HoldDetail::EarlierCheck));
        }
    }
    // Names only the family offers: member names and what member artifacts
    // provide (admissible or not), unless the system offers them too.
    let internal: BTreeSet<(Ecosystem, &str)> = family
        .members()
        .keys()
        .map(|key| (key.ecosystem, key.name.as_str()))
        .chain(
            candidates
                .iter()
                .filter(|candidate| {
                    family
                        .arches(&MemberKey::new(
                            candidate.package.ecosystem(),
                            candidate.package.name(),
                        ))
                        .is_some()
                })
                .flat_map(|candidate| {
                    let ecosystem = candidate.package.ecosystem();
                    candidate
                        .package
                        .offered_names()
                        .map(move |name| (ecosystem, name))
                }),
        )
        .filter(|(_, name)| !system.contains(name))
        .collect();

    // 2. Identity: duplicates, then natively equal versions.
    let mut first_by_digest: BTreeMap<Sha256Digest, usize> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if decisions[index].is_some() {
            continue;
        }
        match first_by_digest.get(&candidate.sha256) {
            Some(&first) => {
                decisions[index] = Some(FamilyDecision::Duplicate {
                    of: candidates[first].key.clone(),
                });
            }
            None => {
                first_by_digest.insert(candidate.sha256, index);
            }
        }
    }
    let open: Vec<usize> = (0..candidates.len())
        .filter(|index| decisions[*index].is_none())
        .collect();
    let mut ambiguous: BTreeMap<usize, Vec<K>> = BTreeMap::new();
    for (position, &left) in open.iter().enumerate() {
        for &right in &open[position + 1..] {
            let (a, b) = (&candidates[left].package, &candidates[right].package);
            if a.ecosystem() == b.ecosystem()
                && a.name() == b.name()
                && a.arch() == b.arch()
                && a.native_version().compare(b.native_version()) == Some(Ordering::Equal)
            {
                ambiguous
                    .entry(left)
                    .or_default()
                    .push(candidates[right].key.clone());
                ambiguous
                    .entry(right)
                    .or_default()
                    .push(candidates[left].key.clone());
            }
        }
    }
    for (index, with) in ambiguous {
        decisions[index] = Some(held(
            ReasonCode::ESourceAmbiguous,
            HoldDetail::Ambiguous { with },
        ));
    }

    // 3. Family dependencies: hold until a fixed point is reached.
    let mut alive: BTreeSet<usize> = (0..candidates.len())
        .filter(|index| decisions[*index].is_none())
        .collect();
    loop {
        let mut changed = false;
        for index in alive.clone() {
            if let Some(detail) = unsatisfied(candidates, &alive, &internal, index) {
                alive.remove(&index);
                decisions[index] = Some(held(ReasonCode::EDependencyUnsatisfiable, detail));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // 4. Publication: the newest of each name and architecture, then the
    //    artifacts their family dependencies need.
    let mut newest: BTreeMap<(Ecosystem, &str, &str), usize> = BTreeMap::new();
    for &index in &alive {
        let package = &candidates[index].package;
        let slot = newest
            .entry((package.ecosystem(), package.name(), package.arch()))
            .or_insert(index);
        if is_newer(candidates, index, *slot) {
            *slot = index;
        }
    }
    let mut publish: BTreeSet<usize> = newest.into_values().collect();
    let mut work: Vec<usize> = publish.iter().copied().collect();
    while let Some(index) = work.pop() {
        for clause in candidates[index].package.depends() {
            let Clause::Any(atoms) = clause else { continue };
            if !is_internal(&internal, candidates[index].package.ecosystem(), atoms) {
                continue;
            }
            let satisfies = |other: usize| {
                atoms
                    .iter()
                    .any(|atom| candidates[other].package.satisfies(atom))
            };
            if publish.iter().any(|other| satisfies(*other)) {
                continue;
            }
            // `alive` is a fixed point, so a satisfier exists; take the
            // newest, the earliest input on a tie.
            let mut best: Option<usize> = None;
            for &other in &alive {
                if satisfies(other)
                    && best.is_none_or(|current| is_newer(candidates, other, current))
                {
                    best = Some(other);
                }
            }
            if let Some(best) = best {
                publish.insert(best);
                work.push(best);
            }
        }
    }
    for &index in &alive {
        decisions[index] = Some(if publish.contains(&index) {
            FamilyDecision::Publish
        } else {
            FamilyDecision::Superseded
        });
    }

    let review = (proposed || !additions.is_empty()).then(|| CompositionReview {
        base_revision: family.revision(),
        additions,
    });
    FamilyAdmission {
        decisions: candidates
            .iter()
            .zip(decisions)
            .map(|(candidate, decision)| {
                (
                    candidate.key.clone(),
                    decision.unwrap_or(FamilyDecision::Superseded),
                )
            })
            .collect(),
        review,
    }
}

const fn held<K>(reason: ReasonCode, detail: HoldDetail<K>) -> FamilyDecision<K> {
    FamilyDecision::Held { reason, detail }
}

/// `candidate` is newer than `current` by native version; on equal
/// versions (a different architecture), the earlier input wins.
fn is_newer<K>(candidates: &[Candidate<K>], candidate: usize, current: usize) -> bool {
    match candidates[candidate]
        .package
        .native_version()
        .compare(candidates[current].package.native_version())
    {
        Some(Ordering::Greater) => true,
        Some(Ordering::Equal) => candidate < current,
        _ => false,
    }
}

/// A clause is the family's own when every alternative names something
/// only the family offers; otherwise the native manager may satisfy it
/// from the system and it is not checked here.
fn is_internal(
    internal: &BTreeSet<(Ecosystem, &str)>,
    ecosystem: Ecosystem,
    atoms: &[Atom],
) -> bool {
    !atoms.is_empty()
        && atoms
            .iter()
            .all(|atom| internal.contains(&(ecosystem, atom.name.as_str())))
}

fn unsatisfied<K>(
    candidates: &[Candidate<K>],
    alive: &BTreeSet<usize>,
    internal: &BTreeSet<(Ecosystem, &str)>,
    index: usize,
) -> Option<HoldDetail<K>> {
    let package = &candidates[index].package;
    let ecosystem = package.ecosystem();
    for clause in package.depends() {
        match clause {
            Clause::Rich(text) => {
                let names_member = text
                    .split(|character: char| {
                        character.is_whitespace() || character == '(' || character == ')'
                    })
                    .any(|token| internal.contains(&(ecosystem, token)));
                if names_member {
                    return Some(HoldDetail::RichDependency {
                        clause: text.clone(),
                    });
                }
            }
            Clause::Any(atoms) => {
                if !is_internal(internal, ecosystem, atoms) {
                    continue;
                }
                let satisfied = alive.iter().any(|other| {
                    atoms
                        .iter()
                        .any(|atom| candidates[*other].package.satisfies(atom))
                });
                if !satisfied {
                    return Some(HoldDetail::Dependency {
                        clause: clause_text(ecosystem, atoms),
                    });
                }
            }
        }
    }
    None
}

/// The clause as the ecosystem writes it.
fn clause_text(ecosystem: Ecosystem, atoms: &[Atom]) -> String {
    atoms
        .iter()
        .map(|atom| match (&atom.constraint, ecosystem) {
            (None, _) => atom.name.clone(),
            (Some((op, version)), Ecosystem::Deb) => {
                format!("{} ({} {version})", atom.name, op.deb())
            }
            (Some((op, version)), Ecosystem::Rpm) => {
                format!("{} {} {version}", atom.name, op.rpm())
            }
        })
        .collect::<Vec<_>>()
        .join(" | ")
}
