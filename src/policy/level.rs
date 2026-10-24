// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provenance levels, the ratchet, and Pinned (P2-011a, ADR-027).
//!
//! The level of a source is a floor (`pinned` < `attested` < `strict`) that
//! rises automatically when a release carries stronger verified evidence and
//! never drops silently. A release weaker than the floor is held with
//! `E_EVIDENCE_DOWNGRADE`; where the source has Pinned consent the user may
//! approve it explicitly, and it is then served at the Pinned level while the
//! floor stays (`specifications/errors.md`). A release without cryptographic
//! evidence is admitted only on a source with Pinned consent and only when
//! the user approved its exact digest; until then it is held with
//! `E_RELEASE_APPROVAL_REQUIRED`. Withdrawn consent holds every Pinned
//! release again, including published ones. The schema keeps the floor from
//! dropping (migration 0001); that a `pinned` floor has consent is checked
//! here, because the schema does not tie the two.

use std::collections::BTreeSet;
use std::fmt;

use super::Evidence;

/// A provenance level, ordered from the weakest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Level {
    Pinned,
    Attested,
    Strict,
}

impl Level {
    pub const ALL: [Self; 3] = [Self::Pinned, Self::Attested, Self::Strict];

    /// The spelling of `forge_repository.trust_floor`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Attested => "attested",
            Self::Strict => "strict",
        }
    }

    pub fn from_column(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.as_str() == text)
    }
}

impl fmt::Display for Level {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the verifier found for one release artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verified {
    Strict,
    Attested,
    /// No cryptographic evidence (no bundle, no release attestation).
    Nothing,
    /// The evidence failed verification.
    Invalid,
}

/// The state of a source that the level decision reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLevel {
    /// `forge_repository.trust_floor`; `None` before the first admission.
    pub floor: Option<Level>,
    /// `forge_repository.pinned_consent_at` is set.
    pub pinned_consent: bool,
}

/// The level decision for one artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LevelDecision {
    /// The evidence fact for the admission decision (`policy::Evidence`).
    pub evidence: Evidence,
    /// The level the artifact is served at, when it is admitted.
    pub served_at: Option<Level>,
    /// The floor after this release; differs only when it rises.
    pub floor: Option<Level>,
}

impl LevelDecision {
    pub fn floor_raised(&self, before: Option<Level>) -> bool {
        self.floor > before
    }
}

/// Decides the level of one artifact. `approved` holds the digests the user
/// approved for this release (`release_approval.subject_sha256`); an
/// approval binds only to those exact bytes.
pub fn decide_level(
    source: &SourceLevel,
    verified: Verified,
    sha256: &str,
    approved: &BTreeSet<String>,
) -> LevelDecision {
    let floor = source.floor;
    let held = |evidence| LevelDecision {
        evidence,
        served_at: None,
        floor,
    };
    let level = match verified {
        Verified::Invalid => return held(Evidence::Invalid),
        Verified::Strict => Some(Level::Strict),
        Verified::Attested => Some(Level::Attested),
        Verified::Nothing => None,
    };
    if let Some(level) = level {
        // Weaker than the floor: held until the user decides; the floor
        // never moves down. Otherwise the floor rises to the release.
        if floor.is_some_and(|floor| level < floor) {
            return pinned_or(source, sha256, approved, Evidence::Downgrade);
        }
        return LevelDecision {
            evidence: if level == Level::Strict {
                Evidence::Strict
            } else {
                Evidence::Attested
            },
            served_at: Some(level),
            floor: Some(floor.map_or(level, |floor| floor.max(level))),
        };
    }
    // No cryptographic evidence.
    match floor {
        // After verified releases this is a downgrade; Pinned consent lets
        // the user approve it explicitly.
        Some(Level::Attested | Level::Strict) => {
            pinned_or(source, sha256, approved, Evidence::Downgrade)
        }
        None | Some(Level::Pinned) => {
            pinned_or(source, sha256, approved, Evidence::PinnedUnapproved)
        }
    }
}

/// A release without the evidence the floor asks for: admitted at the Pinned
/// level only with consent and an approval of these exact bytes.
fn pinned_or(
    source: &SourceLevel,
    sha256: &str,
    approved: &BTreeSet<String>,
    otherwise: Evidence,
) -> LevelDecision {
    let floor = source.floor;
    if !source.pinned_consent {
        // No Pinned without consent, whatever the floor column says.
        return LevelDecision {
            evidence: Evidence::Downgrade,
            served_at: None,
            floor,
        };
    }
    if approved.contains(sha256) {
        return LevelDecision {
            evidence: Evidence::PinnedApproved,
            served_at: Some(Level::Pinned),
            // A first Pinned release sets the floor; a higher floor stays.
            floor: Some(floor.unwrap_or(Level::Pinned)),
        };
    }
    LevelDecision {
        evidence: otherwise,
        served_at: None,
        floor,
    }
}

/// One logical repository of a source and level (ADR-007, ADR-027 point 6):
/// `apt policy` and `dnf repolist` show the level without `pchi`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRepository {
    pub apt_origin: &'static str,
    pub apt_label: String,
    pub dnf_id: String,
    pub dnf_name: String,
}

/// Why a source key cannot name a repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidSourceKey(pub String);

impl fmt::Display for InvalidSourceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "source key {:?} is not [a-z0-9-] of 1-{MAX_SOURCE_KEY} characters",
            self.0
        )
    }
}

impl std::error::Error for InvalidSourceKey {}

/// The longest source key: `pakomichi-<key>-attested` must stay a repository
/// name of at most 64 characters.
pub const MAX_SOURCE_KEY: usize = 64 - "pakomichi-".len() - "-attested".len();

/// The APT `Origin` of every Pakomichi repository.
pub const APT_ORIGIN: &str = "Pakomichi";

/// The logical repository of `source_key` (lowercase letters, digits and
/// `-`, as both APT labels and DNF repository IDs accept) at `level`.
pub fn logical_repository(
    source_key: &str,
    level: Level,
) -> Result<LogicalRepository, InvalidSourceKey> {
    let valid = (1..=MAX_SOURCE_KEY).contains(&source_key.len())
        && source_key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !source_key.starts_with('-');
    if !valid {
        return Err(InvalidSourceKey(source_key.to_owned()));
    }
    let name = format!("pakomichi-{source_key}-{level}");
    let shown = match level {
        Level::Pinned => "Pinned: no cryptographic provenance, every release approved by hand",
        Level::Attested => "Attested",
        Level::Strict => "Strict",
    };
    Ok(LogicalRepository {
        apt_origin: APT_ORIGIN,
        apt_label: name.clone(),
        dnf_name: format!("Pakomichi {source_key} ({shown})"),
        dnf_id: name,
    })
}

#[cfg(test)]
#[path = "level_tests.rs"]
mod tests;
