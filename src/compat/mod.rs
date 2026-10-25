// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operating system compatibility of one artifact (P2-008a).
//!
//! The pure part of `architecture/families-compatibility.md`, "System
//! dependencies": given the target system, the native metadata of an
//! artifact, and what the system's own packages offer, it decides
//! `format_arch_ok`, `declared_dependency_satisfiable`, `platform_claimed`
//! and `platform_tested`, a confidence that never says more than those
//! facts, and the reason to hold the artifact, if any.
//!
//! - The execution policy of the operating system (on Astra Linux the
//!   closed software environment) holds everything while it is on or cannot
//!   be ruled out (ADR-025, N-035).
//! - A dependency the family does not offer must be satisfied by the
//!   system's packages under the native rules; a C library newer than the
//!   system's is held, and nothing is looked for elsewhere (N-009).
//! - A build for another distribution is held; a build for another release
//!   of the same distribution, or for the distribution the target is based
//!   on (Debian 12 under Astra Linux 1.8), follows [`OtherReleaseBuilds`]
//!   (owner decisions of 2026-10-23).
//! - A name of the system namespace is satisfied only by the distribution
//!   and installed packages; any other name also by other enabled sources
//!   (vendor repositories, ADR-032).
//! - Without data about the system's packages nothing can be checked, so the
//!   artifact is held with `E_SYSTEM_NAMESPACE_UNKNOWN`.
//!
//! Collecting the system's packages and the execution policy is separate
//! (P2-008b). Dependencies the family offers are decided by the family
//! admission (`crate::family`), not here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::error::ReasonCode;
use crate::family::PackageMetadata;
use crate::family::offer_satisfies;
use crate::family::relation::{Atom, Clause};
use crate::family::version::Op;
use crate::inventory::{Ecosystem, TargetPlatform};

/// Whether the operating system refuses to run files that are not signed by
/// its own chain (ADR-025).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPolicy {
    Off,
    On,
    /// Configured but not active, unreadable, or not determined: treated as
    /// on, never as off.
    Unknown,
}

/// What to do with a build for another release of the target distribution
/// (`+deb11` on Debian 12, `.fc43` on Fedora 44).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OtherReleaseBuilds {
    /// The dependencies decide; the confidence stays low (default).
    #[default]
    Dependencies,
    Hold,
}

/// A distribution as build tags name it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DistributionFamily {
    Debian,
    Ubuntu,
    Astra,
    /// Enterprise Linux and its rebuilds (RHEL, AlmaLinux, Rocky, CentOS):
    /// the `.elN` tag.
    EnterpriseLinux,
    Fedora,
    /// Any other `ID` from `os-release`; no build tag is known for it.
    Other(String),
}

/// A distribution and, when known, its release (`12`, `9`, `44`, `1.8`).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Distribution {
    pub family: DistributionFamily,
    pub release: Option<String>,
}

impl Distribution {
    /// From the `ID` and `VERSION_ID` of `os-release`.
    pub fn from_os_release(id: &str, version_id: &str) -> Self {
        let major = || version_id.split('.').next().map(str::to_owned);
        let (family, release) = match id {
            "debian" => (DistributionFamily::Debian, major()),
            "ubuntu" => (DistributionFamily::Ubuntu, Some(version_id.to_owned())),
            // `1.8_x86-64` is release 1.8.
            "astra" => (
                DistributionFamily::Astra,
                version_id.split('_').next().map(str::to_owned),
            ),
            "rhel" | "almalinux" | "rocky" | "centos" => {
                (DistributionFamily::EnterpriseLinux, major())
            }
            "fedora" => (DistributionFamily::Fedora, Some(version_id.to_owned())),
            other => (
                DistributionFamily::Other(other.to_owned()),
                Some(version_id.to_owned()),
            ),
        };
        Self {
            family,
            release: release.filter(|release| !release.is_empty()),
        }
    }

    /// The distribution this one is built on, whose builds are treated as
    /// another release of it rather than as foreign (owner decision of
    /// 2026-10-23): Astra Linux 1.8 is based on Debian 12. Only the first
    /// targets of ADR-026 are listed.
    pub fn based_on(&self) -> Option<Self> {
        match (&self.family, self.release.as_deref()) {
            (DistributionFamily::Astra, Some("1.8")) => Some(Self {
                family: DistributionFamily::Debian,
                release: Some("12".to_owned()),
            }),
            _ => None,
        }
    }
}

impl fmt::Display for Distribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match &self.family {
            DistributionFamily::Debian => "debian",
            DistributionFamily::Ubuntu => "ubuntu",
            DistributionFamily::Astra => "astra",
            DistributionFamily::EnterpriseLinux => "el",
            DistributionFamily::Fedora => "fedora",
            DistributionFamily::Other(id) => id,
        };
        match &self.release {
            Some(release) => write!(formatter, "{name} {release}"),
            None => formatter.write_str(name),
        }
    }
}

/// The system the artifact would be installed on.
#[derive(Clone, Debug)]
pub struct Target {
    pub platform: TargetPlatform,
    pub distribution: Distribution,
    pub execution_policy: ExecutionPolicy,
    pub other_release_builds: OtherReleaseBuilds,
}

/// Where an offer of the system comes from.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Origin {
    /// A source of the distribution itself
    /// (`specifications/system-namespace.md`).
    Distribution,
    /// An installed package that did not come from Pakomichi.
    Installed,
    /// Another enabled source: a vendor repository, a PPA, a COPR (ADR-032).
    OtherSource,
}

/// One offer of a name: where it comes from and its constraint (a package's
/// own version is `Some((Equal, version))`).
type Offer = (Origin, Option<(Op, String)>);

/// What the system's packages offer: names at their versions and their
/// `Provides`, for one ecosystem, each with its [`Origin`]. Which packages
/// count is decided by the collector (P2-008b).
///
/// A name the distribution or an installed package offers belongs to the
/// system namespace (ADR-022), and only those offers satisfy a dependency
/// on it: a vendor repository with a newer C library does not make an
/// artifact that needs it admissible (owner decision of 2026-10-23). Any
/// other name may be satisfied by any enabled source.
#[derive(Clone, Debug)]
pub struct SystemPackages {
    ecosystem: Ecosystem,
    offers: BTreeMap<String, Vec<Offer>>,
}

impl SystemPackages {
    pub const fn new(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            offers: BTreeMap::new(),
        }
    }

    /// A package available or installed at `version` (a DEB version, or an
    /// RPM `[epoch:]version-release`). Several versions of one name may be
    /// added.
    pub fn add_package(&mut self, origin: Origin, name: &str, version: &str) {
        self.offer(origin, name, Some((Op::Equal, version.to_owned())));
    }

    /// A `Provides` entry, unversioned or with its constraint.
    pub fn add_provide(&mut self, origin: Origin, name: &str, constraint: Option<(Op, String)>) {
        self.offer(origin, name, constraint);
    }

    fn offer(&mut self, origin: Origin, name: &str, constraint: Option<(Op, String)>) {
        if name.is_empty() {
            return;
        }
        // Every architecture of a package and its own `Provides` repeat the
        // same offer; one copy is enough.
        let offers = self.offers.entry(name.to_owned()).or_default();
        let offer = (origin, constraint);
        if !offers.contains(&offer) {
            offers.push(offer);
        }
    }

    pub const fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    /// No data about the distribution itself. Offers of other sources alone
    /// say nothing about the system.
    pub fn is_empty(&self) -> bool {
        !self
            .offers
            .values()
            .flatten()
            .any(|(origin, _)| *origin != Origin::OtherSource)
    }

    /// Whether `name` belongs to the system namespace: the distribution or
    /// an installed package offers it at some version.
    pub fn knows(&self, name: &str) -> bool {
        self.offers.get(name).is_some_and(|offers| {
            offers
                .iter()
                .any(|(origin, _)| *origin != Origin::OtherSource)
        })
    }

    /// The versions at which packages of `origin` offer `name` itself.
    pub fn versions(&self, origin: Origin, name: &str) -> Vec<&str> {
        self.offers
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|(offer_origin, constraint)| match constraint {
                Some((Op::Equal, version)) if *offer_origin == origin => Some(version.as_str()),
                _ => None,
            })
            .collect()
    }

    /// The number of names offered.
    pub fn len(&self) -> usize {
        self.offers.len()
    }

    /// Whether some admissible offer satisfies `atom` under the native rules.
    pub fn satisfies(&self, atom: &Atom) -> bool {
        let system_name = self.knows(&atom.name);
        self.offers.get(&atom.name).is_some_and(|offers| {
            offers
                .iter()
                .filter(|(origin, _)| !system_name || *origin != Origin::OtherSource)
                .any(|(_, offer)| offer_satisfies(self.ecosystem, offer.as_ref(), atom))
        })
    }
}

/// What the build tags in the native version claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildClaim {
    /// No tag of a known distribution: a generic build.
    Generic,
    /// Built for the target distribution and release.
    Target { tag: String },
    /// Built for another release of the target distribution, or for the
    /// distribution without naming the release.
    OtherRelease { tag: String },
    /// Built for another distribution.
    OtherDistribution { tag: String },
}

/// Debian release numbers and their code names.
const DEBIAN_CODENAMES: [(&str, &str); 6] = [
    ("10", "buster"),
    ("11", "bullseye"),
    ("12", "bookworm"),
    ("13", "trixie"),
    ("14", "forky"),
    ("15", "duke"),
];

/// Ubuntu code names and their releases.
const UBUNTU_CODENAMES: [(&str, &str); 5] = [
    ("20.04", "focal"),
    ("22.04", "jammy"),
    ("24.04", "noble"),
    ("25.04", "plucky"),
    ("25.10", "questing"),
];

/// One tag found in a version: the distribution it names and the text.
#[derive(Clone, Debug)]
struct Tag {
    distribution: Distribution,
    text: String,
}

/// Reads the build tags of a native version. Only tags of the version's own
/// ecosystem are recognized: `.elN`/`.fcN` in an RPM release, `debN`,
/// `bpoN`, Debian and Ubuntu code names, `ubuntu` and `astra` in a DEB
/// version.
pub fn build_claim(ecosystem: Ecosystem, version: &str, target: &Distribution) -> BuildClaim {
    let tags = match ecosystem {
        Ecosystem::Rpm => rpm_tags(version),
        Ecosystem::Deb => deb_tags(version),
    };
    if tags.is_empty() {
        return BuildClaim::Generic;
    }
    // A rebuild keeps the tag of the distribution it came from
    // (`+deb12u4+astra1`): the target's own tags decide when present.
    let own: Vec<&Tag> = tags
        .iter()
        .filter(|tag| tag.distribution.family == target.family)
        .collect();
    let Some(first) = own.first() else {
        // A build for the distribution the target is based on (`+deb12u1`
        // on Astra Linux 1.8) is another release of it, never foreign.
        let base = target.based_on().map(|base| base.family);
        if let Some(tag) = tags
            .iter()
            .find(|tag| Some(&tag.distribution.family) == base.as_ref())
        {
            return BuildClaim::OtherRelease {
                tag: tag.text.clone(),
            };
        }
        return BuildClaim::OtherDistribution {
            tag: tags[0].text.clone(),
        };
    };
    match own.iter().find(|tag| {
        tag.distribution.release.is_some() && tag.distribution.release == target.release
    }) {
        Some(tag) => BuildClaim::Target {
            tag: tag.text.clone(),
        },
        None => BuildClaim::OtherRelease {
            tag: first.text.clone(),
        },
    }
}

fn rpm_tags(evr: &str) -> Vec<Tag> {
    let release = evr.rsplit_once('-').map_or("", |(_, release)| release);
    let mut tags = Vec::new();
    for part in release.split(['.', '+']) {
        for (prefix, family) in [
            ("el", DistributionFamily::EnterpriseLinux),
            ("fc", DistributionFamily::Fedora),
        ] {
            if let Some(rest) = part.strip_prefix(prefix) {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                // `el9`, `el9_4`; not `elf` or `fcgi`.
                let tail = &rest[digits.len()..];
                if !digits.is_empty() && (tail.is_empty() || tail.starts_with('_')) {
                    tags.push(Tag {
                        distribution: Distribution {
                            family: family.clone(),
                            release: Some(digits),
                        },
                        text: format!(".{part}"),
                    });
                }
            }
        }
    }
    tags
}

fn deb_tags(version: &str) -> Vec<Tag> {
    let lower = version.to_ascii_lowercase();
    let mut tags = Vec::new();
    // Tags start after `+`, `~`, `.` or a digit (`1ubuntu1`, `9+deb12u4`).
    let starts = |index: usize| {
        index == 0
            || lower[..index]
                .chars()
                .next_back()
                .is_some_and(|c| matches!(c, '+' | '~' | '.' | '-') || c.is_ascii_digit())
    };
    let mut push = |family: DistributionFamily, release: Option<String>, text: &str| {
        tags.push(Tag {
            distribution: Distribution { family, release },
            text: text.to_owned(),
        });
    };
    for (index, _) in lower.char_indices() {
        if !starts(index) {
            continue;
        }
        let rest = &lower[index..];
        for prefix in ["deb", "bpo"] {
            if let Some(after) = rest.strip_prefix(prefix) {
                let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
                if !digits.is_empty() {
                    let text = &version[index..index + prefix.len() + digits.len()];
                    push(DistributionFamily::Debian, Some(digits), text);
                }
            }
        }
        for (release, codename) in DEBIAN_CODENAMES {
            if word_at(rest, codename) {
                push(
                    DistributionFamily::Debian,
                    Some(release.to_owned()),
                    &version[index..index + codename.len()],
                );
            }
        }
        for (release, codename) in UBUNTU_CODENAMES {
            if word_at(rest, codename) {
                push(
                    DistributionFamily::Ubuntu,
                    Some(release.to_owned()),
                    &version[index..index + codename.len()],
                );
            }
        }
        if rest.starts_with("ubuntu") {
            // `1ubuntu1~22.04`: the release follows the next `~` when present.
            let release = lower[index..].split('~').nth(1).and_then(|after| {
                let release: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                (release.len() == 5).then_some(release)
            });
            push(
                DistributionFamily::Ubuntu,
                release,
                &version[index..index + 6],
            );
        }
        if rest.starts_with("astra") {
            push(DistributionFamily::Astra, None, &version[index..index + 5]);
        }
    }
    tags
}

/// `word` at the start of `text`, not followed by a letter.
fn word_at(text: &str, word: &str) -> bool {
    text.strip_prefix(word)
        .is_some_and(|after| !after.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// The dependencies the family does not offer, checked against the system.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dependencies {
    Satisfiable,
    /// Satisfiable as far as checked; some clauses (RPM rich dependencies)
    /// are left to the native manager.
    NotEvaluated {
        clauses: Vec<String>,
    },
    /// The first clause no system package satisfies.
    Unsatisfiable {
        clause: String,
    },
}

/// How much the facts support the claim that the artifact works on the
/// target. Even `Tested` is not a guarantee of correct operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    Low,
    /// A generic build whose dependencies the system satisfies.
    DependenciesSatisfiable,
    /// Built for the target and its dependencies are satisfied.
    Claimed,
    /// In addition, a test record exists for this target.
    Tested,
}

/// Why the artifact is held.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatHold {
    ExecutionPolicy(ExecutionPolicy),
    /// A package of another ecosystem.
    Ecosystem(Ecosystem),
    Architecture {
        arch: String,
    },
    OtherDistribution {
        tag: String,
    },
    /// Only with [`OtherReleaseBuilds::Hold`].
    OtherRelease {
        tag: String,
    },
    SystemUnknown,
    Dependency {
        clause: String,
    },
}

impl CompatHold {
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::ExecutionPolicy(_) => ReasonCode::EExecutionPolicy,
            Self::Ecosystem(_)
            | Self::Architecture { .. }
            | Self::OtherDistribution { .. }
            | Self::OtherRelease { .. } => ReasonCode::EPlatformUnsupported,
            Self::SystemUnknown => ReasonCode::ESystemNamespaceUnknown,
            Self::Dependency { .. } => ReasonCode::EDependencyUnsatisfiable,
        }
    }
}

impl fmt::Display for CompatHold {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExecutionPolicy(ExecutionPolicy::Unknown) => {
                formatter.write_str("the execution policy of the system cannot be ruled out")
            }
            Self::ExecutionPolicy(_) => {
                formatter.write_str("the execution policy of the system is on")
            }
            Self::Ecosystem(ecosystem) => write!(formatter, "a {ecosystem} package"),
            Self::Architecture { arch } => write!(formatter, "built for architecture {arch}"),
            Self::OtherDistribution { tag } => {
                write!(formatter, "built for another distribution ({tag})")
            }
            Self::OtherRelease { tag } => write!(formatter, "built for another release ({tag})"),
            Self::SystemUnknown => formatter.write_str("no data about the system's packages"),
            Self::Dependency { clause } => {
                write!(formatter, "no system package satisfies {clause}")
            }
        }
    }
}

/// The compatibility facts of one artifact for one target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assessment {
    pub format_arch_ok: bool,
    pub build: BuildClaim,
    /// `None` when an earlier hold made the check pointless.
    pub dependencies: Option<Dependencies>,
    pub declared_dependency_satisfiable: bool,
    pub platform_claimed: bool,
    pub platform_tested: bool,
    pub confidence: Confidence,
    pub hold: Option<CompatHold>,
}

impl Assessment {
    pub fn reason_code(&self) -> Option<ReasonCode> {
        self.hold.as_ref().map(CompatHold::reason_code)
    }
}

/// Whether sources may be activated at all on the target (N-035).
pub const fn activation_allowed(target: &Target) -> Result<(), CompatHold> {
    match target.execution_policy {
        ExecutionPolicy::Off => Ok(()),
        policy => Err(CompatHold::ExecutionPolicy(policy)),
    }
}

/// Assesses one artifact. `family_offers` are the names the admitted family
/// offers (members and their `Provides`); a clause naming one of them is
/// left to the family admission. `tested` says that a test record exists
/// for this artifact on this target (the P5 matrix).
pub fn assess(
    target: &Target,
    package: &PackageMetadata,
    family_offers: &BTreeSet<String>,
    system: &SystemPackages,
    tested: bool,
) -> Assessment {
    let ecosystem_ok = package.ecosystem() == target.platform.ecosystem();
    let format_arch_ok = ecosystem_ok && target.platform.accepts_native_arch(package.arch());
    let build = build_claim(package.ecosystem(), package.version(), &target.distribution);
    let mut assessment = Assessment {
        format_arch_ok,
        build: build.clone(),
        dependencies: None,
        declared_dependency_satisfiable: false,
        platform_claimed: matches!(build, BuildClaim::Target { .. }),
        platform_tested: false,
        confidence: Confidence::Low,
        hold: None,
    };
    let hold = if target.execution_policy != ExecutionPolicy::Off {
        Some(CompatHold::ExecutionPolicy(target.execution_policy))
    } else if !ecosystem_ok {
        Some(CompatHold::Ecosystem(package.ecosystem()))
    } else if !format_arch_ok {
        Some(CompatHold::Architecture {
            arch: package.arch().to_owned(),
        })
    } else {
        match &build {
            BuildClaim::OtherDistribution { tag } => {
                Some(CompatHold::OtherDistribution { tag: tag.clone() })
            }
            BuildClaim::OtherRelease { tag }
                if target.other_release_builds == OtherReleaseBuilds::Hold =>
            {
                Some(CompatHold::OtherRelease { tag: tag.clone() })
            }
            _ if system.is_empty() || system.ecosystem() != package.ecosystem() => {
                Some(CompatHold::SystemUnknown)
            }
            _ => None,
        }
    };
    if hold.is_some() {
        assessment.hold = hold;
        return assessment;
    }
    let dependencies = check_dependencies(package, family_offers, system);
    if let Dependencies::Unsatisfiable { clause } = &dependencies {
        assessment.hold = Some(CompatHold::Dependency {
            clause: clause.clone(),
        });
    }
    let satisfiable = dependencies == Dependencies::Satisfiable;
    assessment.declared_dependency_satisfiable = satisfiable;
    assessment.platform_tested = tested && assessment.hold.is_none();
    assessment.confidence = match (&build, satisfiable) {
        _ if assessment.hold.is_some() => Confidence::Low,
        (BuildClaim::Target { .. } | BuildClaim::Generic, true) if tested => Confidence::Tested,
        (BuildClaim::Target { .. }, true) => Confidence::Claimed,
        (BuildClaim::Generic, true) => Confidence::DependenciesSatisfiable,
        _ => Confidence::Low,
    };
    assessment.dependencies = Some(dependencies);
    assessment
}

fn check_dependencies(
    package: &PackageMetadata,
    family_offers: &BTreeSet<String>,
    system: &SystemPackages,
) -> Dependencies {
    let mut not_evaluated = Vec::new();
    for clause in package.depends() {
        match clause {
            Clause::Rich(text) => not_evaluated.push(text.clone()),
            Clause::Any(atoms) => {
                // A name the system knows is always checked against the
                // system: a family that "provides" the C library itself
                // must not make a newer one look satisfied.
                if atoms
                    .iter()
                    .any(|atom| family_offers.contains(&atom.name) && !system.knows(&atom.name))
                {
                    continue;
                }
                if !atoms.iter().any(|atom| system.satisfies(atom)) {
                    return Dependencies::Unsatisfiable {
                        clause: clause_text(package.ecosystem(), atoms),
                    };
                }
            }
        }
    }
    if not_evaluated.is_empty() {
        Dependencies::Satisfiable
    } else {
        Dependencies::NotEvaluated {
            clauses: not_evaluated,
        }
    }
}

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

#[cfg(target_os = "linux")]
pub mod detect;
pub mod policy;

#[cfg(test)]
mod tests;
