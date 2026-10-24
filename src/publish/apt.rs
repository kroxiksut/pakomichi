// SPDX-License-Identifier: MIT OR Apache-2.0

//! The APT indexes of one logical repository (P3-001, ADR-008, ADR-024
//! point 1, `specifications/apt.md`).
//!
//! `Packages` and `Release` are generated from the exact bytes of admitted
//! DEB files: every stanza is the package's own `control` paragraph, field
//! for field, followed by the `Filename`, `Size`, and `SHA256` of the stored
//! object. A control paragraph that already carries one of those fields is
//! refused: otherwise the package could point APT at another file.
//!
//! `Release` declares `NotAutomatic: yes` and `ButAutomaticUpgrades: yes`,
//! so APT gives the whole repository priority 100: it never displaces a
//! version from another source, and a package installed from it still
//! gets its upgrades. Only an activated name gets more, through a 990 pin
//! (`crate::apt`). `Release` declares `Acquire-By-Hash: yes`; the publisher serves every
//! index under its `by-hash` path as well. `Valid-Until` is the confirmed
//! freshness, the last confirmed synchronization plus the maximum
//! freshness, never the signing time plus the maximum freshness: a failed
//! synchronization does not extend validity, and stale data is never signed
//! as fresh (ADR-010).
//!
//! [`check_generation`] is a separate reader of the same files: before a
//! generation becomes current it re-reads the signed `Release` and every
//! `Packages`, and checks every reference against the bytes that will be
//! served. It shares no code with the generator, so a generator defect is
//! caught here rather than by APT on the user's system.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::manifest::RepoPath;
use crate::cas::{ExpectedObject, Sha256Digest};
use crate::error::ReasonCode;
use crate::family::version::DebVersion;
use crate::inspect::DebControl;
use crate::policy::level::APT_ORIGIN;

/// The only component of a Pakomichi repository.
pub const COMPONENT: &str = "main";

/// Fields that the index adds; a package must not bring its own.
const INDEX_FIELDS: [&str; 6] = ["Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512"];

/// Why the indexes could not be built or did not pass the check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AptError {
    /// The label is not a repository name (lowercase letters, digits, inner
    /// `-`, at most 64 characters).
    InvalidLabel(String),
    /// A repository needs at least one architecture, each a Debian
    /// architecture name other than `all`.
    InvalidArchitectures,
    /// A package for an architecture the repository does not serve.
    ArchitectureNotServed {
        package: String,
        architecture: String,
    },
    /// The control paragraph carries a field the index itself writes.
    IndexFieldInControl { package: String, field: String },
    /// The version cannot be compared as a Debian version.
    InvalidVersion { package: String },
    /// Two different files with one package, version, and architecture:
    /// APT would merge them and pick one by source order (R-001).
    Ambiguous {
        package: String,
        version: String,
        architecture: String,
    },
    /// The confirmed freshness has run out; nothing is signed as fresh.
    Stale { valid_until: u64, now: u64 },
    /// The last confirmed synchronization lies in the future.
    ConfirmedInFuture { confirmed_at: u64, now: u64 },
    /// The generation failed the check before publication.
    Check(String),
}

impl AptError {
    pub const fn reason(&self) -> ReasonCode {
        match self {
            Self::IndexFieldInControl { .. } | Self::InvalidVersion { .. } => {
                ReasonCode::EArtifactMalformed
            }
            Self::Ambiguous { .. } => ReasonCode::ESourceAmbiguous,
            Self::Stale { .. } | Self::ConfirmedInFuture { .. } => ReasonCode::ESourceStale,
            Self::ArchitectureNotServed { .. } => ReasonCode::EPlatformUnsupported,
            Self::InvalidLabel(_) | Self::InvalidArchitectures | Self::Check(_) => {
                ReasonCode::ESnapshotInconsistent
            }
        }
    }
}

impl fmt::Display for AptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLabel(label) => write!(formatter, "{label:?} is not a repository label"),
            Self::InvalidArchitectures => formatter.write_str("invalid repository architectures"),
            Self::ArchitectureNotServed {
                package,
                architecture,
            } => write!(
                formatter,
                "{package} is built for {architecture}, which this repository does not serve"
            ),
            Self::IndexFieldInControl { package, field } => write!(
                formatter,
                "the control file of {package} carries the index field {field}"
            ),
            Self::InvalidVersion { package } => {
                write!(formatter, "{package} has no comparable Debian version")
            }
            Self::Ambiguous {
                package,
                version,
                architecture,
            } => write!(
                formatter,
                "two different files are {package} {version} {architecture}"
            ),
            Self::Stale { valid_until, now } => write!(
                formatter,
                "confirmed freshness ended at {valid_until}, now is {now}"
            ),
            Self::ConfirmedInFuture { confirmed_at, now } => write!(
                formatter,
                "synchronization confirmed at {confirmed_at}, after now ({now})"
            ),
            Self::Check(what) => write!(formatter, "generation check failed: {what}"),
        }
    }
}

impl std::error::Error for AptError {}

fn check(what: impl Into<String>) -> AptError {
    AptError::Check(what.into())
}

fn is_label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

fn is_architecture(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 32
        && text != "all"
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// One logical APT repository: `dists/<label>/` with `Origin: Pakomichi`,
/// and `Label`, `Suite`, and `Codename` all equal to the label of its
/// source and level (ADR-027 point 6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AptRepository {
    label: String,
    architectures: BTreeSet<String>,
}

impl AptRepository {
    pub fn new(label: &str, architectures: &[&str]) -> Result<Self, AptError> {
        if !is_label(label) {
            return Err(AptError::InvalidLabel(label.to_owned()));
        }
        if architectures.is_empty() || !architectures.iter().all(|arch| is_architecture(arch)) {
            return Err(AptError::InvalidArchitectures);
        }
        Ok(Self {
            label: label.to_owned(),
            architectures: architectures
                .iter()
                .map(|arch| (*arch).to_owned())
                .collect(),
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    fn dists(&self) -> String {
        format!("dists/{}", self.label)
    }

    /// `dists/<label>/InRelease`, the only signed path.
    pub fn in_release_path(&self) -> Result<RepoPath, AptError> {
        path(&format!("{}/InRelease", self.dists()))
    }

    /// The `Packages` path of one architecture, relative to `dists/<label>`.
    fn packages_relative(architecture: &str) -> String {
        format!("{COMPONENT}/binary-{architecture}/Packages")
    }
}

fn path(text: &str) -> Result<RepoPath, AptError> {
    RepoPath::new(text).map_err(|_| check(format!("{text} is not a repository path")))
}

/// One admitted DEB file: its inspected control paragraph and the identity
/// of its stored bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AptPackage {
    pub control: DebControl,
    pub object: ExpectedObject,
}

/// What the freshness of the source rests on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Freshness {
    /// Unix seconds of the last successful confirmed synchronization.
    pub confirmed_at: u64,
    /// The maximum freshness in seconds (7 days by default).
    pub max_freshness: u64,
}

/// The generated files of one generation, before signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AptIndexes {
    /// The `Release` text; `InRelease` is its clear-signed form.
    pub release: Vec<u8>,
    /// Each `Packages` index at its plain path.
    pub indexes: Vec<(RepoPath, Vec<u8>)>,
    /// Each package at `pool/<sha256>/<file>.deb`.
    pub pool: Vec<(RepoPath, ExpectedObject)>,
    /// `Date`, Unix seconds.
    pub date: u64,
    /// `Valid-Until`, Unix seconds.
    pub valid_until: u64,
}

/// The pool path of a package: its digest directory and a name built from
/// the control fields, never from the asset's own file name. The name is
/// for people; the digest makes the path unique.
fn pool_path(control: &DebControl, digest: &Sha256Digest) -> Result<RepoPath, AptError> {
    let version = control
        .version()
        .split_once(':')
        .map_or(control.version(), |(_, rest)| rest)
        .replace(':', "_");
    path(&format!(
        "pool/{}/{}_{}_{}.deb",
        digest.to_hex(),
        control.package(),
        version,
        control.architecture()
    ))
}

fn stanza(package: &AptPackage, filename: &RepoPath) -> Result<String, AptError> {
    let control = &package.control;
    let mut text = String::new();
    for (name, value) in control.fields() {
        if INDEX_FIELDS
            .iter()
            .any(|field| field.eq_ignore_ascii_case(name))
        {
            return Err(AptError::IndexFieldInControl {
                package: control.package().to_owned(),
                field: name.clone(),
            });
        }
        text.push_str(name);
        text.push(':');
        if !value.is_empty() && !value.starts_with('\n') {
            text.push(' ');
        }
        text.push_str(value);
        text.push('\n');
    }
    text.push_str(&format!(
        "Filename: {filename}\nSize: {}\nSHA256: {}\n",
        package.object.size,
        package.object.sha256.to_hex()
    ));
    Ok(text)
}

/// Builds `Packages` for every architecture and the `Release` that lists
/// them. `now` is the signing time (Unix seconds).
pub fn build_indexes(
    repo: &AptRepository,
    packages: &[AptPackage],
    freshness: Freshness,
    now: u64,
) -> Result<AptIndexes, AptError> {
    if freshness.confirmed_at > now {
        return Err(AptError::ConfirmedInFuture {
            confirmed_at: freshness.confirmed_at,
            now,
        });
    }
    let valid_until = freshness
        .confirmed_at
        .saturating_add(freshness.max_freshness);
    if valid_until <= now {
        return Err(AptError::Stale { valid_until, now });
    }

    // One file per package, version, and architecture; the same bytes
    // offered twice are one entry.
    let mut chosen: Vec<(DebVersion, &AptPackage)> = Vec::new();
    for package in packages {
        let control = &package.control;
        let architecture = control.architecture();
        if architecture != "all" && !repo.architectures.contains(architecture) {
            return Err(AptError::ArchitectureNotServed {
                package: control.package().to_owned(),
                architecture: architecture.to_owned(),
            });
        }
        let version =
            DebVersion::parse(control.version()).map_err(|_| AptError::InvalidVersion {
                package: control.package().to_owned(),
            })?;
        let same = chosen.iter().find(|(other_version, other)| {
            other.control.package() == control.package()
                && other.control.architecture() == architecture
                && other_version.cmp(&version) == Ordering::Equal
        });
        match same {
            Some((_, other)) if other.object == package.object => continue,
            Some(_) => {
                return Err(AptError::Ambiguous {
                    package: control.package().to_owned(),
                    version: control.version().to_owned(),
                    architecture: architecture.to_owned(),
                });
            }
            None => chosen.push((version, package)),
        }
    }
    chosen.sort_by(|(left_version, left), (right_version, right)| {
        left.control
            .package()
            .cmp(right.control.package())
            .then_with(|| left_version.cmp(right_version))
            .then_with(|| {
                left.control
                    .architecture()
                    .cmp(right.control.architecture())
            })
    });

    let mut pool = Vec::with_capacity(chosen.len());
    let mut stanzas: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (_, package) in &chosen {
        let filename = pool_path(&package.control, &package.object.sha256)?;
        let text = stanza(package, &filename)?;
        let architecture = package.control.architecture();
        for served in &repo.architectures {
            if architecture == "all" || architecture == served {
                stanzas.entry(served).or_default().push(text.clone());
            }
        }
        pool.push((filename, package.object));
    }

    let mut indexes = Vec::new();
    let mut checksums = String::new();
    for architecture in &repo.architectures {
        let relative = AptRepository::packages_relative(architecture);
        let bytes = stanzas
            .get(architecture.as_str())
            .map(|list| list.join("\n"))
            .unwrap_or_default()
            .into_bytes();
        checksums.push_str(&format!(
            " {} {} {relative}\n",
            Sha256Digest::of(&bytes).to_hex(),
            bytes.len()
        ));
        indexes.push((path(&format!("{}/{relative}", repo.dists()))?, bytes));
    }

    let architectures: Vec<&str> = repo.architectures.iter().map(String::as_str).collect();
    let release = format!(
        "Origin: {APT_ORIGIN}\nLabel: {label}\nSuite: {label}\nCodename: {label}\n\
         Date: {date}\nValid-Until: {valid}\nArchitectures: {architectures}\n\
         Components: {COMPONENT}\nNotAutomatic: yes\nButAutomaticUpgrades: yes\n\
         Acquire-By-Hash: yes\nSHA256:\n{checksums}",
        label = repo.label,
        date = rfc2822(now),
        valid = rfc2822(valid_until),
        architectures = architectures.join(" "),
    );
    Ok(AptIndexes {
        release: release.into_bytes(),
        indexes,
        pool,
        date: now,
        valid_until,
    })
}

/// The files a generation will serve, as the check reads them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GenerationFiles {
    /// Every index by its plain path, with its bytes.
    pub indexes: BTreeMap<RepoPath, Vec<u8>>,
    /// Every pool path and the identity of its stored object.
    pub pool: BTreeMap<RepoPath, ExpectedObject>,
}

/// Reads one deb822 paragraph strictly: `Name: value` lines, continuation
/// lines that start with a space, no comments, no blank lines, no
/// duplicate names.
fn paragraph(text: &str) -> Result<Vec<(String, String)>, AptError> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.split_terminator('\n') {
        if line.starts_with(' ') {
            let Some((_, value)) = fields.last_mut() else {
                return Err(check("continuation line without a field"));
            };
            value.push('\n');
            value.push_str(line);
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(check(format!("line without a field: {line:?}")));
        };
        if name.is_empty()
            || fields
                .iter()
                .any(|(other, _)| other.eq_ignore_ascii_case(name))
        {
            return Err(check(format!("empty or duplicate field {name:?}")));
        }
        fields.push((name.to_owned(), value.trim_start_matches(' ').to_owned()));
    }
    Ok(fields)
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Result<&'a str, AptError> {
    fields
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| check(format!("{name} is missing")))
}

/// Checks a generation before it becomes current: `signed_release` is the
/// text the signature covers (as `gpgv` returned it), `files` everything
/// the generation serves. Every index the release lists is served with the
/// listed digest and size; every architecture has its index; every stanza
/// names a served pool file with its digest and size; every pool file is
/// listed; the validity is the expected one and has not ended at `now`.
pub fn check_generation(
    repo: &AptRepository,
    signed_release: &[u8],
    files: &GenerationFiles,
    valid_until: u64,
    now: u64,
) -> Result<(), AptError> {
    let text = std::str::from_utf8(signed_release).map_err(|_| check("Release is not UTF-8"))?;
    let fields = paragraph(text)?;
    for (name, expected) in [
        ("Origin", APT_ORIGIN),
        ("Label", repo.label.as_str()),
        ("Suite", repo.label.as_str()),
        ("Codename", repo.label.as_str()),
        ("Components", COMPONENT),
        ("NotAutomatic", "yes"),
        ("ButAutomaticUpgrades", "yes"),
        ("Acquire-By-Hash", "yes"),
    ] {
        if field(&fields, name)? != expected {
            return Err(check(format!("{name} is not {expected:?}")));
        }
    }
    let served: Vec<&str> = repo.architectures.iter().map(String::as_str).collect();
    if field(&fields, "Architectures")? != served.join(" ") {
        return Err(check("Architectures differ from the repository"));
    }
    let date = parse_rfc2822(field(&fields, "Date")?)?;
    let stated_until = parse_rfc2822(field(&fields, "Valid-Until")?)?;
    if stated_until != valid_until || date > now || stated_until <= now {
        return Err(check("Date or Valid-Until is not the confirmed freshness"));
    }

    let dists = repo.dists();
    let mut listed = BTreeSet::new();
    for line in field(&fields, "SHA256")?
        .split('\n')
        .filter(|line| !line.is_empty())
    {
        let parts: Vec<&str> = line.split(' ').filter(|part| !part.is_empty()).collect();
        let [digest, size, relative] = parts.as_slice() else {
            return Err(check(format!("malformed SHA256 line {line:?}")));
        };
        let digest =
            Sha256Digest::from_hex(digest).map_err(|_| check("malformed digest in Release"))?;
        let size: u64 = size
            .parse()
            .map_err(|_| check("malformed size in Release"))?;
        let index_path = path(&format!("{dists}/{relative}"))?;
        let Some(bytes) = files.indexes.get(&index_path) else {
            return Err(check(format!("{index_path} is listed but not served")));
        };
        if Sha256Digest::of(bytes) != digest || bytes.len() as u64 != size {
            return Err(check(format!("{index_path} does not match Release")));
        }
        if !listed.insert(index_path) {
            return Err(check("an index is listed twice"));
        }
    }
    if listed.len() != files.indexes.len() {
        return Err(check("an index is served but not listed"));
    }

    let mut referenced = BTreeSet::new();
    for architecture in &repo.architectures {
        let index_path = path(&format!(
            "{dists}/{}",
            AptRepository::packages_relative(architecture)
        ))?;
        let Some(bytes) = files.indexes.get(&index_path) else {
            return Err(check(format!("no index for {architecture}")));
        };
        let text = std::str::from_utf8(bytes).map_err(|_| check("Packages is not UTF-8"))?;
        let mut seen = BTreeSet::new();
        for block in text.split("\n\n").filter(|block| !block.is_empty()) {
            let fields = paragraph(block)?;
            let package = field(&fields, "Package")?;
            let version = field(&fields, "Version")?;
            let arch = field(&fields, "Architecture")?;
            if arch != "all" && arch != architecture {
                return Err(check(format!(
                    "{package} {arch} in the {architecture} index"
                )));
            }
            if !seen.insert((package.to_owned(), version.to_owned(), arch.to_owned())) {
                return Err(check(format!("{package} {version} is listed twice")));
            }
            let filename = path(field(&fields, "Filename")?)?;
            let Some(object) = files.pool.get(&filename) else {
                return Err(check(format!("{filename} is not served")));
            };
            let digest = Sha256Digest::from_hex(field(&fields, "SHA256")?)
                .map_err(|_| check("malformed digest in Packages"))?;
            let size: u64 = field(&fields, "Size")?
                .parse()
                .map_err(|_| check("malformed size in Packages"))?;
            if *object != ExpectedObject::new(digest, size) {
                return Err(check(format!("{filename} does not match its stanza")));
            }
            referenced.insert(filename);
        }
    }
    if referenced.len() != files.pool.len() {
        return Err(check("a pool file is served but no index lists it"));
    }
    Ok(())
}

const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The civil date of a day count since 1970-01-01 (H. Hinnant's
/// `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn split_time(seconds: u64) -> (i64, u64) {
    ((seconds / 86_400) as i64, seconds % 86_400)
}

/// `Thu, 23 Oct 2026 10:00:00 UTC`, the form Debian archives write.
pub fn rfc2822(seconds: u64) -> String {
    let (days, rest) = split_time(seconds);
    let (year, month, day) = civil(days);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} UTC",
        WEEKDAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the form of the manifest and the schema.
pub fn iso8601(seconds: u64) -> String {
    let (days, rest) = split_time(seconds);
    let (year, month, day) = civil(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// Reads back exactly the form [`rfc2822`] writes.
fn parse_rfc2822(text: &str) -> Result<u64, AptError> {
    let invalid = || check(format!("{text:?} is not a release date"));
    let parts: Vec<&str> = text.split(' ').collect();
    let [_weekday, day, month, year, clock, "UTC"] = parts.as_slice() else {
        return Err(invalid());
    };
    let number = |text: &str, digits: usize| -> Result<u64, AptError> {
        if text.len() != digits || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        text.parse().map_err(|_| invalid())
    };
    let month = MONTHS
        .iter()
        .position(|name| name == month)
        .ok_or_else(invalid)? as u32
        + 1;
    let day = number(day, 2)? as u32;
    let year = number(year, 4)? as i64;
    let clock: Vec<&str> = clock.split(':').collect();
    let [hours, minutes, seconds] = clock.as_slice() else {
        return Err(invalid());
    };
    let (hours, minutes, seconds) = (number(hours, 2)?, number(minutes, 2)?, number(seconds, 2)?);
    if hours > 23 || minutes > 59 || seconds > 59 || day == 0 || day > 31 || year < 1970 {
        return Err(invalid());
    }
    let days = days_from_civil(year, month, day);
    let value = (days as u64) * 86_400 + hours * 3600 + minutes * 60 + seconds;
    // The round trip rejects a wrong weekday and a day the month lacks.
    if rfc2822(value) != text {
        return Err(invalid());
    }
    Ok(value)
}

#[cfg(test)]
#[path = "apt_tests.rs"]
mod tests;
