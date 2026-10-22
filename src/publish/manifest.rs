// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generation manifest: the immutable list of every path one published
//! generation of one logical repository serves, with the digest and size of
//! its bytes (ADR-008, ADR-024 point 1, R-004).
//!
//! The manifest is the source of truth for a generation; SQLite rows about
//! it are derived (ADR-013). Its text form is versioned, strictly parsed,
//! and written once.

use std::collections::BTreeMap;
use std::fmt;

use crate::cas::{ExpectedObject, Sha256Digest};

const MAGIC: &str = "pakomichi-generation v1";
const MAX_PATH_BYTES: usize = 512;
const MAX_PATH_DEPTH: usize = 16;
/// Largest number of paths in one generation.
pub const MAX_ENTRIES: usize = 100_000;

/// Why a name, path, or manifest is not acceptable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    InvalidName(&'static str),
    InvalidPath,
    /// A path that is neither one of the mutable metadata paths nor a
    /// content-addressed path of the backend (ADR-024 point 1).
    UnclassifiedPath(String),
    /// A content-addressed path whose name does not carry its own digest.
    DigestNotInName(String),
    /// An APT index served without its `by-hash` alias.
    MissingByHashAlias(String),
    DuplicatePath(String),
    /// A content-addressed path whose bytes differ from a retained
    /// generation.
    ImmutablePathChanged(String),
    TooManyEntries,
    Empty,
    /// The text form does not follow the format.
    Malformed(&'static str),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(what) => write!(formatter, "invalid {what}"),
            Self::InvalidPath => formatter.write_str("invalid repository path"),
            Self::UnclassifiedPath(path) => {
                write!(
                    formatter,
                    "path {path} is neither mutable metadata nor content-addressed"
                )
            }
            Self::DigestNotInName(path) => {
                write!(
                    formatter,
                    "content-addressed path {path} does not carry its digest"
                )
            }
            Self::MissingByHashAlias(path) => {
                write!(formatter, "index {path} has no by-hash alias")
            }
            Self::DuplicatePath(path) => write!(formatter, "duplicate path {path}"),
            Self::ImmutablePathChanged(path) => {
                write!(formatter, "content-addressed path {path} changes bytes")
            }
            Self::TooManyEntries => formatter.write_str("too many paths in one generation"),
            Self::Empty => formatter.write_str("a generation needs at least one path"),
            Self::Malformed(what) => write!(formatter, "malformed manifest: {what}"),
        }
    }
}

impl std::error::Error for ManifestError {}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

/// The name of one logical repository, for example
/// `src-1234-apt-strict`: lowercase ASCII letters, digits, and inner `-`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepoName(String);

impl RepoName {
    pub fn new(name: &str) -> Result<Self, ManifestError> {
        if !is_name(name) {
            return Err(ManifestError::InvalidName("repository name"));
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepoName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The source a logical repository belongs to (`forge_repository.id`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceId(String);

impl SourceId {
    pub fn new(id: &str) -> Result<Self, ManifestError> {
        if !is_name(id) {
            return Err(ManifestError::InvalidName("source id"));
        }
        Ok(Self(id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The native backend a logical repository serves; the values of
/// `snapshot.native_backend`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Backend {
    Apt,
    Dnf4,
    Dnf5,
}

impl Backend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf4 => "dnf4",
            Self::Dnf5 => "dnf5",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "apt" => Some(Self::Apt),
            "dnf4" => Some(Self::Dnf4),
            "dnf5" => Some(Self::Dnf5),
            _ => None,
        }
    }
}

/// A generation number. Numbers are allocated once per source and backend,
/// grow monotonically, and are never reused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GenerationId(u64);

impl GenerationId {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 || value > i64::MAX as u64 {
            return None;
        }
        Some(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for GenerationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// A path inside a logical repository: relative, at most 16 components of
/// `[A-Za-z0-9._+~-]`, none of them `.` or `..`, at most 512 bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepoPath(String);

impl RepoPath {
    pub fn new(path: &str) -> Result<Self, ManifestError> {
        let components: Vec<&str> = path.split('/').collect();
        let valid = !path.is_empty()
            && path.len() <= MAX_PATH_BYTES
            && components.len() <= MAX_PATH_DEPTH
            && components.iter().all(|component| {
                !component.is_empty()
                    && *component != "."
                    && *component != ".."
                    && component.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
                    })
            });
        if !valid {
            return Err(ManifestError::InvalidPath);
        }
        Ok(Self(path.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    fn parent(&self) -> &str {
        self.0.rsplit_once('/').map_or("", |(parent, _)| parent)
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Whether a path's bytes may change between generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathClass {
    /// Served only from the current generation (`InRelease`, `repomd.xml`,
    /// plain compatibility indexes).
    Mutable,
    /// Served from any retained generation; its bytes never change.
    ContentAddressed,
}

const APT_SIGNED: [&str; 3] = ["InRelease", "Release", "Release.gpg"];
const APT_PLAIN_INDEXES: [&str; 4] = ["Packages", "Packages.gz", "Packages.xz", "Translation-en"];

fn is_hex_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Classifies a path for `backend` (ADR-024 point 1) and checks that a
/// content-addressed path carries its digest:
///
/// - APT: `dists/**/InRelease`, `Release`, `Release.gpg` and the plain
///   indexes are mutable; `dists/**/by-hash/SHA256/<digest>` and
///   `pool/<digest>/<file>.deb` are content-addressed.
/// - DNF: `repodata/repomd.xml` and `repomd.xml.asc` are mutable;
///   `repodata/<digest>-<name>` and `packages/<digest>/<file>.rpm` are
///   content-addressed.
pub fn classify(
    backend: Backend,
    path: &RepoPath,
    digest: &Sha256Digest,
) -> Result<PathClass, ManifestError> {
    let text = path.as_str();
    let name = path.file_name();
    let components: Vec<&str> = text.split('/').collect();
    let unclassified = || ManifestError::UnclassifiedPath(text.to_owned());
    let named = |found: &str| {
        if found == digest.to_hex() {
            Ok(PathClass::ContentAddressed)
        } else {
            Err(ManifestError::DigestNotInName(text.to_owned()))
        }
    };
    match backend {
        Backend::Apt => match components.as_slice() {
            ["dists", .., "by-hash", "SHA256", found] => named(found),
            ["dists", _, ..] if APT_SIGNED.contains(&name) || APT_PLAIN_INDEXES.contains(&name) => {
                Ok(PathClass::Mutable)
            }
            ["pool", found, file] if file.ends_with(".deb") && is_hex_digest(found) => named(found),
            _ => Err(unclassified()),
        },
        Backend::Dnf4 | Backend::Dnf5 => match components.as_slice() {
            ["repodata", "repomd.xml" | "repomd.xml.asc"] => Ok(PathClass::Mutable),
            ["repodata", file] => match file.split_once('-') {
                Some((found, rest)) if is_hex_digest(found) && !rest.is_empty() => named(found),
                _ => Err(unclassified()),
            },
            ["packages", found, file] if file.ends_with(".rpm") && is_hex_digest(found) => {
                named(found)
            }
            _ => Err(unclassified()),
        },
    }
}

/// One path of a generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub path: RepoPath,
    pub object: ExpectedObject,
    pub class: PathClass,
}

/// Times as `YYYY-MM-DDTHH:MM:SSZ`, the form the schema stores.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(text: &str) -> Result<Self, ManifestError> {
        let bytes = text.as_bytes();
        let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
        let valid = bytes.len() == 20
            && digits(0..4)
            && bytes[4] == b'-'
            && digits(5..7)
            && bytes[7] == b'-'
            && digits(8..10)
            && bytes[10] == b'T'
            && digits(11..13)
            && bytes[13] == b':'
            && digits(14..16)
            && bytes[16] == b':'
            && digits(17..19)
            && bytes[19] == b'Z';
        if !valid {
            return Err(ManifestError::InvalidName("timestamp"));
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the caller states about a generation besides its paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationMeta {
    pub repo: RepoName,
    pub source: SourceId,
    pub backend: Backend,
    /// The validity the signed metadata states: APT `Date`/`Valid-Until`,
    /// for DNF the confirmed freshness (ADR-024 point 3).
    pub valid_from: Timestamp,
    pub valid_until: Timestamp,
}

/// A complete, validated generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub meta: GenerationMeta,
    pub generation: GenerationId,
    /// Seconds since the Unix epoch when the generation was written.
    pub created_at: u64,
    entries: BTreeMap<RepoPath, Entry>,
}

impl Manifest {
    /// Validates the paths for the backend and builds the manifest. Every
    /// path is classified; an APT plain index must have its `by-hash`
    /// alias in the same generation.
    pub fn new(
        meta: GenerationMeta,
        generation: GenerationId,
        created_at: u64,
        objects: Vec<(RepoPath, ExpectedObject)>,
    ) -> Result<Self, ManifestError> {
        if objects.is_empty() {
            return Err(ManifestError::Empty);
        }
        if objects.len() > MAX_ENTRIES {
            return Err(ManifestError::TooManyEntries);
        }
        let mut entries = BTreeMap::new();
        for (path, object) in objects {
            let class = classify(meta.backend, &path, &object.sha256)?;
            if entries.contains_key(&path) {
                return Err(ManifestError::DuplicatePath(path.as_str().to_owned()));
            }
            entries.insert(
                path.clone(),
                Entry {
                    path,
                    object,
                    class,
                },
            );
        }
        let manifest = Self {
            meta,
            generation,
            created_at,
            entries,
        };
        manifest.check_by_hash_aliases()?;
        Ok(manifest)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn get(&self, path: &RepoPath) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every distinct object the generation references.
    pub fn objects(&self) -> impl Iterator<Item = Sha256Digest> + '_ {
        let mut seen = std::collections::BTreeSet::new();
        self.entries
            .values()
            .map(|entry| entry.object.sha256)
            .filter(move |digest| seen.insert(*digest))
    }

    /// APT may fall back from `by-hash` to the plain path (R-004 G4), so
    /// every plain index must be reachable under its digest as well.
    fn check_by_hash_aliases(&self) -> Result<(), ManifestError> {
        if self.meta.backend != Backend::Apt {
            return Ok(());
        }
        for entry in self.entries.values() {
            let name = entry.path.file_name();
            if !APT_PLAIN_INDEXES.contains(&name) {
                continue;
            }
            let alias = format!(
                "{}/by-hash/SHA256/{}",
                entry.path.parent(),
                entry.object.sha256.to_hex()
            );
            let present = RepoPath::new(&alias)
                .ok()
                .and_then(|alias| self.entries.get(&alias))
                .is_some_and(|aliased| aliased.object == entry.object);
            if !present {
                return Err(ManifestError::MissingByHashAlias(
                    entry.path.as_str().to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// The canonical text form.
    pub fn to_text(&self) -> String {
        let mut text = String::new();
        let meta = &self.meta;
        text.push_str(MAGIC);
        text.push('\n');
        text.push_str(&format!("repo {}\n", meta.repo));
        text.push_str(&format!("source {}\n", meta.source.as_str()));
        text.push_str(&format!("backend {}\n", meta.backend.as_str()));
        text.push_str(&format!("generation {}\n", self.generation));
        text.push_str(&format!("created {}\n", self.created_at));
        text.push_str(&format!("valid-from {}\n", meta.valid_from.as_str()));
        text.push_str(&format!("valid-until {}\n", meta.valid_until.as_str()));
        text.push_str(&format!("entries {}\n", self.entries.len()));
        for entry in self.entries.values() {
            let class = match entry.class {
                PathClass::Mutable => 'm',
                PathClass::ContentAddressed => 'c',
            };
            text.push_str(&format!(
                "{}\t{}\t{class}\t{}\n",
                entry.object.sha256.to_hex(),
                entry.object.size,
                entry.path
            ));
        }
        text
    }

    /// Parses the text form strictly: fixed header order, an exact entry
    /// count, paths in ascending order, and the classes the backend
    /// assigns. The result re-serialises to the same text.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let mut lines = text.split_terminator('\n');
        if lines.next() != Some(MAGIC) {
            return Err(ManifestError::Malformed("format line"));
        }
        let mut header = |key: &'static str| -> Result<&str, ManifestError> {
            let line = lines
                .next()
                .ok_or(ManifestError::Malformed("truncated header"))?;
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(' '))
                .ok_or(ManifestError::Malformed(key))
        };
        let repo = RepoName::new(header("repo")?)?;
        let source = SourceId::new(header("source")?)?;
        let backend =
            Backend::parse(header("backend")?).ok_or(ManifestError::Malformed("backend"))?;
        let generation = header("generation")?
            .parse::<u64>()
            .ok()
            .and_then(GenerationId::new)
            .ok_or(ManifestError::Malformed("generation"))?;
        let created_at = header("created")?
            .parse::<u64>()
            .map_err(|_| ManifestError::Malformed("created"))?;
        let valid_from = Timestamp::new(header("valid-from")?)?;
        let valid_until = Timestamp::new(header("valid-until")?)?;
        let count = header("entries")?
            .parse::<usize>()
            .map_err(|_| ManifestError::Malformed("entries"))?;
        if count > MAX_ENTRIES {
            return Err(ManifestError::TooManyEntries);
        }
        let mut objects = Vec::with_capacity(count);
        let mut classes = Vec::with_capacity(count);
        let mut previous: Option<RepoPath> = None;
        for line in lines {
            let mut fields = line.split('\t');
            let (Some(digest), Some(size), Some(class), Some(path), None) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) else {
                return Err(ManifestError::Malformed("entry fields"));
            };
            let digest =
                Sha256Digest::from_hex(digest).map_err(|_| ManifestError::Malformed("digest"))?;
            if size.starts_with('+') || (size.len() > 1 && size.starts_with('0')) {
                return Err(ManifestError::Malformed("size"));
            }
            let size = size
                .parse::<u64>()
                .map_err(|_| ManifestError::Malformed("size"))?;
            let class = match class {
                "m" => PathClass::Mutable,
                "c" => PathClass::ContentAddressed,
                _ => return Err(ManifestError::Malformed("class")),
            };
            let path = RepoPath::new(path)?;
            if previous.as_ref().is_some_and(|previous| *previous >= path) {
                return Err(ManifestError::Malformed("paths out of order"));
            }
            previous = Some(path.clone());
            classes.push(class);
            objects.push((path, ExpectedObject::new(digest, size)));
        }
        if objects.len() != count {
            return Err(ManifestError::Malformed("entry count"));
        }
        let meta = GenerationMeta {
            repo,
            source,
            backend,
            valid_from,
            valid_until,
        };
        let manifest = Self::new(meta, generation, created_at, objects)?;
        let recorded_match = manifest
            .entries
            .values()
            .zip(&classes)
            .all(|(entry, class)| entry.class == *class);
        if !recorded_match {
            return Err(ManifestError::Malformed("recorded class"));
        }
        Ok(manifest)
    }

    /// SHA-256 of the canonical text, recorded as `snapshot.manifest_sha256`.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::of(self.to_text().as_bytes())
    }
}

/// A content-addressed path keeps its bytes across every retained
/// generation of the repository; a change means a broken index generator
/// or a substituted file, never a new version.
pub fn check_immutable_paths(new: &Manifest, retained: &[Manifest]) -> Result<(), ManifestError> {
    for old in retained {
        for entry in old.entries.values() {
            if entry.class != PathClass::ContentAddressed {
                continue;
            }
            if let Some(current) = new.entries.get(&entry.path)
                && current.object != entry.object
            {
                return Err(ManifestError::ImmutablePathChanged(
                    entry.path.as_str().to_owned(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
