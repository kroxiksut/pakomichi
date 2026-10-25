// SPDX-License-Identifier: MIT OR Apache-2.0

//! The APT configuration files Pakomichi owns (ADR-022 point 3,
//! `specifications/apt.md`).
//!
//! For each source: one deb822 `.sources` file with a stanza per logical
//! repository, `Signed-By` the local metadata keyring, and one preferences
//! file with a `Pin: release o=Pakomichi,l=<label>` stanza at
//! `Pin-Priority: 990` per logical repository that has activated names. The
//! repositories themselves are low priority (`NotAutomatic` with
//! `ButAutomaticUpgrades` in their `Release`), so a source without pins
//! never displaces another source's version. Never `Pin: origin` (one
//! loopback host serves every repository) and never a priority of 1000 or
//! more (that allows downgrades).
//!
//! Every value written comes from validated names: a package name or label
//! that could add a line would add a field, so it is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::policy::level::APT_ORIGIN;

/// The local metadata keyring every Pakomichi source is signed by.
pub const KEYRING_PATH: &str = "/etc/apt/keyrings/pakomichi.gpg";
pub const SOURCES_DIR: &str = "/etc/apt/sources.list.d";
pub const PREFERENCES_DIR: &str = "/etc/apt/preferences.d";
/// The priority of an activated name: above every distribution default
/// (500) and below 1000, which would allow downgrades.
pub const PIN_PRIORITY: u16 = 990;
const HEADER: &str = "Managed by Pakomichi; changes are overwritten or reported as drift.";

/// Why a configuration cannot be written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidSourceKey(String),
    InvalidLabel(String),
    InvalidPackageName(String),
    /// Only a loopback port serves Pakomichi repositories.
    InvalidPort,
    /// One label in two places, or one source twice.
    Duplicate(String),
    /// A name activated in two logical repositories: two 990 pins would let
    /// the higher version decide, so another level or source could take
    /// the name over.
    ActivatedTwice {
        name: String,
        first: String,
        second: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceKey(key) => write!(formatter, "{key:?} is not a source key"),
            Self::InvalidLabel(label) => write!(formatter, "{label:?} is not a repository label"),
            Self::InvalidPackageName(name) => write!(formatter, "{name:?} is not a package name"),
            Self::InvalidPort => formatter.write_str("the repository port must be 1-65535"),
            Self::Duplicate(what) => write!(formatter, "{what} appears twice"),
            Self::ActivatedTwice {
                name,
                first,
                second,
            } => write!(
                formatter,
                "{name} is activated in both {first} and {second}"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

fn is_key(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

/// Debian Policy 5.6.1: lowercase letters, digits, `+`, `-`, `.`; at least
/// two characters, starting with a letter or digit.
fn is_package_name(name: &str) -> bool {
    name.len() >= 2
        && name.len() <= 128
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
        })
}

/// One logical repository of a source and the names activated from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalSource {
    /// `pakomichi-<source>-<level>`: the repository path, `Suite`, and
    /// `Label`.
    pub label: String,
    /// Every activated name, including every member of each activated
    /// family (ADR-022 point 3).
    pub activated: BTreeSet<String>,
}

/// The APT configuration of one source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConfig {
    pub source_key: String,
    pub repositories: Vec<LogicalSource>,
}

/// What a managed file is, which also fixes the order of changes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FileKind {
    Keyring,
    Preferences,
    Sources,
}

/// A file Pakomichi writes, with its absolute path and exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFile {
    pub kind: FileKind,
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Whether `path` is one Pakomichi may write or remove: the keyring, or
/// the sources or preferences file of a valid source key. The applier runs
/// as root and refuses any other path, wherever it comes from.
pub fn is_managed_path(path: &str) -> bool {
    if path == KEYRING_PATH {
        return true;
    }
    let key = |directory: &str, suffix: &str| {
        path.strip_prefix(directory)
            .and_then(|rest| rest.strip_prefix("/pakomichi-"))
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(|key| is_key(key, 64))
    };
    key(SOURCES_DIR, ".sources") || key(PREFERENCES_DIR, ".pref")
}

/// The configuration Pakomichi wants APT to have: every source, the
/// loopback port, and the local keyring. The root applier renders the
/// files from it itself.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Desired {
    pub port: u16,
    pub keyring: Vec<u8>,
    pub sources: Vec<SourceConfig>,
}

impl Desired {
    /// No source: it renders no file, so applying it removes all of
    /// Pakomichi's files.
    pub fn empty(port: u16) -> Self {
        Self {
            port,
            keyring: Vec::new(),
            sources: Vec::new(),
        }
    }

    pub fn render(&self) -> Result<Vec<ManagedFile>, ConfigError> {
        render(&self.sources, self.port, &self.keyring)
    }

    /// Every activated name.
    pub fn activated(&self) -> Vec<String> {
        let names: BTreeSet<&String> = self
            .sources
            .iter()
            .flat_map(|source| &source.repositories)
            .flat_map(|repository| &repository.activated)
            .collect();
        names.into_iter().cloned().collect()
    }
}

pub fn sources_path(source_key: &str) -> String {
    format!("{SOURCES_DIR}/pakomichi-{source_key}.sources")
}

pub fn preferences_path(source_key: &str) -> String {
    format!("{PREFERENCES_DIR}/pakomichi-{source_key}.pref")
}

/// Renders every managed file for `sources`, served on `127.0.0.1:port`,
/// with the local keyring `keyring`. A source without activated names gets
/// no preferences file.
pub fn render(
    sources: &[SourceConfig],
    port: u16,
    keyring: &[u8],
) -> Result<Vec<ManagedFile>, ConfigError> {
    if port == 0 {
        return Err(ConfigError::InvalidPort);
    }
    let mut keys = BTreeSet::new();
    let mut labels = BTreeSet::new();
    let mut activated_in: BTreeMap<&str, &str> = BTreeMap::new();
    for source in sources {
        if !is_key(&source.source_key, 64) {
            return Err(ConfigError::InvalidSourceKey(source.source_key.clone()));
        }
        if !keys.insert(source.source_key.as_str()) {
            return Err(ConfigError::Duplicate(source.source_key.clone()));
        }
        for repository in &source.repositories {
            if !is_key(&repository.label, 64) {
                return Err(ConfigError::InvalidLabel(repository.label.clone()));
            }
            if !labels.insert(repository.label.as_str()) {
                return Err(ConfigError::Duplicate(repository.label.clone()));
            }
            for name in &repository.activated {
                if !is_package_name(name) {
                    return Err(ConfigError::InvalidPackageName(name.clone()));
                }
                if let Some(first) = activated_in.insert(name, &repository.label) {
                    return Err(ConfigError::ActivatedTwice {
                        name: name.clone(),
                        first: first.to_owned(),
                        second: repository.label.clone(),
                    });
                }
            }
        }
    }

    // The keyring is managed while any source uses it.
    let mut files = Vec::new();
    if sources.iter().any(|source| !source.repositories.is_empty()) {
        files.push(ManagedFile {
            kind: FileKind::Keyring,
            path: KEYRING_PATH.to_owned(),
            bytes: keyring.to_vec(),
        });
    }
    for source in sources {
        let stanzas: Vec<String> = source
            .repositories
            .iter()
            .map(|repository| {
                format!(
                    "Types: deb\nURIs: http://127.0.0.1:{port}/{label}\nSuites: {label}\n\
                     Components: main\nSigned-By: {KEYRING_PATH}\n",
                    label = repository.label
                )
            })
            .collect();
        if !stanzas.is_empty() {
            files.push(ManagedFile {
                kind: FileKind::Sources,
                path: sources_path(&source.source_key),
                bytes: format!("# {HEADER}\n{}", stanzas.join("\n")).into_bytes(),
            });
        }
        let pins: Vec<String> = source
            .repositories
            .iter()
            .filter(|repository| !repository.activated.is_empty())
            .map(|repository| {
                let names: Vec<&str> = repository.activated.iter().map(String::as_str).collect();
                format!(
                    "Explanation: {HEADER}\nPackage: {}\nPin: release o={APT_ORIGIN},l={}\n\
                     Pin-Priority: {PIN_PRIORITY}\n",
                    names.join(" "),
                    repository.label
                )
            })
            .collect();
        if !pins.is_empty() {
            files.push(ManagedFile {
                kind: FileKind::Preferences,
                path: preferences_path(&source.source_key),
                bytes: pins.join("\n").into_bytes(),
            });
        }
    }
    Ok(files)
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
