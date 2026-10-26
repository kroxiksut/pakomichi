// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsers for what the collector reads from the system. Portable and
//! side-effect free, so every format is tested on every target with
//! fixtures taken from the P2-014 lab runs.

use std::collections::BTreeMap;

use crate::family::relation::{Clause, DebField, parse_deb_field};
use crate::family::version::Op;
use crate::namespace::{PackageRole, deb_relation_name, rpm_relation_name};

/// The package family of a target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Apt,
    Dnf,
}

/// What identifies the distribution's own sources on one first target
/// (`specifications/system-namespace.md`, table).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub os_id: &'static str,
    /// `VERSION_ID` must start with this.
    pub version_prefix: &'static str,
    pub family: Family,
    /// APT: the archive keyring package; DNF: the key package.
    pub key_package: &'static str,
    /// DNF only: the package that owns the `.repo` files.
    pub repos_package: Option<&'static str>,
}

pub const PROFILES: [Profile; 6] = [
    Profile {
        os_id: "debian",
        version_prefix: "12",
        family: Family::Apt,
        key_package: "debian-archive-keyring",
        repos_package: None,
    },
    Profile {
        os_id: "debian",
        version_prefix: "13",
        family: Family::Apt,
        key_package: "debian-archive-keyring",
        repos_package: None,
    },
    Profile {
        os_id: "ubuntu",
        version_prefix: "24.04",
        family: Family::Apt,
        key_package: "ubuntu-keyring",
        repos_package: None,
    },
    Profile {
        os_id: "astra",
        version_prefix: "1.8",
        family: Family::Apt,
        key_package: "astra-archive-keyring",
        repos_package: None,
    },
    Profile {
        os_id: "almalinux",
        version_prefix: "9.",
        family: Family::Dnf,
        key_package: "almalinux-gpg-keys",
        repos_package: Some("almalinux-repos"),
    },
    Profile {
        os_id: "fedora",
        version_prefix: "44",
        family: Family::Dnf,
        key_package: "fedora-gpg-keys",
        repos_package: Some("fedora-repos"),
    },
];

/// One `KEY=value` of `/etc/os-release`, unquoted.
pub fn os_release_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let value = line.strip_prefix(key)?.strip_prefix('=')?;
        Some(value.trim().trim_matches('"'))
    })
}

/// The profile of the running system, if it is a first target.
pub fn profile_for(os_release: &str) -> Option<&'static Profile> {
    let id = os_release_value(os_release, "ID")?;
    let version = os_release_value(os_release, "VERSION_ID")?;
    PROFILES
        .iter()
        .find(|profile| profile.os_id == id && version.starts_with(profile.version_prefix))
}

/// `$releasever` as the first targets use it: `VERSION_ID` up to the first
/// dot (`9.8` gives `9`, `44` gives `44`).
pub fn release_version(os_release: &str) -> Option<&str> {
    let version = os_release_value(os_release, "VERSION_ID")?;
    version.split('.').next().filter(|major| !major.is_empty())
}

/// deb822 paragraphs as `(lowercase field, value)` lists; continuation
/// lines are joined with a newline. Used for APT indexes, the dpkg status
/// file, `.sources` files, and `apt-get indextargets` output.
pub fn deb822(text: &str) -> Vec<Vec<(String, String)>> {
    let mut paragraphs = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                paragraphs.push(std::mem::take(&mut current));
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = current.last_mut() {
                value.push('\n');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((field, value)) = line.split_once(':') {
            current.push((field.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    if !current.is_empty() {
        paragraphs.push(current);
    }
    paragraphs
}

/// The first value of `field` (lowercase) in a paragraph.
pub fn field<'a>(paragraph: &'a [(String, String)], name: &str) -> Option<&'a str> {
    paragraph
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.as_str())
}

/// One index target of `apt-get indextargets` that lists packages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexTarget {
    pub filename: String,
    /// `path:n`: the sources file and the line (one-line format) or the
    /// paragraph (deb822) that defines the source.
    pub sources_entry: String,
    pub base_uri: String,
    pub trusted: bool,
}

pub fn index_targets(output: &str) -> Vec<IndexTarget> {
    deb822(output)
        .iter()
        .filter(|paragraph| field(paragraph, "created-by") == Some("Packages"))
        .filter_map(|paragraph| {
            Some(IndexTarget {
                filename: field(paragraph, "filename")?.to_owned(),
                sources_entry: field(paragraph, "sourcesentry")?.to_owned(),
                base_uri: field(paragraph, "base-uri")?.to_owned(),
                trusted: field(paragraph, "trusted") == Some("yes"),
            })
        })
        .collect()
}

/// How a source names its key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedBy {
    /// No `Signed-By`: APT uses the keyrings in `trusted.gpg.d`.
    Default,
    /// Keyring files (deb822 may list several, separated by spaces).
    Files(Vec<String>),
    /// An inline key block or fingerprints: never a distribution file.
    Other,
}

fn signed_by_value(value: &str) -> SignedBy {
    if value.contains("BEGIN PGP") || value.contains('\n') {
        return SignedBy::Other;
    }
    let files: Vec<String> = value
        .split([' ', ','])
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect();
    if !files.is_empty() && files.iter().all(|file| file.starts_with('/')) {
        SignedBy::Files(files)
    } else {
        SignedBy::Other
    }
}

/// `Signed-By` of the source at `entry` (`path:n`) in `text`, the contents
/// of that sources file. `None` when the entry does not exist.
pub fn signed_by(path: &str, text: &str, number: usize) -> Option<SignedBy> {
    if path.ends_with(".sources") {
        let paragraph = deb822(text).into_iter().nth(number.checked_sub(1)?)?;
        return Some(field(&paragraph, "signed-by").map_or(SignedBy::Default, signed_by_value));
    }
    let line = text.lines().nth(number.checked_sub(1)?)?.trim();
    let rest = line.strip_prefix("deb ")?.trim_start();
    let Some(options) = rest
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
        .map(|(options, _)| options)
    else {
        return Some(SignedBy::Default);
    };
    let value = options
        .split_whitespace()
        .find_map(|option| option.strip_prefix("signed-by="));
    Some(value.map_or(SignedBy::Default, signed_by_value))
}

/// Splits `path:n` of `Sourcesentry`.
pub fn split_sources_entry(entry: &str) -> Option<(&str, usize)> {
    let (path, number) = entry.rsplit_once(':')?;
    Some((path, number.parse().ok()?))
}

/// APT's `URItoFileName`: the URI without scheme and credentials, with
/// `_` and other reserved characters percent-encoded (lowercase hex) and
/// `/` replaced by `_`. `<lists>/<this>InRelease` is the signed release file.
pub fn uri_to_filename(uri: &str) -> String {
    let without_scheme = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    let without_credentials = match without_scheme.split_once('/') {
        Some((host, path)) => {
            let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
            format!("{host}/{path}")
        }
        None => without_scheme
            .rsplit_once('@')
            .map_or(without_scheme, |(_, host)| host)
            .to_owned(),
    };
    let mut out = String::with_capacity(without_credentials.len());
    for byte in without_credentials.bytes() {
        let reserved = b"\\|{}[]<>\"^~_=!@#$%^&*";
        if byte == b'/' {
            out.push('_');
        } else if reserved.contains(&byte) || byte <= 0x20 || byte >= 0x7f {
            out.push_str(&format!("%{byte:02x}"));
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

/// The owners in `dpkg-query -S <path>` output (`pkg1, pkg2: /path`).
pub fn dpkg_owners(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.rsplit_once(": "))
        .filter(|(_, path)| path.starts_with('/'))
        .map(|(owners, _)| owners)
        .flat_map(|owners| owners.split(", "))
        .map(|owner| owner.split(':').next().unwrap_or(owner).trim().to_owned())
        .filter(|owner| !owner.is_empty())
        .collect()
}

/// The role of a DEB package from its paragraph (index or status): a part
/// of the operating system when it is `Essential`, `required` or
/// `important`, or a library section; otherwise `fallback`.
pub fn deb_role(paragraph: &[(String, String)], fallback: PackageRole) -> PackageRole {
    let essential = field(paragraph, "essential") == Some("yes");
    let priority = matches!(field(paragraph, "priority"), Some("required" | "important"));
    let library = field(paragraph, "section").is_some_and(|section| {
        let section = section.rsplit('/').next().unwrap_or(section);
        section == "libs" || section == "oldlibs"
    });
    if essential || priority || library {
        PackageRole::OsPart
    } else {
        fallback
    }
}

/// The capability names of a DEB `Provides` field.
pub fn deb_provides(paragraph: &[(String, String)]) -> Vec<String> {
    field(paragraph, "provides")
        .unwrap_or_default()
        .split([',', '|'])
        .filter_map(deb_relation_name)
        .map(str::to_owned)
        .collect()
}

/// Whether a dpkg status paragraph is an installed package.
pub fn deb_installed(paragraph: &[(String, String)]) -> bool {
    field(paragraph, "status").is_some_and(|status| status.ends_with(" installed"))
}

/// One section of a `.repo` file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepoSection {
    pub id: String,
    pub enabled: bool,
    pub gpgcheck: bool,
    pub gpgkeys: Vec<String>,
}

/// Parses a `.repo` file: `[id]` sections, `key=value` lines, and values
/// continued on indented lines (as `gpgkey` lists often are). `enabled`
/// and `gpgcheck` default to on, as in DNF.
pub fn repo_sections(text: &str) -> Vec<RepoSection> {
    let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    let mut last_key: Option<String> = None;
    for raw in text.lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with(['#', ';']) {
            continue;
        }
        if raw.starts_with([' ', '\t']) {
            if let (Some((_, values)), Some(key)) = (sections.last_mut(), &last_key)
                && let Some(value) = values.get_mut(key)
            {
                value.push(' ');
                value.push_str(raw.trim());
            }
            continue;
        }
        let line = raw.trim();
        if let Some(id) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            sections.push((id.trim().to_owned(), BTreeMap::new()));
            last_key = None;
        } else if let Some((key, value)) = line.split_once('=')
            && let Some((_, values)) = sections.last_mut()
        {
            let key = key.trim().to_ascii_lowercase();
            values.insert(key.clone(), value.trim().to_owned());
            last_key = Some(key);
        }
    }
    let flag = |values: &BTreeMap<String, String>, key: &str| {
        values.get(key).is_none_or(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "yes" | "true" | "on"
            )
        })
    };
    sections
        .into_iter()
        .map(|(id, values)| RepoSection {
            enabled: flag(&values, "enabled"),
            gpgcheck: flag(&values, "gpgcheck"),
            gpgkeys: values
                .get("gpgkey")
                .map(|keys| {
                    keys.split([' ', ','])
                        .filter(|key| !key.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            id,
        })
        .collect()
}

/// A `gpgkey` URL as a local path with `$releasever`, `$releasever_major`,
/// and `$basearch` expanded; `None` for a non-`file://` key.
pub fn gpgkey_path(url: &str, releasever: &str, basearch: &str) -> Option<String> {
    let path = url.strip_prefix("file://")?;
    Some(
        path.replace("$releasever_major", releasever)
            .replace("$releasever", releasever)
            .replace("$basearch", basearch),
    )
}

/// `name -> provides` from output made with `--qf '@@PKG %{name}\n…'`:
/// `dnf repoquery --qf '@@PKG %{name}\n%{provides}\n'` or
/// `rpm -qa --qf '@@PKG %{NAME}\n[%{PROVIDES}\n]'`. Provides are reduced
/// to their names; blank lines are ignored.
pub fn marked_packages(output: &str) -> BTreeMap<String, Vec<String>> {
    let mut packages: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        if let Some(header) = line.strip_prefix("@@PKG ") {
            // The header may also carry the version (`@@PKG name evr`).
            let Some(name) = header.split_whitespace().next() else {
                current = None;
                continue;
            };
            let name = name.to_owned();
            packages.entry(name.clone()).or_default();
            current = Some(name);
        } else if let (Some(name), Some(provide)) = (&current, rpm_relation_name(line)) {
            packages
                .entry(name.clone())
                .or_default()
                .push(provide.to_owned());
        }
    }
    packages
}

/// Mandatory and default packages of `dnf group info core`, in the DNF4
/// layout (`Mandatory Packages:` then indented names) and the DNF5 layout
/// (`Mandatory packages   : name` then `   : name`).
pub fn core_group(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_list = false;
    for line in output.lines() {
        let lower = line.trim_start().to_ascii_lowercase();
        let heading = [
            "mandatory packages",
            "default packages",
            "optional packages",
            "conditional packages",
        ]
        .iter()
        .find(|heading| lower.starts_with(*heading));
        if let Some(heading) = heading {
            in_list = !heading.starts_with("optional") && !heading.starts_with("conditional");
            // DNF5 puts the first name on the heading line after `:`.
            if in_list
                && let Some((_, name)) = line.split_once(':')
                && !name.trim().is_empty()
            {
                names.push(name.trim().to_owned());
            }
            continue;
        }
        if !in_list {
            continue;
        }
        let item = line.trim();
        let item = item.strip_prefix(':').map_or(item, str::trim);
        if line.starts_with([' ', '\t']) && !item.is_empty() && !item.contains(':') {
            names.push(item.to_owned());
        } else {
            in_list = false;
        }
    }
    names
}

/// Package names of `/etc/dnf/protected.d/*.conf`: one per line, `#`
/// comments.
pub fn protected_names(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A shared-library capability: `libc.so.6()(64bit)`,
/// `libm.so.6(GLIBC_2.2.5)(64bit)`, or `libc.so.6` on 32-bit. File
/// provides (`/lib/libc.so.6`) are paths, not sonames.
pub fn is_soname(capability: &str) -> bool {
    if capability.starts_with('/') {
        return false;
    }
    let Some(position) = capability.find(".so") else {
        return false;
    };
    let after = &capability[position + 3..];
    after.is_empty() || after.starts_with(['.', '('])
}

/// One package as the compatibility check needs it (P2-008b): its name,
/// its native version, and what it provides with each constraint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedPackage {
    pub name: String,
    pub version: String,
    pub provides: Vec<(String, Option<(Op, String)>)>,
}

/// A DEB `Packages` or dpkg `status` paragraph with its version. A
/// malformed `Provides` keeps the package and drops its provides: the index
/// belongs to the system, and a missing offer can only hold, never admit.
pub fn deb_versioned(paragraph: &[(String, String)]) -> Option<VersionedPackage> {
    let name = field(paragraph, "package")?;
    let version = field(paragraph, "version")?;
    let provides = parse_deb_field(DebField::Provides, field(paragraph, "provides"))
        .unwrap_or_default()
        .into_iter()
        .flat_map(|clause| match clause {
            Clause::Any(atoms) => atoms,
            Clause::Rich(_) => Vec::new(),
        })
        .map(|atom| (atom.name, atom.constraint))
        .collect();
    Some(VersionedPackage {
        name: name.to_owned(),
        version: version.to_owned(),
        provides,
    })
}

/// One RPM capability as `rpm` and `dnf` print it: `name`, or
/// `name OP evr` with `OP` one of `<`, `<=`, `=`, `>=`, `>`.
pub fn rpm_capability(line: &str) -> Option<(String, Option<(Op, String)>)> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_owned();
    let constraint = match (parts.next(), parts.next()) {
        (None, _) => None,
        (Some(op), Some(version)) => Some((
            match op {
                "<" => Op::Less,
                "<=" => Op::LessEqual,
                "=" => Op::Equal,
                ">=" => Op::GreaterEqual,
                ">" => Op::Greater,
                _ => return None,
            },
            version.to_owned(),
        )),
        (Some(_), None) => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((name, constraint))
}

/// Packages from output made with `--qf '@@PKG %{name} %{evr}\n…'` and one
/// capability per line (`dnf repoquery … %{provides}` or
/// `rpm -qa … [%{PROVIDENEVRS}\n]`). A line that is not a capability is
/// skipped.
pub fn versioned_packages(output: &str) -> Vec<VersionedPackage> {
    let mut packages: Vec<VersionedPackage> = Vec::new();
    for line in output.lines() {
        if let Some(header) = line.strip_prefix("@@PKG ") {
            let mut words = header.split_whitespace();
            if let (Some(name), Some(version)) = (words.next(), words.next()) {
                packages.push(VersionedPackage {
                    name: name.to_owned(),
                    version: version.to_owned(),
                    provides: Vec::new(),
                });
            }
        } else if let (Some(package), Some(capability)) =
            (packages.last_mut(), rpm_capability(line))
        {
            package.provides.push(capability);
        }
    }
    packages
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
