// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading the namespace from a running Linux system (P2-014).
//!
//! Everything runs unprivileged and reads only what the native managers
//! already have: `apt-get indextargets`, `apt-helper cat-file`, the dpkg
//! status file, `dpkg-query -S`, `gpgv`; `/etc/yum.repos.d`, `rpm -qf`,
//! `rpm -qa`, and `dnf -C` (cache only, never a download). Missing native
//! metadata makes the namespace unknown.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::parse::{
    Family, Profile, SignedBy, VersionedPackage, core_group, deb_installed, deb_provides, deb_role,
    deb_versioned, deb822, dpkg_owners, field, gpgkey_path, index_targets, is_soname,
    marked_packages, profile_for, protected_names, release_version, repo_sections, signed_by,
    split_sources_entry, uri_to_filename, versioned_packages,
};
use super::{CollectError, Collected};
use crate::compat::{Origin, SystemPackages};
use crate::inventory::Ecosystem;
use crate::namespace::{PackageRole, SystemNamespace};

fn add_versioned(packages: &mut SystemPackages, origin: Origin, package: VersionedPackage) {
    packages.add_package(origin, &package.name, &package.version);
    for (name, constraint) in package.provides {
        packages.add_provide(origin, &name, constraint);
    }
}

const TOOL_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const TOOL_TIMEOUT: Duration = Duration::from_secs(300);
/// Largest output read from one tool (a full DNF repoquery with provides
/// is about 100 MiB on Fedora 44).
const MAX_TOOL_OUTPUT: usize = 512 * 1024 * 1024;
const LISTS: &str = "/var/lib/apt/lists";

/// Where the collector may keep the per-user DNF5 cache copy.
#[derive(Clone, Debug)]
pub struct CollectorConfig {
    /// A private, writable directory used as `HOME` for `dnf`.
    pub dnf_home: PathBuf,
    /// Installed package names that came from Pakomichi's repositories;
    /// they are not members (the state owner knows them).
    pub installed_from_pakomichi: BTreeSet<String>,
    /// Pakomichi's own sources (APT base URIs, DNF repository IDs); they
    /// are neither distribution nor other sources for the compatibility
    /// check.
    pub pakomichi_sources: BTreeSet<String>,
}

/// Reads the namespace of the running system.
pub fn collect(config: &CollectorConfig) -> Result<Collected, CollectError> {
    let os_release =
        fs::read_to_string("/etc/os-release").map_err(|_| CollectError::Unsupported)?;
    let profile = profile_for(&os_release).ok_or(CollectError::Unsupported)?;
    match profile.family {
        Family::Apt => collect_apt(profile, config),
        Family::Dnf => {
            let releasever = release_version(&os_release).ok_or(CollectError::Unsupported)?;
            collect_dnf(profile, releasever, config)
        }
    }
}

fn collect_apt(profile: &Profile, config: &CollectorConfig) -> Result<Collected, CollectError> {
    let keyrings = owned_keyrings(profile.key_package)?;
    // Without its Release file (before the first `apt update`) a target is
    // missing from plain `indextargets`; `--no-release-info` still lists it.
    // A distribution source without metadata is unknown, not absent.
    for target in index_targets(&run(
        "apt-get",
        &["indextargets", "--no-release-info"],
        None,
    )?) {
        let release = format!("{LISTS}/{}", uri_to_filename(&target.base_uri));
        let has_release = ["InRelease", "Release"]
            .iter()
            .any(|name| Path::new(&format!("{release}{name}")).is_file());
        if !has_release && is_distribution_apt_source(&target, profile, &keyrings)? {
            return Err(CollectError::Unknown {
                source: target.base_uri,
            });
        }
    }
    let targets = index_targets(&run("apt-get", &["indextargets"], None)?);
    let mut namespace = SystemNamespace::new();
    let mut packages = SystemPackages::new(Ecosystem::Deb);
    let mut sources = Vec::new();
    let mut other_sources = Vec::new();
    let mut other_unknown = Vec::new();
    for target in targets {
        if !target.trusted || is_own_source(config, &target.base_uri) {
            continue;
        }
        if !is_distribution_apt_source(&target, profile, &keyrings)? {
            // Another trusted source (a vendor repository, a PPA): it may
            // satisfy an ordinary dependency, never a system name.
            match read_apt_index(&target.filename) {
                Some(index) => {
                    for package in deb822(&index)
                        .iter()
                        .filter_map(|paragraph| deb_versioned(paragraph))
                    {
                        add_versioned(&mut packages, Origin::OtherSource, package);
                    }
                    other_sources.push(target.base_uri);
                }
                None => other_unknown.push(target.base_uri),
            }
            continue;
        }
        if !Path::new(&target.filename).is_file() {
            return Err(CollectError::Unknown {
                source: target.base_uri.clone(),
            });
        }
        let index = read_apt_index(&target.filename).ok_or_else(|| CollectError::Unknown {
            source: target.base_uri.clone(),
        })?;
        for paragraph in deb822(&index) {
            let Some(name) = field(&paragraph, "package") else {
                continue;
            };
            namespace.insert_package(
                name,
                deb_role(&paragraph, PackageRole::DistributionApplication),
            );
            for capability in deb_provides(&paragraph) {
                namespace.insert_capability(&capability);
            }
            if let Some(package) = deb_versioned(&paragraph) {
                add_versioned(&mut packages, Origin::Distribution, package);
            }
        }
        sources.push(target.base_uri);
    }
    if sources.is_empty() {
        return Err(CollectError::NoDistributionSource);
    }
    let status = fs::read_to_string("/var/lib/dpkg/status").map_err(CollectError::Io)?;
    for paragraph in deb822(&status)
        .into_iter()
        .filter(|paragraph| deb_installed(paragraph))
    {
        let Some(name) = field(&paragraph, "package") else {
            continue;
        };
        if config.installed_from_pakomichi.contains(name) {
            continue;
        }
        let mut role = deb_role(&paragraph, PackageRole::InstalledElsewhere);
        if ships_shared_library(name, field(&paragraph, "architecture")) {
            role = PackageRole::OsPart;
        }
        namespace.insert_package(name, role);
        for capability in deb_provides(&paragraph) {
            namespace.insert_capability(&capability);
        }
        if let Some(package) = deb_versioned(&paragraph) {
            add_versioned(&mut packages, Origin::Installed, package);
        }
    }
    for list in [&mut sources, &mut other_sources, &mut other_unknown] {
        list.sort();
        list.dedup();
    }
    Ok(Collected {
        namespace,
        sources,
        packages,
        other_sources,
        other_unknown,
    })
}

/// A decompressed APT index, or `None` when it is missing or unreadable.
fn read_apt_index(filename: &str) -> Option<String> {
    if !Path::new(filename).is_file() {
        return None;
    }
    run("/usr/lib/apt/apt-helper", &["cat-file", filename], None).ok()
}

/// One of Pakomichi's own sources, named by APT base URI or DNF repository
/// ID in the configuration.
fn is_own_source(config: &CollectorConfig, source: &str) -> bool {
    config.pakomichi_sources.contains(source)
}

/// Keyring files owned by the distribution's keyring package.
fn owned_keyrings(package: &str) -> Result<Vec<String>, CollectError> {
    let listing = run("dpkg-query", &["-L", package], None)
        .map_err(|_| CollectError::NoDistributionSource)?;
    Ok(listing
        .lines()
        .filter(|path| {
            (path.starts_with("/etc/apt/trusted.gpg.d/") || path.starts_with("/usr/share/keyrings/"))
                && Path::new(path).extension().is_some_and(|extension| extension == "gpg")
                // Revoked keys ship in the same package and never vouch.
                && !path.contains("removed")
        })
        .map(str::to_owned)
        .collect())
}

fn is_distribution_apt_source(
    target: &super::parse::IndexTarget,
    profile: &Profile,
    keyrings: &[String],
) -> Result<bool, CollectError> {
    let Some((path, number)) = split_sources_entry(&target.sources_entry) else {
        return Ok(false);
    };
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(false);
    };
    match signed_by(path, &text, number) {
        Some(SignedBy::Files(files)) => Ok(files.iter().all(|file| {
            run("dpkg-query", &["-S", file], None).is_ok_and(|output| {
                dpkg_owners(&output)
                    .iter()
                    .any(|owner| owner == profile.key_package)
            })
        })),
        Some(SignedBy::Default) => {
            let release = format!("{LISTS}/{}InRelease", uri_to_filename(&target.base_uri));
            if !Path::new(&release).is_file() {
                return Err(CollectError::Unknown {
                    source: target.base_uri.clone(),
                });
            }
            Ok(keyrings
                .iter()
                .any(|keyring| run("gpgv", &["--keyring", keyring, &release], None).is_ok()))
        }
        Some(SignedBy::Other) | None => Ok(false),
    }
}

/// An installed package with a `shlibs` or `symbols` control file.
fn ships_shared_library(name: &str, architecture: Option<&str>) -> bool {
    let info = Path::new("/var/lib/dpkg/info");
    let mut stems = vec![name.to_owned()];
    if let Some(architecture) = architecture {
        stems.push(format!("{name}:{architecture}"));
    }
    stems.iter().any(|stem| {
        info.join(format!("{stem}.shlibs")).is_file()
            || info.join(format!("{stem}.symbols")).is_file()
    })
}

fn collect_dnf(
    profile: &Profile,
    releasever: &str,
    config: &CollectorConfig,
) -> Result<Collected, CollectError> {
    let repos_package = profile.repos_package.ok_or(CollectError::Unsupported)?;
    let basearch = std::env::consts::ARCH;
    let mut repos = Vec::new();
    let mut other_repos = Vec::new();
    let mut files: Vec<PathBuf> = fs::read_dir("/etc/yum.repos.d")
        .map_err(CollectError::Io)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "repo")
        })
        .collect();
    files.sort();
    for file in files {
        let path = file.to_string_lossy().into_owned();
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        if rpm_owner(&path).as_deref() != Some(repos_package) {
            // Another repository file: its enabled repositories may satisfy
            // an ordinary dependency, never a system name.
            other_repos.extend(
                repo_sections(&text)
                    .into_iter()
                    .filter(|section| section.enabled && !is_own_source(config, &section.id))
                    .map(|section| section.id),
            );
            continue;
        }
        for section in repo_sections(&text) {
            let keys_owned = !section.gpgkeys.is_empty()
                && section.gpgkeys.iter().all(|url| {
                    gpgkey_path(url, releasever, basearch)
                        .is_some_and(|key| rpm_owner(&key).as_deref() == Some(profile.key_package))
                });
            if section.enabled && section.gpgcheck && keys_owned {
                repos.push(section.id);
            }
        }
    }
    if repos.is_empty() {
        return Err(CollectError::NoDistributionSource);
    }
    fs::create_dir_all(&config.dnf_home).map_err(CollectError::Io)?;
    let home = config.dnf_home.to_string_lossy().into_owned();
    let mut base: Vec<String> = vec!["-q".to_owned(), "-C".to_owned()];
    base.extend(repos.iter().map(|repo| format!("--repo={repo}")));
    let unknown = || CollectError::Unknown {
        source: repos.join(","),
    };

    let repoquery = |repo_args: Vec<String>| {
        let mut query = vec!["-q".to_owned(), "-C".to_owned()];
        query.extend(repo_args);
        query.extend([
            "repoquery".to_owned(),
            "--qf".to_owned(),
            "@@PKG %{name} %{evr}\n%{provides}\n".to_owned(),
        ]);
        run_owned("dnf", &query, Some(&home))
    };
    let available = repoquery(repos.iter().map(|repo| format!("--repo={repo}")).collect())
        .map_err(|_| unknown())?;
    let mut group = base.clone();
    group.extend(["group".to_owned(), "info".to_owned(), "core".to_owned()]);
    let core: BTreeSet<String> =
        core_group(&run_owned("dnf", &group, Some(&home)).map_err(|_| unknown())?)
            .into_iter()
            .collect();
    if core.is_empty() {
        return Err(unknown());
    }
    let protected = protected_packages();

    let mut namespace = SystemNamespace::new();
    let mut packages = SystemPackages::new(Ecosystem::Rpm);
    for package in versioned_packages(&available) {
        add_versioned(&mut packages, Origin::Distribution, package);
    }
    // Each other repository on its own, so one without metadata does not
    // hide the others.
    let mut other_sources = Vec::new();
    let mut other_unknown = Vec::new();
    other_repos.sort();
    other_repos.dedup();
    for repo in other_repos {
        match repoquery(vec![format!("--repo={repo}")]) {
            Ok(output) => {
                for package in versioned_packages(&output) {
                    add_versioned(&mut packages, Origin::OtherSource, package);
                }
                other_sources.push(repo);
            }
            Err(_) => other_unknown.push(repo),
        }
    }
    let role_of = |name: &str, provides: &[String], fallback: PackageRole| {
        if core.contains(name)
            || protected.contains(name)
            || provides.iter().any(|provide| is_soname(provide))
        {
            PackageRole::OsPart
        } else {
            fallback
        }
    };
    for (name, provides) in marked_packages(&available) {
        namespace.insert_package(
            &name,
            role_of(&name, &provides, PackageRole::DistributionApplication),
        );
        for capability in &provides {
            namespace.insert_capability(capability);
        }
    }
    let installed = run(
        "rpm",
        &["-qa", "--qf", "@@PKG %{NAME} %{EVR}\n[%{PROVIDENEVRS}\n]"],
        None,
    )?;
    for (name, provides) in marked_packages(&installed) {
        if config.installed_from_pakomichi.contains(&name) {
            continue;
        }
        namespace.insert_package(
            &name,
            role_of(&name, &provides, PackageRole::InstalledElsewhere),
        );
        for capability in &provides {
            namespace.insert_capability(capability);
        }
    }
    for package in versioned_packages(&installed)
        .into_iter()
        .filter(|package| !config.installed_from_pakomichi.contains(&package.name))
    {
        add_versioned(&mut packages, Origin::Installed, package);
    }
    Ok(Collected {
        namespace,
        sources: repos,
        packages,
        other_sources,
        other_unknown,
    })
}

fn rpm_owner(path: &str) -> Option<String> {
    let output = run("rpm", &["-qf", "--qf", "%{NAME}\n", path], None).ok()?;
    let mut owners = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let owner = owners.next()?.to_owned();
    // A path owned by several packages is not the distribution's alone.
    owners.next().is_none().then_some(owner)
}

fn protected_packages() -> BTreeSet<String> {
    let Ok(entries) = fs::read_dir("/etc/dnf/protected.d") else {
        return BTreeSet::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "conf")
        })
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .flat_map(|text| protected_names(&text))
        .collect()
}

fn run(program: &str, args: &[&str], home: Option<&str>) -> Result<String, CollectError> {
    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    run_owned(program, &owned, home)
}

/// Runs a tool without a shell, with a fixed environment, a deadline, and
/// an output cap; a non-zero exit is an error.
fn run_owned(program: &str, args: &[String], home: Option<&str>) -> Result<String, CollectError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", TOOL_PATH)
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(home) = home {
        command.env("HOME", home);
    }
    let mut child = command.spawn().map_err(|_| CollectError::ToolFailed {
        tool: program.to_owned(),
    })?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err(CollectError::ToolFailed {
            tool: program.to_owned(),
        });
    };
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = (&mut stdout)
            .take(MAX_TOOL_OUTPUT as u64 + 1)
            .read_to_end(&mut bytes);
        (read, bytes)
    });
    let deadline = Instant::now() + TOOL_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CollectError::ToolFailed {
                    tool: program.to_owned(),
                });
            }
        }
    };
    let (read, bytes) = reader.join().map_err(|_| CollectError::ToolFailed {
        tool: program.to_owned(),
    })?;
    if read.is_err() || bytes.len() > MAX_TOOL_OUTPUT || !status.success() {
        return Err(CollectError::ToolFailed {
            tool: program.to_owned(),
        });
    }
    String::from_utf8(bytes).map_err(|_| CollectError::ToolFailed {
        tool: program.to_owned(),
    })
}

#[cfg(test)]
#[path = "system_tests.rs"]
mod tests;
