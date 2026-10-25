// SPDX-License-Identifier: MIT OR Apache-2.0

//! The target of this system for the compatibility check: the
//! distribution from `/etc/os-release`, the native architecture from the
//! package manager itself, and the execution policy (P4-001a).
//!
//! The architecture is what `dpkg --print-architecture` or
//! `rpm --eval %_arch` answers, never `uname`: a 32-bit userland on a
//! 64-bit kernel installs the userland's packages.

use std::fmt;
use std::io::Read;
use std::process::{Command, Stdio};

use super::{Distribution, OtherReleaseBuilds, Target, policy};
use crate::inventory::{Ecosystem, TargetPlatform};
use crate::namespace::collect::parse::os_release_value;

const OS_RELEASE: &str = "/etc/os-release";
const MAX_OUTPUT: u64 = 256;

#[derive(Debug)]
pub enum DetectError {
    OsRelease(String),
    Tool(&'static str, String),
    Platform(String),
}

impl fmt::Display for DetectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OsRelease(detail) => write!(formatter, "{OS_RELEASE}: {detail}"),
            Self::Tool(tool, detail) => write!(formatter, "{tool}: {detail}"),
            Self::Platform(detail) => write!(formatter, "platform: {detail}"),
        }
    }
}

impl std::error::Error for DetectError {}

/// The distribution of `os-release` text.
pub fn distribution(os_release: &str) -> Result<Distribution, DetectError> {
    let id = os_release_value(os_release, "ID")
        .ok_or_else(|| DetectError::OsRelease("no ID".to_owned()))?;
    let version = os_release_value(os_release, "VERSION_ID").unwrap_or("");
    Ok(Distribution::from_os_release(id, version))
}

/// One short line from a package manager tool, without a shell.
fn tool_line(tool: &'static str, path: &str, args: &[&str]) -> Result<String, DetectError> {
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| DetectError::Tool(tool, error.to_string()))?;
    let mut text = String::new();
    if let Some(stdout) = child.stdout.take() {
        stdout
            .take(MAX_OUTPUT)
            .read_to_string(&mut text)
            .map_err(|error| DetectError::Tool(tool, error.to_string()))?;
    }
    let status = child
        .wait()
        .map_err(|error| DetectError::Tool(tool, error.to_string()))?;
    let line = text.trim();
    if !status.success() || line.is_empty() || line.contains(char::is_whitespace) {
        return Err(DetectError::Tool(
            tool,
            format!("unexpected answer ({status})"),
        ));
    }
    Ok(line.to_owned())
}

/// The native architecture of the package manager of `ecosystem`.
pub fn native_arch(ecosystem: Ecosystem) -> Result<String, DetectError> {
    match ecosystem {
        Ecosystem::Deb => tool_line("dpkg", "/usr/bin/dpkg", &["--print-architecture"]),
        Ecosystem::Rpm => tool_line("rpm", "/usr/bin/rpm", &["--eval", "%_arch"]),
    }
}

/// The target of this system.
pub fn target(ecosystem: Ecosystem) -> Result<Target, DetectError> {
    let os_release = std::fs::read_to_string(OS_RELEASE)
        .map_err(|error| DetectError::OsRelease(error.to_string()))?;
    let arch = native_arch(ecosystem)?;
    Ok(Target {
        platform: TargetPlatform::new(ecosystem, &arch)
            .map_err(|error| DetectError::Platform(error.to_string()))?,
        distribution: distribution(&os_release)?,
        execution_policy: policy::detect(),
        other_release_builds: OtherReleaseBuilds::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::DistributionFamily;

    #[test]
    fn the_distribution_comes_from_os_release_and_its_absence_is_an_error() {
        let debian =
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n";
        let parsed = distribution(debian).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(parsed.family, DistributionFamily::Debian);
        assert_eq!(parsed.release.as_deref(), Some("12"));
        let astra = "ID=astra\nVERSION_ID=1.8_x86-64\n";
        let parsed = distribution(astra).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(parsed.family, DistributionFamily::Astra);
        assert_eq!(parsed.release.as_deref(), Some("1.8"));
        // No ID: the distribution is unknown, not guessed.
        assert!(distribution("NAME=Linux\n").is_err());
    }
}
