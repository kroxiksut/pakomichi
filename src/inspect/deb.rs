// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed DEB metadata built from the control tar stream.
//!
//! Relationship fields stay raw strings with folded whitespace; parsing them
//! belongs to the family and dependency model.

use super::InspectLimits;
use super::ar::DebFormat;
use super::control::{Field, parse_paragraph};
use super::error::InspectError;
use super::tar::{EntryKind, read_control_tar};

const MAX_VERSION_BYTES: usize = 256;

/// Scripts that dpkg runs during installation or configuration. Only their
/// presence is recorded; their content is never executed or interpreted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintainerScript {
    Preinst,
    Postinst,
    Prerm,
    Postrm,
    /// The debconf `config` script, which runs before `preinst`.
    Config,
}

impl MaintainerScript {
    pub const ALL: [Self; 5] = [
        Self::Preinst,
        Self::Postinst,
        Self::Prerm,
        Self::Postrm,
        Self::Config,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preinst => "preinst",
            Self::Postinst => "postinst",
            Self::Prerm => "prerm",
            Self::Postrm => "postrm",
            Self::Config => "config",
        }
    }
}

/// The validated `control` paragraph of a binary package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebControl {
    package: String,
    version: String,
    architecture: String,
    installed_size_kib: Option<u64>,
    fields: Vec<(String, String)>,
}

impl DebControl {
    pub fn package(&self) -> &str {
        &self.package
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// `Installed-Size`, in KiB as dpkg defines it.
    pub const fn installed_size_kib(&self) -> Option<u64> {
        self.installed_size_kib
    }

    pub fn depends(&self) -> Option<String> {
        self.relation("Depends")
    }

    pub fn pre_depends(&self) -> Option<String> {
        self.relation("Pre-Depends")
    }

    pub fn provides(&self) -> Option<String> {
        self.relation("Provides")
    }

    pub fn conflicts(&self) -> Option<String> {
        self.relation("Conflicts")
    }

    pub fn breaks(&self) -> Option<String> {
        self.relation("Breaks")
    }

    pub fn replaces(&self) -> Option<String> {
        self.relation("Replaces")
    }

    /// Any field by case-insensitive name, as `dpkg-deb --field` prints it.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// All fields in file order, with names as written.
    pub fn fields(&self) -> &[(String, String)] {
        &self.fields
    }

    /// A relationship field with whitespace and line breaks folded to single
    /// spaces.
    fn relation(&self, name: &str) -> Option<String> {
        self.field(name)
            .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
    }

    pub(crate) fn from_fields(fields: Vec<Field>) -> Result<Self, InspectError> {
        let fields: Vec<(String, String)> = fields
            .into_iter()
            .map(|field| (field.name, field.value))
            .collect();
        let find = |name: &'static str| {
            fields
                .iter()
                .find(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        let required = |name: &'static str| {
            find(name)
                .filter(|value| !value.is_empty())
                .ok_or(InspectError::MissingField { field: name })
        };

        let package = required("Package")?;
        if !is_package_name(package) {
            return Err(invalid("Package", "not a valid package name"));
        }
        let version = required("Version")?;
        if !is_version(version) {
            return Err(invalid("Version", "not a valid version"));
        }
        let architecture = required("Architecture")?;
        if !is_architecture(architecture) {
            return Err(invalid("Architecture", "not a single architecture name"));
        }
        let installed_size_kib = find("Installed-Size")
            .map(|value| {
                (!value.is_empty()
                    && value.len() <= 20
                    && value.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| value.parse::<u64>().ok())
                .flatten()
                .ok_or(invalid("Installed-Size", "not a number of KiB"))
            })
            .transpose()?;

        Ok(Self {
            package: package.to_owned(),
            version: version.to_owned(),
            architecture: architecture.to_owned(),
            installed_size_kib,
            fields,
        })
    }
}

/// Everything the inspector learned about one binary DEB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebInspection {
    format: DebFormat,
    control: DebControl,
    control_members: Vec<String>,
    maintainer_scripts: Vec<MaintainerScript>,
}

impl DebInspection {
    pub fn format(&self) -> &DebFormat {
        &self.format
    }

    pub fn control(&self) -> &DebControl {
        &self.control
    }

    /// Top-level names in the control archive, such as `control`,
    /// `md5sums`, `conffiles`, `triggers`, or `shlibs`.
    pub fn control_members(&self) -> &[String] {
        &self.control_members
    }

    /// Maintainer scripts present in the package, in [`MaintainerScript::ALL`]
    /// order. Presence matters to policy even though nothing runs them here.
    pub fn maintainer_scripts(&self) -> &[MaintainerScript] {
        &self.maintainer_scripts
    }

    pub fn has_maintainer_scripts(&self) -> bool {
        !self.maintainer_scripts.is_empty()
    }
}

/// Builds the inspection result from the checked container `format` and the
/// decompressed control tar stream `control_tar`.
pub(crate) fn inspect_control_tar(
    format: DebFormat,
    control_tar: &[u8],
    limits: &InspectLimits,
) -> Result<DebInspection, InspectError> {
    let archive = read_control_tar(control_tar, limits)?;
    let fields = parse_paragraph(&archive.control, limits)?;
    let control = DebControl::from_fields(fields)?;

    let control_members: Vec<String> = archive
        .entries
        .iter()
        .filter(|entry| !entry.name.is_empty() && !entry.name.contains('/'))
        .filter(|entry| entry.kind != EntryKind::Directory)
        .map(|entry| entry.name.clone())
        .collect();
    let maintainer_scripts = MaintainerScript::ALL
        .into_iter()
        .filter(|script| control_members.iter().any(|name| name == script.as_str()))
        .collect();

    Ok(DebInspection {
        format,
        control,
        control_members,
        maintainer_scripts,
    })
}

/// Debian Policy 5.6.1: lowercase letters, digits, `+`, `-`, `.`; at least
/// two characters, starting with an alphanumeric.
fn is_package_name(name: &str) -> bool {
    name.len() >= 2
        && name.len() <= 128
        && name.starts_with(|character: char| {
            character.is_ascii_lowercase() || character.is_ascii_digit()
        })
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+-.".contains(&byte)
        })
}

/// Debian Policy 5.6.12 character set: `[epoch:]upstream[-revision]`. The
/// ordering itself is left to the native tools.
fn is_version(version: &str) -> bool {
    if version.len() > MAX_VERSION_BYTES {
        return false;
    }
    let upstream = match version.split_once(':') {
        Some((epoch, rest)) => {
            if epoch.is_empty() || !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            rest
        }
        None => version,
    };
    !upstream.is_empty()
        && upstream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+~-:".contains(&byte))
}

fn is_architecture(architecture: &str) -> bool {
    !architecture.is_empty()
        && architecture.len() <= 64
        && architecture
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

const fn invalid(field: &'static str, problem: &'static str) -> InspectError {
    InspectError::InvalidField { field, problem }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::inspect::ar::read_layout;
    use crate::inspect::fixtures::{TarItem, ar, tar};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const CONTROL: &str = "Package: pakomichi-probe\n\
        Version: 1:2.3.4~rc1-1+deb12u1\n\
        Architecture: amd64\n\
        Maintainer: Pakomichi test fixture <noreply@example.invalid>\n\
        Installed-Size: 42\n\
        Pre-Depends: dpkg (>= 1.21)\n\
        Depends: libc6 (>= 2.36),\n libssl3 | libssl1.1\n\
        Provides: probe\n\
        Conflicts: old-probe\n\
        Breaks: other (<< 2)\n\
        Replaces: old-probe\n\
        Description: TEST ONLY fixture\n long description\n";

    /// The control tar stream as `dpkg-deb --ctrl-tarfile` emits it for an
    /// uncompressed control member.
    fn inspect(items: &[TarItem<'_>]) -> Result<DebInspection, InspectError> {
        let control_tar = tar(items);
        let data_tar = tar(&[]);
        let package = ar(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar", &control_tar),
            ("data.tar", &data_tar),
        ]);
        let limits = InspectLimits::default();
        let format = read_layout(&mut Cursor::new(&package), package.len() as u64, &limits)?;
        inspect_control_tar(format, &control_tar, &limits)
    }

    #[test]
    fn extracts_typed_fields() -> TestResult {
        let inspection = inspect(&[
            TarItem::dir("./"),
            TarItem::file("./control", CONTROL.as_bytes()),
        ])?;
        let control = inspection.control();
        assert_eq!(control.package(), "pakomichi-probe");
        assert_eq!(control.version(), "1:2.3.4~rc1-1+deb12u1");
        assert_eq!(control.architecture(), "amd64");
        assert_eq!(control.installed_size_kib(), Some(42));
        assert_eq!(control.pre_depends().as_deref(), Some("dpkg (>= 1.21)"));
        assert_eq!(
            control.depends().as_deref(),
            Some("libc6 (>= 2.36), libssl3 | libssl1.1")
        );
        assert_eq!(control.provides().as_deref(), Some("probe"));
        assert_eq!(control.conflicts().as_deref(), Some("old-probe"));
        assert_eq!(control.breaks().as_deref(), Some("other (<< 2)"));
        assert_eq!(control.replaces().as_deref(), Some("old-probe"));
        assert_eq!(
            control.field("description"),
            Some("TEST ONLY fixture\n long description")
        );
        assert_eq!(control.fields().len(), 12);
        assert!(!inspection.has_maintainer_scripts());
        assert_eq!(inspection.control_members(), ["control".to_owned()]);
        assert_eq!(inspection.format().version(), "2.0");
        Ok(())
    }

    #[test]
    fn records_maintainer_scripts_without_running_them() -> TestResult {
        let script = b"#!/bin/sh\ntouch /tmp/pakomichi-must-not-exist\n";
        let inspection = inspect(&[
            TarItem::file("./control", CONTROL.as_bytes()),
            TarItem::file("./postrm", script),
            TarItem::file("./preinst", script),
            TarItem::symlink("./postinst", "preinst"),
            TarItem::file("./config", script),
            TarItem::file("./prerm", script),
            TarItem::file("./triggers", b"interest foo\n"),
        ])?;
        assert_eq!(inspection.maintainer_scripts(), MaintainerScript::ALL);
        assert!(
            inspection
                .control_members()
                .contains(&"triggers".to_owned())
        );
        Ok(())
    }

    #[test]
    fn requires_package_version_and_architecture() {
        for (missing, text) in [
            ("Package", "Version: 1\nArchitecture: all\n"),
            ("Version", "Package: probe\nArchitecture: all\n"),
            ("Architecture", "Package: probe\nVersion: 1\n"),
            ("Version", "Package: probe\nVersion:\nArchitecture: all\n"),
        ] {
            let result = inspect(&[TarItem::file("./control", text.as_bytes())]);
            assert!(
                matches!(result, Err(InspectError::MissingField { field }) if field == missing),
                "{text}"
            );
        }
    }

    #[test]
    fn rejects_invalid_identity_fields() {
        for (field, text) in [
            ("Package", "Package: Probe\nVersion: 1\nArchitecture: all\n"),
            ("Package", "Package: p\nVersion: 1\nArchitecture: all\n"),
            ("Package", "Package: ../x\nVersion: 1\nArchitecture: all\n"),
            (
                "Version",
                "Package: probe\nVersion: 1 2\nArchitecture: all\n",
            ),
            (
                "Version",
                "Package: probe\nVersion: x:1\nArchitecture: all\n",
            ),
            (
                "Version",
                "Package: probe\nVersion: 1/2\nArchitecture: all\n",
            ),
            (
                "Version",
                "Package: probe\nVersion: 1\n -2\nArchitecture: all\n",
            ),
            (
                "Architecture",
                "Package: probe\nVersion: 1\nArchitecture: amd64 i386\n",
            ),
            (
                "Installed-Size",
                "Package: probe\nVersion: 1\nArchitecture: all\nInstalled-Size: -1\n",
            ),
            (
                "Installed-Size",
                "Package: probe\nVersion: 1\nArchitecture: all\nInstalled-Size: 99999999999999999999\n",
            ),
        ] {
            let result = inspect(&[TarItem::file("./control", text.as_bytes())]);
            assert!(
                matches!(result, Err(InspectError::InvalidField { field: actual, .. }) if actual == field),
                "{text}: {result:?}"
            );
        }
    }

    #[test]
    fn accepts_many_long_fields() -> TestResult {
        let mut text = String::from("Package: probe\nVersion: 1\nArchitecture: all\n");
        for index in 0..300 {
            text.push_str(&format!("X-Field-{index}: {}\n", "v".repeat(100)));
        }
        text.push_str("Description: long\n");
        for _ in 0..2000 {
            text.push(' ');
            text.push_str(&"d".repeat(70));
            text.push('\n');
        }
        let inspection = inspect(&[TarItem::file("./control", text.as_bytes())])?;
        assert_eq!(inspection.control().fields().len(), 304);
        assert!(inspection.control().field("Description").map(str::len) > Some(140_000));
        Ok(())
    }
}
