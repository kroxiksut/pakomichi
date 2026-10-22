// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inspection errors and their mapping to the stable reason contract.

use std::fmt;
use std::io;
use std::time::Duration;

use crate::error::{ObjectReference, Reason, ReasonCode, SafeText};

use super::control::ControlError;

/// The `dpkg-deb` diagnostic (under `LC_ALL=C`) for a member whose
/// compression this `dpkg` cannot decompress, as in dpkg 1.21.23 (Debian
/// 12) and 1.22.6 (Ubuntu 24.04). The reader accepts only member names with a known suffix, so the
/// package cannot choose this text; and either way the result admits
/// nothing, only the reason code differs.
const DPKG_UNKNOWN_COMPRESSION: &str = "uses unknown compression for member";

#[derive(Debug)]
#[non_exhaustive]
pub enum InspectError {
    /// The process runs with effective UID 0 and no test override is set.
    RunningAsRoot,
    /// A required native tool was not found at a trusted path.
    ToolUnavailable { tool: &'static str },
    /// The package path is a symlink, a directory, a FIFO, or a device.
    NotRegularFile,
    /// The package file exceeds the configured size limit.
    PackageTooLarge { size: u64, limit: u64 },
    /// The `ar` container is truncated or structurally invalid.
    MalformedArchive { problem: &'static str },
    /// Not an `ar` container, or a format version, lead, or member
    /// compression that this reader does not accept and no current `dpkg` or
    /// `rpm` accepts either.
    UnsupportedFormat { problem: &'static str },
    /// The compressed control member exceeds the configured limit.
    ControlMemberTooLarge { size: u64, limit: u64 },
    /// The decompressed control tar stream exceeds the configured limit.
    ControlArchiveTooLarge { limit: u64 },
    /// The control tar stream is truncated, ambiguous, or unsafe.
    MalformedControlArchive { problem: &'static str },
    /// The `control` file exceeds the configured limit.
    ControlFileTooLarge { size: u64, limit: u64 },
    /// The `control` paragraph violates the deb822 syntax or a limit.
    MalformedControl(ControlError),
    /// A field required for a binary package (DEB control field or RPM
    /// header tag) is absent.
    MissingField { field: &'static str },
    /// A field is present but its value is not acceptable.
    InvalidField {
        field: &'static str,
        problem: &'static str,
    },
    /// The file does not start with the RPM lead magic (for example an empty
    /// file or a DEB).
    NotRpm,
    /// The RPM lead or a header is truncated, structurally invalid, or
    /// inconsistent with the file size.
    MalformedRpm { problem: &'static str },
    /// An RPM header declares more index entries or data than allowed.
    RpmHeaderTooLarge {
        header: &'static str,
        entries: u32,
        bytes: u32,
    },
    /// The native tool rejected the package. `stderr` is bounded tool output
    /// about untrusted input: log it, never put it into a reason message.
    ToolFailed {
        exit_code: Option<i32>,
        stderr: String,
    },
    /// The native tool was terminated by a signal, for example `SIGXCPU`
    /// from the CPU limit.
    ToolKilled { signal: i32 },
    /// The native tool exceeded the wall-clock limit and was killed.
    TimedOut { after: Duration },
    /// The native tool wrote more diagnostics than allowed and was killed.
    DiagnosticsTooLarge { limit: usize },
    /// Any other local I/O failure.
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl InspectError {
    /// The stable reason code for user-facing results, if this error has one.
    ///
    /// A rejection of the package bytes maps to `E_ARTIFACT_MALFORMED`: the
    /// file is truncated or corrupted, is not a DEB or RPM, has malformed
    /// headers or metadata, exceeds an inspection limit, or uses a format
    /// version or member compression that no current `dpkg` or `rpm`
    /// accepts. The one exception is `dpkg-deb` reporting an unknown
    /// compression for a member that this reader accepts (for example
    /// `control.tar.zst` under a dpkg without zstd support, such as the one
    /// in Debian 11): the bytes may be well-formed and
    /// only the native tool of this system cannot read them, so that maps to
    /// `E_PLATFORM_UNSUPPORTED`. Failures of the local environment (root, a
    /// missing tool, a timeout or signal that load can also cause, I/O) have
    /// no code; the caller treats them as an internal fault and admits
    /// nothing.
    pub fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::ToolFailed { stderr, .. } if stderr.contains(DPKG_UNKNOWN_COMPRESSION) => {
                Some(ReasonCode::EPlatformUnsupported)
            }
            Self::PackageTooLarge { .. }
            | Self::MalformedArchive { .. }
            | Self::UnsupportedFormat { .. }
            | Self::ControlMemberTooLarge { .. }
            | Self::ControlArchiveTooLarge { .. }
            | Self::MalformedControlArchive { .. }
            | Self::ControlFileTooLarge { .. }
            | Self::MalformedControl(_)
            | Self::MissingField { .. }
            | Self::InvalidField { .. }
            | Self::NotRpm
            | Self::MalformedRpm { .. }
            | Self::RpmHeaderTooLarge { .. }
            | Self::ToolFailed { .. } => Some(ReasonCode::EArtifactMalformed),
            Self::RunningAsRoot
            | Self::ToolUnavailable { .. }
            | Self::NotRegularFile
            | Self::ToolKilled { .. }
            | Self::TimedOut { .. }
            | Self::DiagnosticsTooLarge { .. }
            | Self::Io { .. } => None,
        }
    }

    /// A reason event for `object` with a fixed message; no package bytes,
    /// field values, member names, or tool output enter the message.
    pub fn reason(&self, object: ObjectReference) -> Option<Reason> {
        let code = self.reason_code()?;
        let message = match self {
            Self::ToolFailed { .. } if code == ReasonCode::EPlatformUnsupported => {
                "package compression is not supported by the native package tool"
            }
            Self::PackageTooLarge { .. } => "package exceeds the inspection size limit",
            Self::MalformedArchive { .. } => "package archive is truncated or malformed",
            Self::UnsupportedFormat { .. } => "package format version is not supported",
            Self::ControlMemberTooLarge { .. }
            | Self::ControlArchiveTooLarge { .. }
            | Self::ControlFileTooLarge { .. }
            | Self::RpmHeaderTooLarge { .. } => "package metadata exceeds the inspection limits",
            Self::MalformedControlArchive { .. } => "package metadata archive is malformed",
            Self::MalformedControl(_) => "package control data is malformed",
            Self::MissingField { .. } => "package metadata lacks a required field",
            Self::InvalidField { .. } => "package metadata has an invalid field",
            Self::NotRpm => "package is not an RPM package",
            Self::MalformedRpm { .. } => "package header is truncated or malformed",
            _ => "native package tool rejected the package",
        };
        SafeText::new(message)
            .ok()
            .map(|message| Reason::new(code, object, message))
    }
}

impl fmt::Display for InspectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunningAsRoot => {
                formatter.write_str("the package inspector must not run as root")
            }
            Self::ToolUnavailable { tool } => write!(formatter, "{tool} was not found"),
            Self::NotRegularFile => formatter.write_str("the package is not a regular file"),
            Self::PackageTooLarge { size, limit } => {
                write!(formatter, "package of {size} bytes exceeds {limit} bytes")
            }
            Self::MalformedArchive { problem } => write!(formatter, "malformed archive: {problem}"),
            Self::UnsupportedFormat { problem } => {
                write!(formatter, "unsupported package format: {problem}")
            }
            Self::ControlMemberTooLarge { size, limit } => write!(
                formatter,
                "control member of {size} bytes exceeds {limit} bytes"
            ),
            Self::ControlArchiveTooLarge { limit } => {
                write!(formatter, "control archive exceeds {limit} bytes")
            }
            Self::MalformedControlArchive { problem } => {
                write!(formatter, "malformed control archive: {problem}")
            }
            Self::ControlFileTooLarge { size, limit } => {
                write!(
                    formatter,
                    "control file of {size} bytes exceeds {limit} bytes"
                )
            }
            Self::MalformedControl(error) => write!(formatter, "malformed control file: {error}"),
            Self::MissingField { field } => write!(formatter, "required field {field} is missing"),
            Self::InvalidField { field, problem } => {
                write!(formatter, "field {field} is invalid: {problem}")
            }
            Self::NotRpm => formatter.write_str("the file is not an RPM package"),
            Self::MalformedRpm { problem } => write!(formatter, "malformed RPM: {problem}"),
            Self::RpmHeaderTooLarge {
                header,
                entries,
                bytes,
            } => write!(
                formatter,
                "RPM {header} declares {entries} entries and {bytes} bytes, over the limits"
            ),
            Self::ToolFailed {
                exit_code: Some(code),
                ..
            } => write!(formatter, "dpkg-deb exited with status {code}"),
            Self::ToolFailed {
                exit_code: None, ..
            } => formatter.write_str("dpkg-deb failed without an exit status"),
            Self::ToolKilled { signal } => {
                write!(formatter, "dpkg-deb was killed by signal {signal}")
            }
            Self::TimedOut { after } => {
                write!(formatter, "dpkg-deb did not finish within {after:?}")
            }
            Self::DiagnosticsTooLarge { limit } => {
                write!(formatter, "dpkg-deb diagnostics exceed {limit} bytes")
            }
            Self::Io { operation, source } => write!(formatter, "cannot {operation}: {source}"),
        }
    }
}

impl std::error::Error for InspectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::MalformedControl(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ControlError> for InspectError {
    fn from(error: ControlError) -> Self {
        Self::MalformedControl(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ObjectKind, SafeIdentifier};
    use crate::inspect::ControlProblem;

    fn object() -> Result<ObjectReference, crate::error::SafeValueError> {
        Ok(ObjectReference::new(
            ObjectKind::Artifact,
            SafeIdentifier::new("artifact-1")?,
        ))
    }

    #[test]
    fn package_rejections_map_to_artifact_malformed() -> Result<(), Box<dyn std::error::Error>> {
        let rejections = [
            InspectError::PackageTooLarge { size: 2, limit: 1 },
            InspectError::MalformedArchive { problem: "x" },
            InspectError::UnsupportedFormat { problem: "x" },
            InspectError::ControlMemberTooLarge { size: 2, limit: 1 },
            InspectError::ControlArchiveTooLarge { limit: 1 },
            InspectError::MalformedControlArchive { problem: "x" },
            InspectError::ControlFileTooLarge { size: 2, limit: 1 },
            InspectError::MalformedControl(ControlError::new(1, ControlProblem::MissingColon)),
            InspectError::MissingField { field: "Package" },
            InspectError::InvalidField {
                field: "Package",
                problem: "x",
            },
            InspectError::NotRpm,
            InspectError::MalformedRpm { problem: "x" },
            InspectError::RpmHeaderTooLarge {
                header: "main header",
                entries: 1,
                bytes: 1,
            },
            InspectError::ToolFailed {
                exit_code: Some(2),
                stderr: "token=abc".to_owned(),
            },
        ];
        for error in rejections {
            let reason = error.reason(object()?).ok_or("expected a reason")?;
            assert_eq!(reason.code(), ReasonCode::EArtifactMalformed, "{error}");
            assert_eq!(error.reason_code(), Some(reason.code()), "{error}");
            // Tool output never reaches the message.
            assert!(!reason.message().as_str().contains("token"));
        }
        Ok(())
    }

    #[test]
    fn a_compression_unknown_to_the_native_tool_is_a_platform_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let unsupported = InspectError::ToolFailed {
            exit_code: Some(2),
            stderr: "dpkg-deb: error: archive '/proc/self/fd/0' uses unknown compression \
                     for member 'control.tar.zst', giving up\n"
                .to_owned(),
        };
        let reason = unsupported.reason(object()?).ok_or("expected a reason")?;
        assert_eq!(reason.code(), ReasonCode::EPlatformUnsupported);
        assert!(!reason.message().as_str().contains("control.tar"));

        // A corrupted stream in a supported compression stays malformed.
        let corrupted = InspectError::ToolFailed {
            exit_code: Some(2),
            stderr: "dpkg-deb (subprocess): decompressing archive member: \
                     lzma error: compressed data is corrupt\n"
                .to_owned(),
        };
        assert_eq!(
            corrupted.reason_code(),
            Some(ReasonCode::EArtifactMalformed)
        );
        Ok(())
    }

    #[test]
    fn environment_failures_have_no_reason() -> Result<(), Box<dyn std::error::Error>> {
        let faults = [
            InspectError::RunningAsRoot,
            InspectError::ToolUnavailable { tool: "dpkg-deb" },
            InspectError::NotRegularFile,
            InspectError::ToolKilled { signal: 24 },
            InspectError::TimedOut {
                after: Duration::from_secs(1),
            },
            InspectError::DiagnosticsTooLarge { limit: 1 },
            InspectError::Io {
                operation: "read",
                source: io::Error::other("x"),
            },
        ];
        for error in faults {
            assert_eq!(error.reason_code(), None, "{error}");
            assert!(error.reason(object()?).is_none());
        }
        Ok(())
    }
}
