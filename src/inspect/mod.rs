// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package metadata inspection without installation (ADR-009, ADR-017).
//!
//! A downloaded package is untrusted input. The inspector reads its native
//! metadata and never installs it, unpacks its payload, or runs a maintainer
//! script. For a binary DEB the work is split as follows:
//!
//! 1. The outer `ar` container is checked in-process from an already opened
//!    file: member order, the `debian-binary` format version, the control
//!    and data member names (and so their compression), and the compressed
//!    size of the control member. A truncated archive fails here.
//! 2. `dpkg-deb --ctrl-tarfile` decompresses only the control member to a
//!    pipe, in a child process with a fixed environment, a wall-clock
//!    timeout, capped output, and kernel resource limits applied by
//!    `prlimit`. The archive reaches it as its standard input, so the bytes
//!    checked in step 1 are the bytes it reads.
//! 3. The control tar stream and the `control` paragraph are parsed in
//!    memory with explicit limits; nothing is written to disk.
//!
//! An RPM is read in-process, without a native tool: the lead, the signature
//! header, and the main header are checked against the limits and parsed
//! with the `rpm` crate; the payload is never read.
//!
//! Both inspectors run only on Linux and refuse to run as root; deploy them
//! in the unprivileged, disposable inspector process of ADR-017. The parsers
//! and their limits are portable so that they are tested on every target.

// The helpers below serve the Linux inspector; on other targets only their
// own unit tests use them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod ar;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod control;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod deb;
mod error;
#[cfg(test)]
pub(crate) mod fixtures;
#[cfg(target_os = "linux")]
mod remote;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod rpm_reader;
#[cfg(target_os = "linux")]
mod runner;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod tar;

use std::time::Duration;

pub use ar::{Compression, DebFormat};
pub use control::{ControlError, ControlProblem};
pub use deb::{DebControl, DebInspection, MaintainerScript};
pub use error::InspectError;
#[cfg(target_os = "linux")]
pub use remote::{RemoteInspectError, SocketInspector, answer_inspect};
pub use rpm_reader::{
    RPM_HEADER_MAX_BYTES, RPM_HEADER_MAX_ENTRIES, RPM_SIGNATURE_MAX_BYTES,
    RPM_SIGNATURE_MAX_ENTRIES, RpmDependency, RpmDigest, RpmInspection, RpmScriptlet, RpmSignature,
};
#[cfg(target_os = "linux")]
pub use rpm_reader::{RpmInspector, RpmInspectorConfig};
#[cfg(target_os = "linux")]
pub use runner::{DebInspector, InspectorConfig, ToolPaths};

/// Upper bounds for one inspection. Exceeding any of them rejects the
/// package; none of them is silently truncated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectLimits {
    /// The whole package file (GitHub limits a release asset to 2 GiB).
    pub max_package_bytes: u64,
    /// The compressed control member inside the `ar` container.
    pub max_control_member_bytes: u64,
    /// The decompressed control tar stream; this bounds a decompression bomb.
    pub max_control_tar_bytes: u64,
    /// The `control` file inside the control tar stream.
    pub max_control_file_bytes: u64,
    /// One field value of the `control` paragraph.
    pub max_field_bytes: usize,
    /// Fields in the `control` paragraph.
    pub max_fields: usize,
    /// Entries in the control tar stream.
    pub max_tar_entries: usize,
    /// Captured diagnostics of the native tool.
    pub max_stderr_bytes: usize,
    /// Wall-clock time for the native tool.
    pub timeout: Duration,
    /// `RLIMIT_CPU` of the native tool, in seconds.
    pub cpu_seconds: u64,
    /// `RLIMIT_AS` of the native tool, in bytes.
    pub address_space_bytes: u64,
    /// `RLIMIT_NOFILE` of the native tool.
    pub open_files: u64,
    /// Index entries of an RPM signature header; capped at
    /// [`RPM_SIGNATURE_MAX_ENTRIES`] whatever the setting.
    pub max_rpm_signature_entries: u32,
    /// Data store of an RPM signature header; capped at
    /// [`RPM_SIGNATURE_MAX_BYTES`].
    pub max_rpm_signature_bytes: u32,
    /// Index entries of an RPM main header; capped at
    /// [`RPM_HEADER_MAX_ENTRIES`].
    pub max_rpm_header_entries: u32,
    /// Data store of an RPM main header; capped at [`RPM_HEADER_MAX_BYTES`].
    pub max_rpm_header_bytes: u32,
}

impl Default for InspectLimits {
    fn default() -> Self {
        Self {
            max_package_bytes: 2 * 1024 * 1024 * 1024,
            max_control_member_bytes: 16 * 1024 * 1024,
            max_control_tar_bytes: 64 * 1024 * 1024,
            max_control_file_bytes: 1024 * 1024,
            max_field_bytes: 256 * 1024,
            max_fields: 512,
            max_tar_entries: 128,
            max_stderr_bytes: 64 * 1024,
            timeout: Duration::from_secs(30),
            cpu_seconds: 20,
            address_space_bytes: 1024 * 1024 * 1024,
            open_files: 64,
            max_rpm_signature_entries: RPM_SIGNATURE_MAX_ENTRIES,
            max_rpm_signature_bytes: RPM_SIGNATURE_MAX_BYTES,
            max_rpm_header_entries: RPM_HEADER_MAX_ENTRIES,
            // librpm accepts 256 MiB; a larger header is rejected here
            // unless the limit is raised explicitly.
            max_rpm_header_bytes: 64 * 1024 * 1024,
        }
    }
}
