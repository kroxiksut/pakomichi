// SPDX-License-Identifier: MIT OR Apache-2.0

//! Start-up checks of Pakomichi's processes (ADR-017 point 7, ADR-035).
//!
//! Each process refuses to run with more authority than its role: only the
//! applier is root; the signer's key directory belongs to the signer and
//! nobody else can enter it. A channel admits the uid that owns its socket
//! file: systemd creates the socket with the owner the unit names
//! (`SocketUser=`), so the code check repeats the file mode instead of a
//! second, separately configured number.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Why a process refuses to start.
#[derive(Debug)]
pub enum StartError {
    Io(io::Error),
    /// The process runs as root but its role is unprivileged.
    Root,
    /// The process must run as root (the applier).
    NotRoot {
        uid: u32,
    },
    /// A path is not what the role requires; the text says what.
    Unsafe(String),
}

impl fmt::Display for StartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Root => formatter.write_str("refusing to run as root"),
            Self::NotRoot { uid } => write!(formatter, "must run as root, runs as uid {uid}"),
            Self::Unsafe(what) => formatter.write_str(what),
        }
    }
}

impl std::error::Error for StartError {}

impl From<io::Error> for StartError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The effective uid, from `/proc/self/status` (no `unsafe`).
pub fn effective_uid() -> Result<u32, StartError> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| StartError::Unsafe("no effective uid in /proc/self/status".to_owned()))
}

/// An unprivileged role: refuses uid 0.
pub fn require_unprivileged() -> Result<u32, StartError> {
    unprivileged_role(effective_uid()?)
}

/// The applier's role: requires uid 0.
pub fn require_root() -> Result<(), StartError> {
    root_role(effective_uid()?)
}

/// The role checks as functions of the uid, so both answers are tested
/// whatever user runs the tests.
const fn unprivileged_role(uid: u32) -> Result<u32, StartError> {
    match uid {
        0 => Err(StartError::Root),
        uid => Ok(uid),
    }
}

const fn root_role(uid: u32) -> Result<(), StartError> {
    match uid {
        0 => Ok(()),
        uid => Err(StartError::NotRoot { uid }),
    }
}

/// The uid that owns the socket file at `path`: the one peer the channel
/// admits. The socket must be a socket, not a symlink.
pub fn socket_owner(path: &Path) -> Result<u32, StartError> {
    let metadata = fs::symlink_metadata(path)?;
    if !std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) {
        return Err(StartError::Unsafe(format!(
            "{} is not a socket",
            path.display()
        )));
    }
    Ok(metadata.uid())
}

/// A directory only `uid` can enter: owned by it, a real directory, no
/// access for group or others. The signer's key lives in one.
pub fn require_private_dir(path: &Path, uid: u32) -> Result<(), StartError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(StartError::Unsafe(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    if metadata.uid() != uid {
        return Err(StartError::Unsafe(format!(
            "{} belongs to uid {}, not {uid}",
            path.display(),
            metadata.uid()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StartError::Unsafe(format!(
            "{} is open to group or others ({:o})",
            path.display(),
            metadata.permissions().mode() & 0o777
        )));
    }
    Ok(())
}

/// The descriptors systemd passed, read once: `listenfd` clears
/// `LISTEN_FDS` and `LISTEN_PID` when it reads them, so a second read would
/// find none.
fn inherited() -> &'static std::sync::Mutex<listenfd::ListenFd> {
    static FDS: std::sync::OnceLock<std::sync::Mutex<listenfd::ListenFd>> =
        std::sync::OnceLock::new();
    FDS.get_or_init(|| std::sync::Mutex::new(listenfd::ListenFd::from_env()))
}

/// The Unix listener systemd passed under `name` (`FileDescriptorName=`,
/// listed in `LISTEN_FDNAMES`). There is no fallback bind (ADR-029 point 1).
/// Each listener is taken once.
pub fn inherited_unix_listener(name: &str) -> Result<std::os::unix::net::UnixListener, StartError> {
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let index = names
        .split(':')
        .position(|candidate| candidate == name)
        .ok_or_else(|| StartError::Unsafe(format!("no socket named {name} from systemd")))?;
    inherited()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take_unix_listener(index)?
        .ok_or_else(|| StartError::Unsafe(format!("socket {name} is not a Unix listener")))
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
