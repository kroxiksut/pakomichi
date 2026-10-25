// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pakomichi-applier`: one `Accept=yes` instance of `apply.sock`
//! (ADR-029 point 2, P4-003a).
//!
//! ```text
//! pakomichi-applier --socket /run/pakomichi/apply.sock --lock /run/pakomichi/apply.lock
//! ```
//!
//! Standard input and output are the connection. The instance must run as
//! root, admits only the uid that owns the socket file (the state owner;
//! a socket owned by root is a misconfiguration and is refused), takes an
//! exclusive lock so two instances never write the same files, applies
//! one desired APT configuration to `/`, and exits.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match linux::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("event=fatal error={message}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("pakomichi-applier runs only on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    use pakomichi::apt::applier::{SystemCheck, answer};
    use pakomichi::ipc::channels::{ApplyRequest, ApplyResponse};
    use pakomichi::ipc::oneshot::serve_stdio;
    use pakomichi::ipc::server::PeerRule;
    use pakomichi::process::{require_root, socket_owner};

    /// The lock file: created by root in a root-owned directory, never
    /// followed through a symlink, and held until the instance exits.
    fn take_lock(path: &Path) -> Result<File, String> {
        let directory = path.parent().ok_or("--lock has no directory")?;
        let owner = std::fs::symlink_metadata(directory)
            .map_err(|e| format!("{}: {e}", directory.display()))?;
        if !owner.is_dir() || owner.uid() != 0 || owner.mode() & 0o022 != 0 {
            return Err(format!(
                "{} must be a directory owned by root and not writable by others",
                directory.display()
            ));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        // Waits for another instance; the unit's RuntimeMaxSec bounds it.
        lock.lock().map_err(|e| format!("lock: {e}"))?;
        Ok(lock)
    }

    fn outcome(response: &ApplyResponse) -> &'static str {
        match response {
            ApplyResponse::Applied(_) => "applied",
            ApplyResponse::RolledBack(_) => "rolled_back",
            ApplyResponse::Drifted(_) => "drifted",
            ApplyResponse::Invalid(_) => "invalid",
            ApplyResponse::Failed(_) => "failed",
            ApplyResponse::Error(_) => "error",
        }
    }

    pub fn run() -> Result<(), String> {
        // The role is checked before anything else is read.
        require_root().map_err(|e| e.to_string())?;
        let mut socket = None;
        let mut lock = None;
        let mut arguments = std::env::args().skip(1);
        while let Some(name) = arguments.next() {
            let value = arguments.next().ok_or(format!("{name} needs a value"))?;
            match name.as_str() {
                "--socket" => socket = Some(PathBuf::from(value)),
                "--lock" => lock = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown argument {name}")),
            }
        }
        let socket = socket.ok_or("--socket is required")?;
        let lock = lock.ok_or("--lock is required")?;
        let peer = socket_owner(&socket).map_err(|e| e.to_string())?;
        if peer == 0 {
            return Err(format!(
                "{} belongs to root; it must belong to the state owner's user",
                socket.display()
            ));
        }
        let _lock = take_lock(&lock)?;
        serve_stdio(
            PeerRule::OnlyUid(peer),
            |request: ApplyRequest, _uid| -> ApplyResponse {
                let ApplyRequest::ApplyApt(apply) = &request;
                let operation = apply.operation_id.clone();
                let response = answer(Path::new("/"), request, &SystemCheck);
                eprintln!(
                    "event=apply operation={} outcome={}",
                    operation.escape_debug(),
                    outcome(&response)
                );
                response
            },
        )
        .map_err(|e| e.to_string())
    }
}
