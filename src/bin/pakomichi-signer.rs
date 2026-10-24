// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pakomichi-signer`: one `Accept=yes` instance of `sign.sock` (ADR-035).
//!
//! ```text
//! pakomichi-signer --homedir DIR --key FINGERPRINT --socket /run/pakomichi/sign.sock
//! ```
//!
//! Standard input and output are the connection. The instance refuses to
//! run as root or with a key directory anyone else can enter, admits only
//! the uid that owns the socket file (the state owner), clear-signs one
//! text with `gpg`, and exits.

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
    eprintln!("pakomichi-signer runs only on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;

    use pakomichi::ipc::channels::{SignRequest, SignResponse};
    use pakomichi::ipc::oneshot::serve_stdio;
    use pakomichi::ipc::server::PeerRule;
    use pakomichi::process::{require_private_dir, require_unprivileged, socket_owner};
    use pakomichi::publish::sign::{Fingerprint, GpgSigner, answer_sign};

    pub fn run() -> Result<(), String> {
        // The role is checked before anything else is read.
        let uid = require_unprivileged().map_err(|e| e.to_string())?;
        let mut homedir = None;
        let mut key = None;
        let mut socket = None;
        let mut arguments = std::env::args().skip(1);
        while let Some(name) = arguments.next() {
            let value = arguments.next().ok_or(format!("{name} needs a value"))?;
            match name.as_str() {
                "--homedir" => homedir = Some(PathBuf::from(value)),
                "--key" => {
                    key = Some(Fingerprint::new(&value).ok_or("--key is not a fingerprint")?)
                }
                "--socket" => socket = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown argument {name}")),
            }
        }
        let homedir = homedir.ok_or("--homedir is required")?;
        let socket = socket.ok_or("--socket is required")?;
        require_private_dir(&homedir, uid).map_err(|e| e.to_string())?;
        let peer = socket_owner(&socket).map_err(|e| e.to_string())?;
        let signer =
            GpgSigner::new(&homedir, key.ok_or("--key is required")?).map_err(|e| e.to_string())?;
        serve_stdio(
            PeerRule::OnlyUid(peer),
            |request: SignRequest, _uid| -> SignResponse { answer_sign(&signer, request) },
        )
        .map_err(|e| e.to_string())
    }
}
