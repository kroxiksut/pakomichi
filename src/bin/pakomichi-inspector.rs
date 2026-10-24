// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pakomichi-inspector`: one `Accept=yes` instance of `inspect.sock`
//! (ADR-035).
//!
//! ```text
//! pakomichi-inspector --cas-root DIR --socket /run/pakomichi/inspect.sock
//! ```
//!
//! Standard input and output are the connection. The instance refuses
//! root, admits only the uid that owns the socket file (the state owner),
//! opens the named object read-only in the CAS, checks its digest, inspects
//! it without running anything from it, answers, and exits. The unit runs
//! it with `DynamicUser=yes`, no network, and a read-only file system.

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
    eprintln!("pakomichi-inspector runs only on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;

    use pakomichi::cas::ObjectReader;
    use pakomichi::inspect::{DebInspector, InspectorConfig, answer_inspect};
    use pakomichi::ipc::channels::{InspectRequest, InspectResponse};
    use pakomichi::ipc::oneshot::serve_stdio;
    use pakomichi::ipc::server::PeerRule;
    use pakomichi::process::{require_unprivileged, socket_owner};

    pub fn run() -> Result<(), String> {
        // The role is checked before anything else is read.
        require_unprivileged().map_err(|e| e.to_string())?;
        let mut cas_root = None;
        let mut socket = None;
        let mut arguments = std::env::args().skip(1);
        while let Some(name) = arguments.next() {
            let value = arguments.next().ok_or(format!("{name} needs a value"))?;
            match name.as_str() {
                "--cas-root" => cas_root = Some(PathBuf::from(value)),
                "--socket" => socket = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown argument {name}")),
            }
        }
        let cas_root = cas_root.ok_or("--cas-root is required")?;
        let socket = socket.ok_or("--socket is required")?;
        let peer = socket_owner(&socket).map_err(|e| e.to_string())?;
        let inspector = DebInspector::new(InspectorConfig::default()).map_err(|e| e.to_string())?;
        let objects = ObjectReader::open(&cas_root).map_err(|e| e.to_string())?;
        serve_stdio(
            PeerRule::OnlyUid(peer),
            |request: InspectRequest, _uid| -> InspectResponse {
                answer_inspect(&inspector, &objects, &cas_root, request)
            },
        )
        .map_err(|e| e.to_string())
    }
}
