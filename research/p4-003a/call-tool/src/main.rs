// SPDX-License-Identifier: MIT OR Apache-2.0
//! Drives the state owner's side of an APT apply against the real root
//! applier on `apply.sock` (P4-003a research tool).
//!
//! ```text
//! p4003a-call apply DB SOCKET CONFIG.json
//! p4003a-call recover DB SOCKET
//! p4003a-call begin-only DB CONFIG.json        # intent written, applier never asked
//! p4003a-call lose-answer DB SOCKET CONFIG.json  # applier asked, answer dropped
//! p4003a-call raw SOCKET FRAME.json            # one frame as is; prints the answer
//! p4003a-call status DB
//! ```
//!
//! CONFIG.json is an `AptConfigWire`. Prints one result line; exit 0 on a
//! verified or reconciled apply (or a printed answer), 3 otherwise.

use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use pakomichi::apt::config::Desired;
use pakomichi::apt::operation::{Applier, Ended, SocketApplier, apply_apt, recover_apt};
use pakomichi::apt::wire::{desired_from_wire, desired_to_wire, digests_to_wire};
use pakomichi::ipc::channels::{AptConfigWire, ApplyApt, ApplyRequest};
use pakomichi::ipc::frame::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, read_frame, write_frame};
use pakomichi::state::StateOwner;

fn main() -> ExitCode {
    match run() {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(line) => {
            println!("{line}");
            ExitCode::from(3)
        }
    }
}

fn now() -> String {
    jiff::Timestamp::now().to_string()
}

fn config(path: &str) -> Result<Desired, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("usage: {path}: {e}"))?;
    let wire: AptConfigWire = serde_json::from_str(&text).map_err(|e| format!("usage: {e}"))?;
    desired_from_wire(&wire).map_err(|e| format!("usage: {e}"))
}

fn applier(socket: &str) -> SocketApplier {
    SocketApplier {
        path: socket.into(),
        timeout: Duration::from_secs(300),
    }
}

fn ended(ended: &Ended) -> Result<String, String> {
    match ended {
        Ended::Verified { changed } => Ok(format!("verified changed={}", changed.len())),
        Ended::Reconciled => Ok("reconciled".to_owned()),
        Ended::RolledBack {
            reason_code,
            message,
        } => Err(format!("rolled_back {reason_code} {message}")),
        Ended::Drifted { drift } => Err(format!(
            "drifted {}",
            drift
                .iter()
                .map(|d| format!("{}:{}", d.kind, d.path))
                .collect::<Vec<_>>()
                .join(",")
        )),
        Ended::Invalid { message } => Err(format!("invalid {message}")),
        Ended::Failed {
            reason_code,
            message,
        } => Err(format!("failed {reason_code} {message}")),
    }
}

fn random_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .map_err(|e| e.to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Writes an intent the way `apply_apt` does and returns its request.
fn begin(owner: &mut StateOwner, desired: &Desired) -> Result<ApplyRequest, String> {
    let state = owner.apt_state().map_err(|e| e.to_string())?;
    let previous = state
        .last_good
        .unwrap_or_else(|| Desired::empty(desired.port));
    let target = desired.digests().map_err(|e| e.to_string())?.0;
    let id = random_id()?;
    owner
        .begin_apt_operation(&id, desired, &previous, &state.known, &target, &now())
        .map_err(|e| e.to_string())?;
    Ok(ApplyRequest::ApplyApt(ApplyApt {
        operation_id: id,
        desired: desired_to_wire(desired),
        previous: desired_to_wire(&previous),
        known: digests_to_wire(&state.known),
    }))
}

fn raw(socket: &str, frame: &str) -> Result<String, String> {
    let body = std::fs::read_to_string(frame).map_err(|e| format!("usage: {e}"))?;
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    write_frame(&mut stream, body.trim_end(), MAX_REQUEST_BYTES).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| e.to_string())?;
    match read_frame(&mut stream, MAX_RESPONSE_BYTES) {
        Ok(text) => Ok(format!("answer {text}")),
        Err(error) => Err(format!("closed {error}")),
    }
}

fn run() -> Result<String, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let argument = |index: usize| {
        arguments
            .get(index)
            .cloned()
            .ok_or("usage: missing argument".to_owned())
    };
    let command = argument(0)?;
    if command == "raw" {
        return raw(&argument(1)?, &argument(2)?);
    }
    let mut owner = StateOwner::open(Path::new(&argument(1)?)).map_err(|e| e.to_string())?;
    match command.as_str() {
        "apply" => {
            let desired = config(&argument(3)?)?;
            match apply_apt(&mut owner, &applier(&argument(2)?), &desired, &now()) {
                Ok(result) => ended(&result),
                Err(error) => Err(format!("error {error}")),
            }
        }
        "recover" => {
            let finished =
                recover_apt(&mut owner, &applier(&argument(2)?), &now()).map_err(|e| e.to_string())?;
            let mut lines = Vec::new();
            let mut ok = true;
            for (id, result) in &finished {
                match ended(result) {
                    Ok(line) => lines.push(format!("{id} {line}")),
                    Err(line) => {
                        ok = false;
                        lines.push(format!("{id} {line}"));
                    }
                }
            }
            let line = format!("recovered {} {}", finished.len(), lines.join("; "));
            if ok { Ok(line) } else { Err(line) }
        }
        "begin-only" => {
            let desired = config(&argument(2)?)?;
            begin(&mut owner, &desired).map(|_| "planned".to_owned())
        }
        "lose-answer" => {
            let desired = config(&argument(3)?)?;
            let request = begin(&mut owner, &desired)?;
            // The applier runs; its answer never reaches the journal.
            let answer = applier(&argument(2)?).call(&request);
            Ok(format!("answer dropped ({})", if answer.is_ok() { "received" } else { "none" }))
        }
        "status" => {
            let open = owner
                .unfinished_apt_operations()
                .map_err(|e| e.to_string())?;
            let state = owner.apt_state();
            Ok(format!(
                "open={} known={}",
                open.len(),
                state.map(|s| s.known.len().to_string()).unwrap_or_else(|_| "-".into())
            ))
        }
        other => Err(format!("usage: unknown command {other}")),
    }
}
