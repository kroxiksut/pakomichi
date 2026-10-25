// SPDX-License-Identifier: MIT OR Apache-2.0

//! Talking to the state owner over `status.sock` and `admin.sock`.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use super::{Command, exit, render_outcome, render_plan, render_sources, render_status};
use crate::ipc::oneshot::call;
use crate::ipc::protocol::{
    AdminAction, AdminRequest, ConfirmRequest, Empty, OperationQuery, OperationState, PlanRequest,
    Response, StatusRequest, encode,
};

/// The runtime directory of the sockets (ADR-029 point 1).
const RUNTIME_DIR: &str = "/run/pakomichi";
/// For a test bed only: another directory with the same sockets.
const RUNTIME_DIR_VARIABLE: &str = "PAKOMICHI_RUNTIME_DIR";
const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(500);
/// How long the CLI follows an operation before it gives the identifier
/// back to the user.
const FOLLOW: Duration = Duration::from_secs(30 * 60);

fn socket(name: &str) -> PathBuf {
    let directory = std::env::var_os(RUNTIME_DIR_VARIABLE)
        .map_or_else(|| PathBuf::from(RUNTIME_DIR), PathBuf::from);
    directory.join(name)
}

fn status_call(request: &StatusRequest) -> Result<Response, String> {
    call(&socket("status.sock"), request, TIMEOUT).map_err(|error| error.to_string())
}

fn admin_call(request: &AdminRequest) -> Result<Response, String> {
    call(&socket("admin.sock"), request, TIMEOUT).map_err(|error| error.to_string())
}

fn unavailable(error: &str) -> u8 {
    eprintln!("the Pakomichi service did not answer: {error}");
    exit::UNAVAILABLE
}

fn unexpected(response: &Response) -> u8 {
    match response {
        Response::Error(body) => eprintln!("refused: {}", body.message),
        Response::Refused(refusal) => match refusal.reason_code {
            Some(code) => eprintln!("refused [{}]: {}", code.as_str(), refusal.message),
            None => eprintln!("refused: {}", refusal.message),
        },
        other => eprintln!("unexpected answer: {}", encode(other)),
    }
    exit::FAILED
}

pub fn execute(command: &Command) -> u8 {
    match command {
        Command::Help => exit::OK,
        Command::Status { json } => match status_call(&StatusRequest::Status(Empty {})) {
            Ok(Response::Status(report)) => {
                if *json {
                    println!("{}", encode(&Response::Status(report)));
                } else {
                    print!("{}", render_status(&report));
                }
                exit::OK
            }
            Ok(other) => unexpected(&other),
            Err(error) => unavailable(&error),
        },
        Command::SourceList { json } | Command::SourceInspect { json, .. } => {
            let report = match status_call(&StatusRequest::Status(Empty {})) {
                Ok(Response::Status(report)) => report,
                Ok(other) => return unexpected(&other),
                Err(error) => return unavailable(&error),
            };
            let sources: Vec<_> = match command {
                Command::SourceInspect { source_id, .. } => report
                    .sources
                    .into_iter()
                    .filter(|source| &source.source_id == source_id)
                    .collect(),
                _ => report.sources,
            };
            if sources.is_empty() && matches!(command, Command::SourceInspect { .. }) {
                eprintln!("no such source");
                return exit::FAILED;
            }
            if *json {
                println!("{}", serde_json::to_string(&sources).unwrap_or_default());
            } else {
                print!("{}", render_sources(&sources));
            }
            exit::OK
        }
        Command::Admin(action) => administer(action),
    }
}

/// Plan → show → `yes` at a terminal → confirm → follow the operation.
fn administer(action: &AdminAction) -> u8 {
    let plan = match admin_call(&AdminRequest::Plan(PlanRequest {
        action: action.clone(),
    })) {
        Ok(Response::Plan(plan)) => plan,
        Ok(other) => return unexpected(&other),
        Err(error) => return unavailable(&error),
    };
    print!("{}", render_plan(&plan));
    if !io::stdin().is_terminal() {
        eprintln!("confirming needs an interactive terminal; nothing was changed");
        return exit::NOT_CONFIRMED;
    }
    print!("Type yes to apply this plan: ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer).is_err() || answer.trim() != "yes" {
        eprintln!("not confirmed; nothing was changed");
        return exit::NOT_CONFIRMED;
    }
    let operation = match admin_call(&AdminRequest::Confirm(ConfirmRequest {
        plan_digest: plan.plan_digest,
        confirmed: true,
    })) {
        Ok(Response::Started(started)) => started.operation_id,
        Ok(other) => return unexpected(&other),
        Err(error) => return unavailable(&error),
    };
    follow(&operation)
}

fn follow(operation: &str) -> u8 {
    let started = Instant::now();
    loop {
        let view = match admin_call(&AdminRequest::Operation(OperationQuery {
            operation_id: operation.to_owned(),
        })) {
            Ok(Response::Operation(view)) => view,
            Ok(other) => return unexpected(&other),
            Err(error) => return unavailable(&error),
        };
        match (view.state, &view.outcome) {
            (OperationState::Succeeded, outcome) => {
                if let Some(outcome) = outcome {
                    print!("{}", render_outcome(outcome));
                }
                return exit::OK;
            }
            (OperationState::Failed, outcome) => {
                if let Some(outcome) = outcome {
                    eprint!("{}", render_outcome(outcome));
                }
                return exit::FAILED;
            }
            (OperationState::Queued | OperationState::Running, _) => {}
        }
        if started.elapsed() > FOLLOW {
            eprintln!("still running; follow it with the operation identifier {operation}");
            return exit::FAILED;
        }
        thread::sleep(POLL);
    }
}
