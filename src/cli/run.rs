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
        Command::Doctor => {
            let findings = super::doctor::diagnose(&doctor_facts());
            print!("{}", super::doctor::render(&findings));
            super::doctor::exit_status(&findings)
        }
        Command::DoctorRepair => repair(),
        Command::Admin(action) => administer(action),
    }
}

/// What `pchi doctor` judges, read without root and without changing
/// anything; a fact that cannot be read is reported as such.
fn doctor_facts() -> super::doctor::Facts {
    use super::doctor::{Facts, UNITS, UnitState, parse_unit};
    let units = UNITS
        .iter()
        .map(|unit| {
            let shown = std::process::Command::new("/usr/bin/systemctl")
                .args([
                    "show",
                    "--property=LoadState,ActiveState,Result,Listen",
                    "--",
                    unit,
                ])
                .env("LC_ALL", "C")
                .output();
            match shown {
                Ok(output) if output.status.success() => {
                    parse_unit(unit, &String::from_utf8_lossy(&output.stdout))
                }
                Ok(output) => UnitState {
                    unit: (*unit).to_owned(),
                    load: format!("unknown (systemctl {})", output.status),
                    ..UnitState::default()
                },
                Err(error) => UnitState {
                    unit: (*unit).to_owned(),
                    load: format!("unknown (systemctl: {error})"),
                    ..UnitState::default()
                },
            }
        })
        .collect();
    let unprivileged_port_start =
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            .ok()
            .and_then(|text| text.trim().parse().ok());
    let status = match status_call(&StatusRequest::Status(Empty {})) {
        Ok(Response::Status(report)) => Ok(report),
        Ok(other) => Err(format!("unexpected answer: {}", encode(&other))),
        Err(error) => Err(error),
    };
    #[cfg(target_os = "linux")]
    let execution_policy = {
        let ecosystem = if std::path::Path::new("/usr/bin/dpkg").exists() {
            crate::inventory::Ecosystem::Deb
        } else {
            crate::inventory::Ecosystem::Rpm
        };
        crate::compat::detect::target(ecosystem)
            .map(|target| target.execution_policy)
            .map_err(|error| error.to_string())
    };
    #[cfg(not(target_os = "linux"))]
    let execution_policy = Err("Pakomichi runs only on Linux".to_owned());
    Facts {
        units,
        unprivileged_port_start,
        status,
        execution_policy,
        now: jiff::Timestamp::now(),
    }
}

/// `yes` typed at a terminal. Anything else, or no terminal, is a refusal,
/// said on stderr.
fn confirmed_at_terminal(prompt: &str) -> bool {
    if !io::stdin().is_terminal() {
        eprintln!("confirming needs an interactive terminal; nothing was changed");
        return false;
    }
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer).is_err() || answer.trim() != "yes" {
        eprintln!("not confirmed; nothing was changed");
        return false;
    }
    true
}

/// `pchi doctor --repair`: the documented recovery of failed units, run by
/// the CLI itself as root (owner decision of 2026-10-25). The state owner is
/// unprivileged and cannot call systemctl, and it may be the unit that is
/// down. Diagnose → show the commands → `yes` at a terminal → run them in
/// order, stop at the first failure → diagnose again.
fn repair() -> u8 {
    use super::doctor::{diagnose, render, render_repair, repair_plan, shell_line, unrepaired};
    #[cfg(target_os = "linux")]
    let uid = crate::process::effective_uid().map_err(|error| error.to_string());
    #[cfg(not(target_os = "linux"))]
    let uid: Result<u32, String> = Err("Pakomichi runs only on Linux".to_owned());
    match uid {
        Ok(0) => {}
        Ok(_) => {
            eprintln!("pchi doctor --repair needs root; nothing was changed");
            return exit::FAILED;
        }
        Err(error) => {
            eprintln!("the effective user is not known ({error}); nothing was changed");
            return exit::FAILED;
        }
    }
    let before = doctor_facts();
    print!("{}", render(&diagnose(&before)));
    let plan = repair_plan(&before);
    print!("{}", render_repair(&plan));
    if plan.is_empty() {
        return exit::OK;
    }
    if !confirmed_at_terminal("Type yes to run these commands: ") {
        return exit::NOT_CONFIRMED;
    }
    let mut status = exit::OK;
    'units: for repair in &plan {
        for arguments in &repair.commands {
            let line = shell_line(arguments);
            if let Err(error) = systemctl(arguments) {
                eprintln!("{line} failed: {error}; the remaining commands were not run");
                status = exit::FAILED;
                break 'units;
            }
            println!("ran: {line}");
        }
    }
    let after = doctor_facts();
    println!("after the repair:");
    print!("{}", render(&diagnose(&after)));
    let left = unrepaired(&plan, &after);
    if !left.is_empty() {
        eprintln!("not repaired: {}", left.join(", "));
        return exit::FAILED;
    }
    status
}

/// `/usr/bin/systemctl <arguments>` with its output captured.
fn systemctl(arguments: &[String]) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(arguments)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
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
    if !confirmed_at_terminal("Type yes to apply this plan: ") {
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
