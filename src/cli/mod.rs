// SPDX-License-Identifier: MIT OR Apache-2.0

//! The command line of `pchi` and `pakomichi` (`specifications/cli-api.md`).
//!
//! One implementation for both entry points: each binary calls [`main`].
//! Parsing and printing are portable; talking to the service is Unix only.
//! Read-only commands use `status.sock`; administrative ones use
//! `admin.sock`, show the server's plan, and ask the administrator to type
//! `yes` at a terminal. There is no `--yes`: a confirmation that a script
//! could give is not a confirmation (ADR-029 point 8). `doctor --repair`
//! is the exception to the channel: it runs `systemctl` in the CLI as root,
//! because the state owner is unprivileged and may be the unit that is down.

use std::fmt::Write as _;

use crate::attest::{AttestedSigner, SignerRef};
use crate::ipc::protocol::{
    ActivationPolicy, AdminAction, OperationOutcome, PlanView, ReleaseApprove, SourceActivate,
    SourceAdd, SourceAllowPinned, SourceStatus, StatusReport, SyncTarget,
};

pub mod doctor;
#[cfg(unix)]
mod run;

/// Exit statuses of the CLI.
pub mod exit {
    pub const OK: u8 = 0;
    /// The server refused the action, or the operation failed.
    pub const FAILED: u8 = 1;
    pub const USAGE: u8 = 2;
    /// Not confirmed, or no terminal to confirm at; nothing was changed.
    pub const NOT_CONFIRMED: u8 = 3;
    /// The service did not answer.
    pub const UNAVAILABLE: u8 = 4;
}

/// What the user asked for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Status {
        json: bool,
    },
    SourceList {
        json: bool,
    },
    SourceInspect {
        source_id: String,
        json: bool,
    },
    /// `pchi doctor`: diagnoses, changes nothing.
    Doctor,
    /// `pchi doctor --repair`: the socket recovery, run by the CLI itself as
    /// root after a confirmation at a terminal, never by the service.
    DoctorRepair,
    Admin(AdminAction),
    Help,
}

pub const USAGE: &str = "\
usage:
  pchi source add <https-git-url> [--observe] [--workflow <path> --ref tag|refs/heads/<name>]
  pchi source list [--json]
  pchi source inspect <id> [--json]
  pchi source activate <id> --packages <comma-list> [--policy supplemental|preferred]
  pchi source allow-pinned <id>
  pchi release approve <source-id> <release-id>
  pchi sync [<id>] [--force]
  pchi status [--json]
  pchi doctor
  pchi doctor --repair
";

fn usage(problem: &str) -> String {
    format!("{problem}\n{USAGE}")
}

/// Parses the arguments after the program name.
pub fn parse(arguments: &[String]) -> Result<Command, String> {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let flag = |name: &str| words.contains(&name);
    match words.as_slice() {
        [] | ["help"] | ["--help"] | ["-h"] => Ok(Command::Help),
        ["status", rest @ ..] => {
            only_flags(rest, &["--json"])?;
            Ok(Command::Status {
                json: flag("--json"),
            })
        }
        ["source", "list", rest @ ..] => {
            only_flags(rest, &["--json"])?;
            Ok(Command::SourceList {
                json: flag("--json"),
            })
        }
        ["source", "inspect", id, rest @ ..] if !id.starts_with('-') => {
            only_flags(rest, &["--json"])?;
            Ok(Command::SourceInspect {
                source_id: (*id).to_owned(),
                json: flag("--json"),
            })
        }
        ["source", "add", url, rest @ ..] if !url.starts_with('-') => {
            let mut observe = false;
            let mut workflow = None;
            let mut source_ref = None;
            let mut index = 0;
            while index < rest.len() {
                match (rest[index], rest.get(index + 1)) {
                    ("--observe", _) if !observe => {
                        observe = true;
                        index += 1;
                        continue;
                    }
                    ("--workflow", Some(value)) if workflow.is_none() => workflow = Some(*value),
                    ("--ref", Some(value)) if source_ref.is_none() => source_ref = Some(*value),
                    (other, _) => return Err(usage(&format!("unexpected {other}"))),
                }
                index += 2;
            }
            // The two name one signer: half of it is not a signer.
            let signer = match (workflow, source_ref) {
                (None, None) => None,
                (Some(workflow), Some(source_ref)) => {
                    let rule = SignerRef::parse(source_ref)
                        .map_err(|_| usage("--ref is tag or refs/heads/<branch>"))?;
                    let signer = AttestedSigner::new(workflow, rule).map_err(|_| {
                        usage("--workflow is .github/workflows/<file>.yml or .yaml")
                    })?;
                    Some(signer.to_string())
                }
                _ => return Err(usage("--workflow and --ref go together")),
            };
            Ok(Command::Admin(AdminAction::SourceAdd(SourceAdd {
                url: (*url).to_owned(),
                observe,
                signer,
            })))
        }
        ["source", "allow-pinned", id] if !id.starts_with('-') => Ok(Command::Admin(
            AdminAction::SourceAllowPinned(SourceAllowPinned {
                source_id: (*id).to_owned(),
            }),
        )),
        ["release", "approve", id, release] if !id.starts_with('-') => {
            let release_id = release
                .parse::<u64>()
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| usage("the release id is the forge's positive number"))?;
            Ok(Command::Admin(AdminAction::ReleaseApprove(
                ReleaseApprove {
                    source_id: (*id).to_owned(),
                    release_id,
                },
            )))
        }
        ["source", "activate", id, rest @ ..] if !id.starts_with('-') => {
            let mut packages = None;
            let mut policy = ActivationPolicy::Supplemental;
            let mut index = 0;
            while index < rest.len() {
                match (rest[index], rest.get(index + 1)) {
                    ("--packages", Some(list)) if packages.is_none() => {
                        let names: Vec<String> = list.split(',').map(str::to_owned).collect();
                        if names.iter().any(String::is_empty) {
                            return Err(usage("--packages has an empty name"));
                        }
                        packages = Some(names);
                    }
                    ("--policy", Some(&"supplemental")) => policy = ActivationPolicy::Supplemental,
                    ("--policy", Some(&"preferred")) => policy = ActivationPolicy::Preferred,
                    (other, _) => return Err(usage(&format!("unexpected {other}"))),
                }
                index += 2;
            }
            Ok(Command::Admin(AdminAction::SourceActivate(
                SourceActivate {
                    source_id: (*id).to_owned(),
                    packages: packages.ok_or_else(|| usage("--packages is required"))?,
                    policy,
                },
            )))
        }
        ["sync", rest @ ..] => {
            let (id, flags) = match rest {
                [id, flags @ ..] if !id.starts_with('-') => (Some((*id).to_owned()), flags),
                flags => (None, flags),
            };
            only_flags(flags, &["--force"])?;
            Ok(Command::Admin(AdminAction::Sync(SyncTarget {
                source_id: id,
                force: flag("--force"),
            })))
        }
        ["doctor"] => Ok(Command::Doctor),
        ["doctor", "--repair"] => Ok(Command::DoctorRepair),
        _ => Err(usage("unknown command")),
    }
}

fn only_flags(words: &[&str], allowed: &[&str]) -> Result<(), String> {
    for (index, word) in words.iter().enumerate() {
        if !allowed.contains(word) || words[..index].contains(word) {
            return Err(usage(&format!("unexpected {word}")));
        }
    }
    Ok(())
}

/// The plan as the administrator reads it before confirming.
pub fn render_plan(plan: &PlanView) -> String {
    let mut text = format!("{}\n", plan.summary);
    if plan.changes.is_empty() {
        text.push_str("  no changes\n");
    }
    for change in &plan.changes {
        let kind = serde_json::to_value(change.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        let _ = write!(text, "  {kind} {}", change.target);
        match (&change.before, &change.after) {
            (Some(before), Some(after)) => {
                let _ = write!(text, " ({} -> {})", short(before), short(after));
            }
            (None, Some(after)) => {
                let _ = write!(text, " (new: {})", short(after));
            }
            (Some(before), None) => {
                let _ = write!(text, " (was: {})", short(before));
            }
            (None, None) => {}
        }
        if !change.risks.is_empty() {
            let risks: Vec<&str> = change.risks.iter().map(|code| code.as_str()).collect();
            let _ = write!(text, " RISK: {}", risks.join(", "));
        }
        text.push('\n');
    }
    let _ = writeln!(text, "plan {}", short(&plan.plan_digest));
    text
}

/// A digest shortened for reading; the full one is what is confirmed.
fn short(value: &str) -> &str {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        &value[..12]
    } else {
        value
    }
}

pub fn render_outcome(outcome: &OperationOutcome) -> String {
    if outcome.reason_codes.is_empty() {
        format!("{}\n", outcome.message)
    } else {
        let codes: Vec<&str> = outcome.reason_codes.iter().map(|c| c.as_str()).collect();
        format!("{} [{}]\n", outcome.message, codes.join(", "))
    }
}

fn render_source(source: &SourceStatus) -> String {
    let mut text = render_source_line(source);
    for update in &source.updates_elsewhere {
        text.push_str(&format!(
            "  notice: {} {} is offered by {}; the publisher stays until you switch it\n",
            update.name, update.version, update.offered_by
        ));
    }
    for problem in &source.apt_problems {
        match problem.reason_code {
            Some(code) => text.push_str(&format!(
                "  PROBLEM {}: {}\n",
                code.as_str(),
                problem.message
            )),
            None => text.push_str(&format!("  PROBLEM: {}\n", problem.message)),
        }
    }
    text
}

fn render_source_line(source: &SourceStatus) -> String {
    format!(
        "{}  {}  state={}  floor={}  signer={}  pinned_consent={}  activated={}\n",
        source.source_id,
        source.url,
        source.state,
        source.trust_floor.as_deref().unwrap_or("-"),
        source.signer.as_deref().unwrap_or("none"),
        if source.pinned_consent { "yes" } else { "no" },
        if source.activated.is_empty() {
            "-".to_owned()
        } else {
            source.activated.join(",")
        },
    )
}

pub fn render_status(report: &StatusReport) -> String {
    let mut text = format!(
        "pakomichi {}; operations running: {}\n",
        report.service_version, report.operations_running
    );
    if report.sources.is_empty() {
        text.push_str("no sources\n");
    }
    for source in &report.sources {
        text.push_str(&render_source(source));
    }
    text
}

pub fn render_sources(sources: &[SourceStatus]) -> String {
    sources.iter().map(render_source).collect()
}

/// Runs the CLI and returns its exit status.
pub fn main() -> u8 {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&arguments) {
        Ok(command) => command,
        Err(message) => {
            eprint!("{message}");
            return exit::USAGE;
        }
    };
    if command == Command::Help {
        print!("{USAGE}");
        return exit::OK;
    }
    #[cfg(unix)]
    {
        run::execute(&command)
    }
    #[cfg(not(unix))]
    {
        eprintln!("pakomichi runs only on Linux");
        exit::UNAVAILABLE
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
