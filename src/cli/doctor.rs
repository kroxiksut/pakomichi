// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pchi doctor`: what is wrong with this Pakomichi installation, and how to
//! fix it, without changing anything (`specifications/cli-api.md`, ADR-021,
//! ADR-022, ADR-024, ADR-025, ADR-036). `pchi doctor --repair` runs only
//! the documented recovery of failed units, planned here from the same
//! facts.
//!
//! The facts are gathered by `run` (systemd units, a sysctl, the status
//! channel, the execution policy); judging them is portable and pure, so
//! every rule is tested on every target. The doctor works when the service
//! does not answer: that is one of the findings, not a reason to stop. The
//! exit status of `apt-get update` is never used as a health signal.

use std::fmt::Write as _;

use crate::compat::ExecutionPolicy;
use crate::error::ReasonCode;
use crate::ipc::protocol::StatusReport;

/// The units of a Pakomichi installation (P5-004a), sockets first.
pub const UNITS: [&str; 8] = [
    "pakomichi-reader.socket",
    "pakomichi-status.socket",
    "pakomichi-admin.socket",
    "pakomichi-fetch.socket",
    "pakomichi-sign.socket",
    "pakomichi-inspect.socket",
    "pakomichi-apply.socket",
    "pakomichi-state.service",
];

/// The reader's socket: the address APT and DNF talk to.
pub const READER_SOCKET: &str = "pakomichi-reader.socket";

/// What `systemctl show` says about one unit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnitState {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub result: String,
    /// `Listen=` of a socket: `127.0.0.1:879 (Stream)`.
    pub listen: Vec<String>,
}

/// Parses `systemctl show --property=LoadState,ActiveState,Result,Listen`.
pub fn parse_unit(unit: &str, show: &str) -> UnitState {
    let mut state = UnitState {
        unit: unit.to_owned(),
        ..UnitState::default()
    };
    for line in show.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "LoadState" => value.clone_into(&mut state.load),
            "ActiveState" => value.clone_into(&mut state.active),
            "Result" => value.clone_into(&mut state.result),
            "Listen" if !value.is_empty() => state.listen.push(value.to_owned()),
            _ => {}
        }
    }
    state
}

/// Everything the doctor judges.
#[derive(Clone, Debug)]
pub struct Facts {
    pub units: Vec<UnitState>,
    /// `net.ipv4.ip_unprivileged_port_start`; `None` when unreadable.
    pub unprivileged_port_start: Option<u32>,
    /// The answer of `status.sock`, or why there was none.
    pub status: Result<StatusReport, String>,
    /// The operating system's execution policy, or why it is not known.
    pub execution_policy: Result<ExecutionPolicy, String>,
    pub now: jiff::Timestamp,
}

/// How much a finding matters. A problem breaks a promise now; a risk lets
/// someone break one; a notice needs no fix.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Problem,
    Risk,
    Notice,
}

impl Severity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Problem => "PROBLEM",
            Self::Risk => "RISK",
            Self::Notice => "notice",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub reason: Option<ReasonCode>,
    pub message: String,
    /// What to run or change; always shown, never run by the doctor.
    pub remedy: Option<String>,
}

fn finding(
    severity: Severity,
    reason: Option<ReasonCode>,
    message: String,
    remedy: Option<String>,
) -> Finding {
    Finding {
        severity,
        reason,
        message,
        remedy,
    }
}

/// What a socket serves, for the message about it.
fn role(unit: &str) -> &'static str {
    match unit {
        "pakomichi-status.socket" => "`pchi status` and the status API",
        "pakomichi-admin.socket" => "administrative commands",
        "pakomichi-fetch.socket" => "downloads of pinned packages on demand",
        "pakomichi-sign.socket" => "signing of repository metadata",
        "pakomichi-inspect.socket" => "inspection of downloaded packages",
        "pakomichi-apply.socket" => "changes of the APT configuration",
        _ => "Pakomichi",
    }
}

/// What `systemctl reset-failed` resets with a socket: the service it
/// starts (`Service=` of the packaged units), or every instance of the
/// template of an accepting socket. `reset-failed` refuses a unit that is
/// not loaded, so a name derived from the socket's own name would stop the
/// recovery before the socket starts.
fn services_of(socket: &str) -> &'static str {
    match socket {
        READER_SOCKET => "pakomichi-reader.service",
        "pakomichi-sign.socket" => "pakomichi-sign@*.service",
        "pakomichi-inspect.socket" => "pakomichi-inspect@*.service",
        "pakomichi-apply.socket" => "pakomichi-apply@*.service",
        // status, admin, fetch.
        _ => "pakomichi-state.service",
    }
}

/// The documented recovery of a failed unit (ADR-021 point 3.1): its
/// `systemctl` arguments, one command each.
fn recovery(unit: &str) -> Vec<Vec<String>> {
    let reset = if unit.ends_with(".socket") {
        vec!["reset-failed", services_of(unit), unit]
    } else {
        vec!["reset-failed", unit]
    };
    [reset, vec!["start", unit]]
        .into_iter()
        .map(|arguments| arguments.into_iter().map(str::to_owned).collect())
        .collect()
}

/// `systemctl <arguments>` as the administrator would type it; a glob is
/// quoted so that the shell leaves it to systemctl.
pub fn shell_line(arguments: &[String]) -> String {
    let mut line = "systemctl".to_owned();
    for argument in arguments {
        if argument.contains('*') {
            let _ = write!(line, " '{argument}'");
        } else {
            let _ = write!(line, " {argument}");
        }
    }
    line
}

fn check_unit(unit: &UnitState) -> Option<Finding> {
    let name = &unit.unit;
    if unit.load != "loaded" {
        return Some(finding(
            Severity::Problem,
            None,
            format!("{name} is not installed (LoadState={})", unit.load),
            Some("reinstall the Pakomichi package".to_owned()),
        ));
    }
    let is_socket = name.ends_with(".socket");
    let remedy = format!(
        "{} (as root)",
        recovery(name)
            .iter()
            .map(|arguments| shell_line(arguments))
            .collect::<Vec<_>>()
            .join(" && ")
    );
    if unit.active == "failed" {
        let message = if name == READER_SOCKET {
            format!(
                "the Pakomichi repositories are down: {name} failed ({}) and no longer \
                 listens, so APT and DNF cannot reach them",
                unit.result
            )
        } else if is_socket {
            format!(
                "{name} failed ({}): {} is unavailable",
                unit.result,
                role(name)
            )
        } else {
            format!(
                "{name} failed ({}): the state owner does not run",
                unit.result
            )
        };
        return Some(finding(Severity::Problem, None, message, Some(remedy)));
    }
    // A service started by its sockets may be inactive; a socket may not.
    if is_socket && unit.active != "active" {
        return Some(finding(
            Severity::Problem,
            None,
            format!(
                "{name} is not listening ({}): {} is unavailable",
                unit.active,
                role(name)
            ),
            Some(format!("systemctl start {name} (as root)")),
        ));
    }
    None
}

/// The port of `127.0.0.1:879 (Stream)`.
fn listen_port(listen: &str) -> Option<u16> {
    let address = listen.split_whitespace().next()?;
    address.rsplit_once(':')?.1.parse().ok()
}

fn check_port(facts: &Facts, findings: &mut Vec<Finding>) {
    let Some(reader) = facts.units.iter().find(|unit| unit.unit == READER_SOCKET) else {
        return;
    };
    let Some(port) = reader.listen.iter().find_map(|listen| listen_port(listen)) else {
        return;
    };
    let protect = format!(
        "use a port below 1024 (the default is 879) in both the ListenStream= of {READER_SOCKET} \
         and `pakomichi-state --loopback-port`"
    );
    if port >= 1024 {
        findings.push(finding(
            Severity::Risk,
            None,
            format!(
                "the loopback port {port} is unprivileged: while {READER_SOCKET} is down, any \
                 local user can bind it and answer APT and DNF in Pakomichi's place (N-034)"
            ),
            Some(protect),
        ));
    } else {
        match facts.unprivileged_port_start {
            Some(start) if start > u32::from(port) => {}
            Some(start) => findings.push(finding(
                Severity::Risk,
                None,
                format!(
                    "net.ipv4.ip_unprivileged_port_start = {start} lets unprivileged users bind \
                     the loopback port {port}: while {READER_SOCKET} is down, any local user can \
                     answer APT and DNF in Pakomichi's place (N-034)"
                ),
                Some(format!(
                    "sysctl -w net.ipv4.ip_unprivileged_port_start=1024, and keep it above {port} \
                     in /etc/sysctl.d"
                )),
            )),
            None => findings.push(finding(
                Severity::Risk,
                None,
                format!(
                    "net.ipv4.ip_unprivileged_port_start could not be read, so it cannot be ruled \
                     out that unprivileged users may bind the loopback port {port} (N-034)"
                ),
                None,
            )),
        }
    }
    if let Ok(StatusReport {
        loopback_port: Some(published),
        ..
    }) = &facts.status
        && *published != port
    {
        findings.push(finding(
            Severity::Problem,
            None,
            format!(
                "{READER_SOCKET} listens on port {port}, but the APT sources of Pakomichi name \
                 port {published}: APT cannot reach the repositories"
            ),
            Some(
                "set the same port in a drop-in for the socket's ListenStream= and in \
                 `pakomichi-state --loopback-port`"
                    .to_owned(),
            ),
        ));
    }
}

fn check_sources(report: &StatusReport, now: jiff::Timestamp, findings: &mut Vec<Finding>) {
    let freshness = jiff::SignedDuration::from_secs(
        i64::try_from(crate::publish::MAX_FRESHNESS_SECONDS).unwrap_or(i64::MAX),
    );
    for source in &report.sources {
        let id = &source.source_id;
        let sync = Some(format!("pchi sync {id}"));
        match source.last_verified_at.as_deref() {
            None => findings.push(finding(
                Severity::Notice,
                None,
                format!("{id} has not been synchronized yet"),
                sync.clone(),
            )),
            Some(at) => match at.parse::<jiff::Timestamp>() {
                Ok(at) if now.duration_since(at) <= freshness => {}
                Ok(_) => findings.push(finding(
                    Severity::Problem,
                    Some(ReasonCode::ESourceStale),
                    format!(
                        "{id} was last confirmed at {at}, longer ago than the maximum freshness \
                         of {} days: its metadata is served as stale",
                        crate::publish::MAX_FRESHNESS_SECONDS / 86_400
                    ),
                    sync.clone(),
                )),
                Err(_) => findings.push(finding(
                    Severity::Problem,
                    Some(ReasonCode::ESourceStale),
                    format!("{id}: the time of its last confirmation ({at}) cannot be read"),
                    sync.clone(),
                )),
            },
        }
        for update in &source.updates_elsewhere {
            findings.push(finding(
                Severity::Notice,
                None,
                format!(
                    "{id}: {} {} is offered by {}; the publisher stays until you switch it",
                    update.name, update.version, update.offered_by
                ),
                None,
            ));
        }
        for problem in &source.apt_problems {
            findings.push(finding(
                Severity::Problem,
                problem.reason_code,
                format!("{id}: {}", problem.message),
                None,
            ));
        }
    }
}

fn check_execution_policy(policy: &Result<ExecutionPolicy, String>, findings: &mut Vec<Finding>) {
    let message = match policy {
        Ok(ExecutionPolicy::Off) => return,
        Ok(ExecutionPolicy::On) => "the operating system's execution policy is on".to_owned(),
        Ok(ExecutionPolicy::Unknown) => {
            "the operating system's execution policy cannot be ruled out".to_owned()
        }
        Err(detail) => {
            findings.push(finding(
                Severity::Problem,
                Some(ReasonCode::EPlatformUnsupported),
                format!("this system could not be identified: {detail}"),
                None,
            ));
            return;
        }
    };
    findings.push(finding(
        Severity::Problem,
        Some(ReasonCode::EExecutionPolicy),
        format!(
            "{message} (on Astra Linux the closed software environment): every artifact is held \
             and sources are not activated (ADR-025)"
        ),
        None,
    ));
}

/// Judges `facts`, most severe first.
pub fn diagnose(facts: &Facts) -> Vec<Finding> {
    let mut findings: Vec<Finding> = facts.units.iter().filter_map(check_unit).collect();
    check_port(facts, &mut findings);
    match &facts.status {
        Ok(report) => check_sources(report, facts.now, &mut findings),
        Err(error) => findings.push(finding(
            Severity::Problem,
            None,
            format!("the state owner does not answer on status.sock: {error}"),
            Some("systemctl status pakomichi-state.service pakomichi-status.socket".to_owned()),
        )),
    }
    check_execution_policy(&facts.execution_policy, &mut findings);
    // Stable: most severe first, then in the order found.
    findings.sort_by_key(|finding| finding.severity);
    findings
}

/// The report as the administrator reads it.
pub fn render(findings: &[Finding]) -> String {
    let mut text = String::new();
    if findings.is_empty() {
        text.push_str("no problems found\n");
    }
    for finding in findings {
        let code = finding
            .reason
            .map_or_else(String::new, |code| format!(" {}", code.as_str()));
        let _ = writeln!(
            text,
            "{}{code}: {}",
            finding.severity.as_str(),
            finding.message
        );
        if let Some(remedy) = &finding.remedy {
            let _ = writeln!(text, "  fix: {remedy}");
        }
    }
    text
}

/// The recovery of one failed unit, as `pchi doctor --repair` runs it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Repair {
    pub unit: String,
    /// The arguments of `/usr/bin/systemctl`, one command each, in order.
    pub commands: Vec<Vec<String>>,
}

/// What `pchi doctor --repair` runs: the documented recovery of every
/// installed unit in `failed` (ADR-021 point 3.1), sockets first in `UNITS`
/// order, then the state owner, which requires its sockets. A unit that is
/// merely stopped was stopped by someone, and a missing one needs the
/// package: neither is repaired.
pub fn repair_plan(facts: &Facts) -> Vec<Repair> {
    UNITS
        .iter()
        .filter(|name| {
            facts
                .units
                .iter()
                .any(|unit| unit.unit == **name && unit.load == "loaded" && unit.active == "failed")
        })
        .map(|name| Repair {
            unit: (*name).to_owned(),
            commands: recovery(name),
        })
        .collect()
}

/// The units of `plan` that still have a problem in `after`: failed, not
/// listening, or not reported at all.
pub fn unrepaired<'a>(plan: &'a [Repair], after: &Facts) -> Vec<&'a str> {
    plan.iter()
        .filter(|repair| {
            after
                .units
                .iter()
                .find(|unit| unit.unit == repair.unit)
                .is_none_or(|unit| check_unit(unit).is_some())
        })
        .map(|repair| repair.unit.as_str())
        .collect()
}

/// The plan as the administrator reads it before confirming.
pub fn render_repair(plan: &[Repair]) -> String {
    if plan.is_empty() {
        return "nothing to repair\n".to_owned();
    }
    let mut text = "the recovery runs, in this order:\n".to_owned();
    for repair in plan {
        for arguments in &repair.commands {
            let _ = writeln!(text, "  {}", shell_line(arguments));
        }
    }
    text
}

/// `0` when nothing needs fixing (notices only), `1` otherwise.
pub fn exit_status(findings: &[Finding]) -> u8 {
    if findings
        .iter()
        .any(|finding| finding.severity != Severity::Notice)
    {
        super::exit::FAILED
    } else {
        super::exit::OK
    }
}

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
