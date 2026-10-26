// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::ipc::protocol::{AptProblem, SourceStatus, UpdateElsewhere};

const NOW: &str = "2026-10-25T12:00:00Z";
const SOURCE: &str = "github-1429307950";

fn unit(name: &str, active: &str, result: &str) -> UnitState {
    UnitState {
        unit: name.to_owned(),
        load: "loaded".to_owned(),
        active: active.to_owned(),
        result: result.to_owned(),
        listen: if name == READER_SOCKET {
            vec!["127.0.0.1:879 (Stream)".to_owned()]
        } else {
            Vec::new()
        },
    }
}

fn source(last_verified_at: Option<&str>) -> SourceStatus {
    SourceStatus {
        source_id: SOURCE.to_owned(),
        url: "https://github.com/kroxiksut/pchi-test".to_owned(),
        state: "active".to_owned(),
        trust_floor: Some("attested".to_owned()),
        pinned_consent: false,
        last_verified_at: last_verified_at.map(str::to_owned),
        signer: None,
        activated: vec!["sampleapp".to_owned()],
        updates_elsewhere: Vec::new(),
        apt_problems: Vec::new(),
    }
}

/// A healthy installation: every unit up, port 879 protected, a source
/// synchronized an hour ago, no execution policy.
fn healthy() -> Result<Facts, jiff::Error> {
    Ok(Facts {
        units: UNITS
            .iter()
            .map(|name| unit(name, "active", "success"))
            .collect(),
        unprivileged_port_start: Some(1024),
        status: Ok(StatusReport {
            service_version: "0.0.0".to_owned(),
            operations_running: 0,
            loopback_port: Some(879),
            sources: vec![source(Some("2026-10-25T11:00:00Z"))],
        }),
        execution_policy: Ok(ExecutionPolicy::Off),
        now: NOW.parse()?,
    })
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn only(findings: &[Finding], severity: Severity) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .collect()
}

#[test]
fn a_healthy_installation_has_nothing_to_fix() -> TestResult {
    let findings = diagnose(&healthy()?);
    assert_eq!(findings, Vec::new());
    assert_eq!(render(&findings), "no problems found\n");
    assert_eq!(exit_status(&findings), crate::cli::exit::OK);
    Ok(())
}

#[test]
fn n029_a_failed_reader_socket_is_an_outage_with_its_recovery_command() -> TestResult {
    // A crash loop puts the socket into `failed`: it stops listening, and
    // `apt-get update` still exits 0, so only the doctor says so.
    let mut facts = healthy()?;
    facts.units[0] = unit(READER_SOCKET, "failed", "service-start-limit-hit");
    let findings = diagnose(&facts);
    let [outage] = only(&findings, Severity::Problem)[..] else {
        return Err(format!("{findings:?}").into());
    };
    assert!(
        outage.message.contains("Pakomichi repositories are down")
            && outage.message.contains("service-start-limit-hit"),
        "{}",
        outage.message
    );
    let remedy = outage.remedy.as_deref().unwrap_or_default();
    assert!(
        remedy.contains("systemctl reset-failed pakomichi-reader.service pakomichi-reader.socket")
            && remedy.contains("systemctl start pakomichi-reader.socket"),
        "{remedy}"
    );
    assert_eq!(exit_status(&findings), crate::cli::exit::FAILED);
    Ok(())
}

#[test]
fn a_unit_that_is_missing_or_not_listening_is_named() -> TestResult {
    let mut facts = healthy()?;
    facts.units[1] = UnitState {
        load: "not-found".to_owned(),
        ..unit("pakomichi-status.socket", "inactive", "success")
    };
    facts.units[6] = unit("pakomichi-apply.socket", "inactive", "success");
    facts.units[7] = unit("pakomichi-state.service", "failed", "exit-code");
    let findings = diagnose(&facts);
    let problems: Vec<&str> = only(&findings, Severity::Problem)
        .iter()
        .map(|finding| finding.message.as_str())
        .collect();
    assert!(
        problems
            .iter()
            .any(|m| m.contains("pakomichi-status.socket") && m.contains("not installed")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|m| m.contains("pakomichi-apply.socket") && m.contains("not listening")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|m| m.contains("pakomichi-state.service") && m.contains("exit-code")),
        "{problems:?}"
    );
    Ok(())
}

#[test]
fn n034_a_port_that_an_unprivileged_user_can_bind_is_a_risk() -> TestResult {
    // While the socket is down, whoever binds the port answers APT and DNF.
    let mut facts = healthy()?;
    facts.unprivileged_port_start = Some(0);
    let findings = diagnose(&facts);
    let [risk] = only(&findings, Severity::Risk)[..] else {
        return Err(format!("{findings:?}").into());
    };
    assert!(
        risk.message
            .contains("net.ipv4.ip_unprivileged_port_start = 0")
            && risk.message.contains("879"),
        "{}",
        risk.message
    );
    // The first unprivileged port is the port itself: it can be bound.
    facts.unprivileged_port_start = Some(879);
    assert_eq!(only(&diagnose(&facts), Severity::Risk).len(), 1);
    facts.unprivileged_port_start = Some(880);
    assert_eq!(diagnose(&facts), Vec::new());
    // The same when the value cannot be read: unknown is not protected.
    facts.unprivileged_port_start = None;
    assert_eq!(only(&diagnose(&facts), Severity::Risk).len(), 1);
    // A port of 1024 or above is unprotected (owner decision of 2026-10-24),
    // whatever the sysctl says today.
    let mut facts = healthy()?;
    facts.units[0].listen = vec!["127.0.0.1:18080 (Stream)".to_owned()];
    facts.unprivileged_port_start = Some(65535);
    if let Ok(report) = &mut facts.status {
        report.loopback_port = Some(18080);
    }
    let findings = diagnose(&facts);
    let [risk] = only(&findings, Severity::Risk)[..] else {
        return Err(format!("{findings:?}").into());
    };
    assert!(
        risk.message
            .contains("the loopback port 18080 is unprivileged"),
        "{}",
        risk.message
    );
    Ok(())
}

#[test]
fn a_reader_on_another_port_than_the_apt_sources_is_a_problem() -> TestResult {
    let mut facts = healthy()?;
    if let Ok(report) = &mut facts.status {
        report.loopback_port = Some(18080);
    }
    let findings = diagnose(&facts);
    let [mismatch] = only(&findings, Severity::Problem)[..] else {
        return Err(format!("{findings:?}").into());
    };
    assert!(
        mismatch.message.contains("879") && mismatch.message.contains("18080"),
        "{}",
        mismatch.message
    );
    Ok(())
}

#[test]
fn a_service_that_does_not_answer_does_not_stop_the_other_checks() -> TestResult {
    let mut facts = healthy()?;
    facts.status = Err("connection refused".to_owned());
    facts.unprivileged_port_start = Some(0);
    let findings = diagnose(&facts);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::Problem && f.message.contains("connection refused")),
        "{findings:?}"
    );
    assert_eq!(only(&findings, Severity::Risk).len(), 1, "{findings:?}");
    Ok(())
}

#[test]
fn a_source_not_confirmed_within_the_freshness_is_stale() -> TestResult {
    let mut facts = healthy()?;
    if let Ok(report) = &mut facts.status {
        report.sources = vec![source(Some("2026-10-18T11:59:59Z"))];
    }
    let findings = diagnose(&facts);
    let [stale] = only(&findings, Severity::Problem)[..] else {
        return Err(format!("{findings:?}").into());
    };
    assert_eq!(stale.reason, Some(ReasonCode::ESourceStale));
    assert!(
        stale.remedy.as_deref() == Some(&format!("pchi sync {SOURCE}")[..]),
        "{stale:?}"
    );
    // Within the freshness: nothing to fix.
    if let Ok(report) = &mut facts.status {
        report.sources = vec![source(Some("2026-10-18T12:00:01Z"))];
    }
    assert_eq!(diagnose(&facts), Vec::new());
    // Never synchronized: said, and not a problem yet.
    if let Ok(report) = &mut facts.status {
        report.sources = vec![source(None)];
    }
    let findings = diagnose(&facts);
    assert_eq!(only(&findings, Severity::Notice).len(), 1, "{findings:?}");
    assert_eq!(exit_status(&findings), crate::cli::exit::OK);
    Ok(())
}

#[test]
fn n027_updates_elsewhere_are_notices_and_broken_promises_problems() -> TestResult {
    let mut facts = healthy()?;
    if let Ok(report) = &mut facts.status {
        let mut status = source(Some("2026-10-25T11:00:00Z"));
        status.updates_elsewhere = vec![UpdateElsewhere {
            name: "sampleapp".to_owned(),
            version: "9.9.9".to_owned(),
            offered_by: "file:/srv/other ./".to_owned(),
        }];
        status.apt_problems = vec![AptProblem {
            name: Some("sampleapp-data".to_owned()),
            reason_code: Some(ReasonCode::ESourceAmbiguous),
            message: "sampleapp-data 1.0-1 is also offered elsewhere".to_owned(),
        }];
        report.sources = vec![status];
    }
    let findings = diagnose(&facts);
    let [notice] = only(&findings, Severity::Notice)[..] else {
        return Err(format!("{findings:?}").into());
    };
    assert!(
        notice.message.contains("sampleapp 9.9.9") && notice.message.contains("file:/srv/other"),
        "{}",
        notice.message
    );
    let [problem] = only(&findings, Severity::Problem)[..] else {
        return Err(format!("{findings:?}").into());
    };
    assert_eq!(problem.reason, Some(ReasonCode::ESourceAmbiguous));
    // Most severe first.
    assert_eq!(findings[0].severity, Severity::Problem);
    Ok(())
}

#[test]
fn an_execution_policy_that_is_on_or_unknown_holds_everything() -> TestResult {
    for policy in [ExecutionPolicy::On, ExecutionPolicy::Unknown] {
        let mut facts = healthy()?;
        facts.execution_policy = Ok(policy);
        let findings = diagnose(&facts);
        let [problem] = only(&findings, Severity::Problem)[..] else {
            return Err(format!("{policy:?}: {findings:?}").into());
        };
        assert_eq!(problem.reason, Some(ReasonCode::EExecutionPolicy));
    }
    let mut facts = healthy()?;
    facts.execution_policy = Err("no os-release".to_owned());
    let findings = diagnose(&facts);
    assert_eq!(
        only(&findings, Severity::Problem)[0].reason,
        Some(ReasonCode::EPlatformUnsupported)
    );
    Ok(())
}

/// `reset-failed a b` → `["reset-failed", "a", "b"]`.
fn command(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

fn repair(unit: &str, commands: &[&str]) -> Repair {
    Repair {
        unit: unit.to_owned(),
        commands: commands.iter().map(|line| command(line)).collect(),
    }
}

#[test]
fn n029_a_failed_reader_socket_is_repaired_by_exactly_its_recovery() -> TestResult {
    let mut facts = healthy()?;
    facts.units[0] = unit(READER_SOCKET, "failed", "service-start-limit-hit");
    assert_eq!(
        repair_plan(&facts),
        vec![repair(
            READER_SOCKET,
            &[
                "reset-failed pakomichi-reader.service pakomichi-reader.socket",
                "start pakomichi-reader.socket",
            ]
        )]
    );
    Ok(())
}

#[test]
fn a_failed_state_owner_is_reset_and_started_after_its_sockets() -> TestResult {
    // Whatever order systemctl was asked in: sockets first, in `UNITS`
    // order, then the service, which requires them.
    let mut facts = healthy()?;
    facts.units[1] = unit(
        "pakomichi-status.socket",
        "failed",
        "service-start-limit-hit",
    );
    facts.units[7] = unit("pakomichi-state.service", "failed", "start-limit-hit");
    facts.units.reverse();
    assert_eq!(
        repair_plan(&facts),
        vec![
            // The status socket starts the state owner, not a unit of its
            // own name that does not exist.
            repair(
                "pakomichi-status.socket",
                &[
                    "reset-failed pakomichi-state.service pakomichi-status.socket",
                    "start pakomichi-status.socket",
                ]
            ),
            repair(
                "pakomichi-state.service",
                &[
                    "reset-failed pakomichi-state.service",
                    "start pakomichi-state.service",
                ]
            ),
        ]
    );
    Ok(())
}

#[test]
fn only_a_failed_installed_unit_is_repaired() -> TestResult {
    assert_eq!(repair_plan(&healthy()?), Vec::new());
    // A stopped socket was stopped by someone: the documented recovery is
    // for `failed` only (ADR-021 point 3.1), and a missing unit needs the
    // package, not systemctl.
    let mut facts = healthy()?;
    facts.units[0] = unit(READER_SOCKET, "inactive", "success");
    facts.units[1] = UnitState {
        load: "not-found".to_owned(),
        ..unit("pakomichi-status.socket", "failed", "exit-code")
    };
    assert_eq!(repair_plan(&facts), Vec::new());
    Ok(())
}

#[test]
fn every_printed_recovery_names_units_that_exist() -> TestResult {
    // `systemctl reset-failed` refuses a unit that is not loaded, and `&&`
    // then never starts the socket: the status socket starts the state
    // owner, and an accepting socket starts instances of a template.
    let mut facts = healthy()?;
    facts.units[1] = unit(
        "pakomichi-status.socket",
        "failed",
        "service-start-limit-hit",
    );
    facts.units[4] = unit("pakomichi-sign.socket", "failed", "trigger-limit-hit");
    let remedies: Vec<String> = diagnose(&facts)
        .into_iter()
        .filter_map(|finding| finding.remedy)
        .collect();
    assert_eq!(
        remedies,
        vec![
            "systemctl reset-failed pakomichi-state.service pakomichi-status.socket \
             && systemctl start pakomichi-status.socket (as root)"
                .to_owned(),
            "systemctl reset-failed 'pakomichi-sign@*.service' pakomichi-sign.socket \
             && systemctl start pakomichi-sign.socket (as root)"
                .to_owned(),
        ]
    );
    Ok(())
}

#[test]
fn a_repair_that_left_a_unit_failed_is_not_done() -> TestResult {
    let mut facts = healthy()?;
    facts.units[0] = unit(READER_SOCKET, "failed", "service-start-limit-hit");
    let plan = repair_plan(&facts);
    // Still failed, or merely not listening, after the commands.
    assert_eq!(unrepaired(&plan, &facts), vec![READER_SOCKET]);
    facts.units[0] = unit(READER_SOCKET, "inactive", "success");
    assert_eq!(unrepaired(&plan, &facts), vec![READER_SOCKET]);
    // Another unit's problem is not this repair's.
    let mut after = healthy()?;
    after.units[2] = unit("pakomichi-admin.socket", "failed", "exit-code");
    assert_eq!(unrepaired(&plan, &after), Vec::<&str>::new());
    Ok(())
}

#[test]
fn systemctl_show_is_read_by_key() {
    let state = parse_unit(
        READER_SOCKET,
        "LoadState=loaded\nActiveState=failed\nResult=service-start-limit-hit\n\
         Listen=127.0.0.1:879 (Stream)\nUnrelated=x=y\n",
    );
    assert_eq!(
        state,
        UnitState {
            unit: READER_SOCKET.to_owned(),
            load: "loaded".to_owned(),
            active: "failed".to_owned(),
            result: "service-start-limit-hit".to_owned(),
            listen: vec!["127.0.0.1:879 (Stream)".to_owned()],
        }
    );
}
