// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::error::ReasonCode;
use crate::ipc::protocol::{ChangeKind, PlanChange};

fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn no_command_can_be_confirmed_from_its_arguments() {
    // A confirmation a script can pass is not a confirmation: `--yes` and
    // its spellings are unknown arguments everywhere (cli-api.md).
    for line in [
        "source add https://github.com/o/r --yes",
        "source activate github-1 --packages a --yes",
        "source activate github-1 --yes --packages a",
        "sync --yes",
        "sync github-1 -y",
        "doctor --repair --yes",
        "source add https://github.com/o/r --assume-yes",
    ] {
        assert!(parse(&words(line)).is_err(), "{line}");
    }
}

#[test]
fn administrative_commands_carry_exactly_their_arguments() -> Result<(), String> {
    assert_eq!(
        parse(&words("source add https://github.com/o/r --observe"))?,
        Command::Admin(AdminAction::SourceAdd(SourceAdd {
            url: "https://github.com/o/r".to_owned(),
            observe: true,
            signer: None,
        }))
    );
    assert_eq!(
        parse(&words(
            "source add https://github.com/o/r --ref refs/heads/main --workflow .github/workflows/release.yml"
        ))?,
        Command::Admin(AdminAction::SourceAdd(SourceAdd {
            url: "https://github.com/o/r".to_owned(),
            observe: false,
            signer: Some(".github/workflows/release.yml@refs/heads/main".to_owned()),
        }))
    );
    assert_eq!(
        parse(&words(
            "source activate github-1 --packages app,app-data --policy preferred"
        ))?,
        Command::Admin(AdminAction::SourceActivate(SourceActivate {
            source_id: "github-1".to_owned(),
            packages: vec!["app".to_owned(), "app-data".to_owned()],
            policy: ActivationPolicy::Preferred,
        }))
    );
    // Without --policy an activation is supplemental, never preferred.
    assert_eq!(
        parse(&words("source activate github-1 --packages app"))?,
        Command::Admin(AdminAction::SourceActivate(SourceActivate {
            source_id: "github-1".to_owned(),
            packages: vec!["app".to_owned()],
            policy: ActivationPolicy::Supplemental,
        }))
    );
    assert_eq!(
        parse(&words("sync github-1 --force"))?,
        Command::Admin(AdminAction::Sync(SyncTarget {
            source_id: Some("github-1".to_owned()),
            force: true,
        }))
    );
    assert_eq!(
        parse(&words("sync"))?,
        Command::Admin(AdminAction::Sync(SyncTarget {
            source_id: None,
            force: false,
        }))
    );
    Ok(())
}

#[test]
fn an_incomplete_or_ambiguous_command_is_refused() {
    for line in [
        "source activate github-1",
        "source activate github-1 --packages",
        "source activate github-1 --packages a,,b",
        "source activate github-1 --packages a --packages b",
        "source activate github-1 --packages a --policy pinned",
        "source add",
        "source add --observe",
        "source add https://github.com/o/r --observe --observe",
        // Half a signer, a signer that is not a workflow file of the
        // repository, or a fixed tag that every release would have to share.
        "source add https://github.com/o/r --workflow .github/workflows/release.yml",
        "source add https://github.com/o/r --ref tag",
        "source add https://github.com/o/r --workflow release.yml --ref tag",
        "source add https://github.com/o/r --workflow .github/workflows/release.yml --ref refs/tags/v1",
        "source add https://github.com/o/r --workflow .github/workflows/a.yml --ref tag --ref tag",
        "source add https://github.com/o/r --workflow",
        "status --json --json",
        "source inspect",
        "sync github-1 github-2",
        "install sampleapp",
        "source remove github-1",
    ] {
        assert!(parse(&words(line)).is_err(), "{line}");
    }
}

#[test]
fn the_plan_shows_every_change_and_its_risks() {
    let plan = PlanView {
        action: AdminAction::Sync(SyncTarget {
            source_id: None,
            force: false,
        }),
        plan_digest: "ab".repeat(32),
        summary: "synchronize 1 source".to_owned(),
        changes: vec![
            PlanChange {
                kind: ChangeKind::WriteFile,
                target: "/etc/apt/preferences.d/pakomichi-app.pref".to_owned(),
                before: Some("11".repeat(32)),
                after: Some("22".repeat(32)),
                risks: vec![ReasonCode::ESourceAmbiguous],
            },
            PlanChange {
                kind: ChangeKind::RemoveFile,
                target: "/etc/apt/sources.list.d/pakomichi-old.sources".to_owned(),
                before: Some("33".repeat(32)),
                after: None,
                risks: Vec::new(),
            },
        ],
    };
    let text = render_plan(&plan);
    assert!(
        text.contains("write_file /etc/apt/preferences.d/pakomichi-app.pref"),
        "{text}"
    );
    assert!(text.contains("RISK: E_SOURCE_AMBIGUOUS"), "{text}");
    assert!(
        text.contains(
            "remove_file /etc/apt/sources.list.d/pakomichi-old.sources (was: 333333333333)"
        ),
        "{text}"
    );
    assert!(text.contains("plan abababababab"), "{text}");
}

#[test]
fn n027_the_status_names_the_other_source_and_every_broken_promise() {
    use crate::ipc::protocol::{AptProblem, UpdateElsewhere};
    let source = SourceStatus {
        source_id: "github-1429307950".to_owned(),
        url: "https://github.com/kroxiksut/pchi-test".to_owned(),
        state: "active".to_owned(),
        trust_floor: Some("attested".to_owned()),
        pinned_consent: false,
        last_verified_at: None,
        signer: None,
        activated: vec!["sampleapp".to_owned()],
        updates_elsewhere: vec![UpdateElsewhere {
            name: "sampleapp".to_owned(),
            version: "1.1-1".to_owned(),
            offered_by: "http://deb.debian.org/debian-security bookworm-security/main".to_owned(),
        }],
        apt_problems: vec![
            AptProblem {
                name: Some("sampleapp-data".to_owned()),
                reason_code: Some(ReasonCode::ESourceAmbiguous),
                message: "sampleapp-data 1.0-1 is also offered elsewhere".to_owned(),
            },
            AptProblem {
                name: None,
                reason_code: None,
                message: "what APT will choose could not be read".to_owned(),
            },
        ],
    };
    let text = render_sources(&[source]);
    assert!(
        text.contains(
            "notice: sampleapp 1.1-1 is offered by \
             http://deb.debian.org/debian-security bookworm-security/main"
        ),
        "{text}"
    );
    assert!(
        text.contains("PROBLEM E_SOURCE_AMBIGUOUS: sampleapp-data 1.0-1 is also offered"),
        "{text}"
    );
    assert!(
        text.contains("PROBLEM: what APT will choose could not be read"),
        "{text}"
    );
}

#[test]
fn doctor_repair_runs_in_the_cli_and_takes_no_confirmation_from_arguments() -> Result<(), String> {
    // N-029: the recovery runs as root in the CLI itself, never through the
    // unprivileged state owner, which may be the unit that is down; the
    // diagnosis alone changes nothing and takes no confirmation.
    assert_eq!(parse(&words("doctor"))?, Command::Doctor);
    assert_eq!(parse(&words("doctor --repair"))?, Command::DoctorRepair);
    for refused in [
        "doctor --yes",
        "doctor --repair --yes",
        "doctor --yes --repair",
        "doctor --repair --repair",
        "doctor now",
    ] {
        assert!(parse(&words(refused)).is_err(), "{refused}");
    }
    Ok(())
}

#[test]
fn pinned_consent_and_approval_take_exactly_their_arguments() -> Result<(), String> {
    use crate::ipc::protocol::{ReleaseApprove, SourceAllowPinned};
    assert_eq!(
        parse(&words("source allow-pinned github-1"))?,
        Command::Admin(AdminAction::SourceAllowPinned(SourceAllowPinned {
            source_id: "github-1".to_owned()
        }))
    );
    assert_eq!(
        parse(&words("release approve github-1 268800123"))?,
        Command::Admin(AdminAction::ReleaseApprove(ReleaseApprove {
            source_id: "github-1".to_owned(),
            release_id: 268_800_123,
        }))
    );
    // No --yes, no tag instead of the release ID, no zero.
    for refused in [
        "source allow-pinned github-1 --yes",
        "release approve github-1 268800123 --yes",
        "release approve github-1 v1.0",
        "release approve github-1 0",
        "release approve github-1",
    ] {
        assert!(parse(&words(refused)).is_err(), "{refused}");
    }
    Ok(())
}
