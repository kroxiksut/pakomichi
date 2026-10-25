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
