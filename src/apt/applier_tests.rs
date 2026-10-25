// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use super::*;
use crate::apt::config::{LogicalSource, SourceConfig, sources_path};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PORT: u16 = 18080;
const DEBIAN_SOURCES: &str = "etc/apt/sources.list.d/debian.sources";

fn config(names: &[&str]) -> Desired {
    Desired {
        port: PORT,
        keyring: b"keyring v1".to_vec(),
        sources: vec![SourceConfig {
            source_key: "sampleapp".to_owned(),
            repositories: vec![LogicalSource {
                label: "pakomichi-sampleapp-strict".to_owned(),
                activated: names.iter().map(|name| (*name).to_owned()).collect(),
            }],
        }],
    }
}

/// A configuration that changes all three files of `config(&["sampleapp"])`:
/// a new keyring, a second logical repository, and its pin.
fn changed_everywhere() -> Desired {
    let mut desired = config(&["sampleapp"]);
    desired.keyring = b"keyring v2".to_vec();
    desired.sources[0].repositories.push(LogicalSource {
        label: "pakomichi-sampleapp-attested".to_owned(),
        activated: ["sampleapp-data".to_owned()].into_iter().collect(),
    });
    desired
}

/// APT's answers, in order; then it accepts.
struct Apt(RefCell<Vec<Result<(), String>>>);

impl Apt {
    fn accepts() -> Self {
        Self(RefCell::new(Vec::new()))
    }

    fn refuses_once() -> Self {
        Self(RefCell::new(vec![Err(
            "E: Conflicting values set for option Signed-By".to_owned(),
        )]))
    }
}

impl AptCheck for Apt {
    fn check(&self) -> Result<(), String> {
        let mut answers = self.0.borrow_mut();
        if answers.is_empty() {
            Ok(())
        } else {
            answers.remove(0)
        }
    }
}

/// A root with the distribution's own sources file.
fn system() -> Result<(TempDir, PathBuf), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = dir.join("root");
    fs::create_dir_all(root.join("etc/apt/sources.list.d"))?;
    fs::create_dir_all(root.join("etc/apt/preferences.d"))?;
    fs::write(root.join(DEBIAN_SOURCES), "Types: deb\n")?;
    Ok((dir, root))
}

/// Every file under `root` with its bytes, staging files included.
fn tree(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                let name = entry.path().strip_prefix(root)?.display().to_string();
                files.insert(name, fs::read(entry.path())?);
            }
        }
    }
    Ok(files)
}

type Tree = BTreeMap<String, Vec<u8>>;

/// The system after `previous` was applied cleanly.
fn applied(
    previous: &Desired,
) -> Result<(TempDir, PathBuf, Known, Tree), Box<dyn std::error::Error>> {
    let (dir, root) = system()?;
    let known = match apply(
        &root,
        previous,
        &Desired::empty(PORT),
        Known::default(),
        &Apt::accepts(),
    ) {
        Outcome::Applied { known, .. } => known,
        other => return Err(format!("setup: {other:?}").into()),
    };
    let before = tree(&root)?;
    Ok((dir, root, known, before))
}

#[test]
fn an_apply_leaves_exactly_the_rendered_files_and_records_them() -> TestResult {
    let (_dir, root) = system()?;
    let desired = config(&["sampleapp"]);
    let outcome = apply(
        &root,
        &desired,
        &Desired::empty(PORT),
        Known::default(),
        &Apt::accepts(),
    );
    let Outcome::Applied { known, changed } = outcome else {
        return Err(format!("{outcome:?}").into());
    };
    assert_eq!(known, desired.digests()?);
    assert_eq!(changed.len(), 3);
    let files = tree(&root)?;
    let mut expected: BTreeMap<String, Vec<u8>> = desired
        .render()?
        .into_iter()
        .map(|file| (file.path.trim_start_matches('/').to_owned(), file.bytes))
        .collect();
    expected.insert(DEBIAN_SOURCES.to_owned(), b"Types: deb\n".to_vec());
    assert_eq!(files, expected, "nothing else written, no staging left");
    Ok(())
}

#[test]
fn a_configuration_apt_refuses_is_rolled_back_byte_for_byte() -> TestResult {
    let previous = config(&["sampleapp"]);
    let (_dir, root, known, before) = applied(&previous)?;
    let desired = changed_everywhere();
    let outcome = apply(&root, &desired, &previous, known, &Apt::refuses_once());
    let Outcome::RolledBack {
        known,
        reason,
        detail,
    } = outcome
    else {
        return Err(format!("{outcome:?}").into());
    };
    assert_eq!(reason, ReasonCode::EAdminApplyFailed);
    assert!(detail.contains("Signed-By"), "{detail}");
    assert_eq!(known, previous.digests()?);
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn a_write_that_fails_at_any_step_leaves_the_previous_configuration() -> TestResult {
    let previous = config(&["sampleapp"]);
    let desired = changed_everywhere();
    for step in 0..3 {
        let (_dir, root, known, before) = applied(&previous)?;
        // Three changes, so every step is reached once.
        assert_eq!(
            files::plan(&root, &desired.render()?, &known).changes.len(),
            3
        );
        let outcome = apply_with(
            &root,
            &desired,
            &previous,
            known,
            &Apt::accepts(),
            &mut |index, _| {
                if index == step {
                    Err(io::Error::other("disk full"))
                } else {
                    Ok(())
                }
            },
        );
        let Outcome::RolledBack { known, reason, .. } = outcome else {
            return Err(format!("step {step}: {outcome:?}").into());
        };
        assert_eq!(reason, ReasonCode::EAdminApplyFailed, "step {step}");
        assert_eq!(known, previous.digests()?, "step {step}");
        assert_eq!(tree(&root)?, before, "step {step}");
    }
    Ok(())
}

#[test]
fn removing_a_source_that_apt_then_refuses_restores_it() -> TestResult {
    let previous = config(&["sampleapp"]);
    let (_dir, root, known, before) = applied(&previous)?;
    let outcome = apply(
        &root,
        &Desired::empty(PORT),
        &previous,
        known,
        &Apt::refuses_once(),
    );
    assert!(matches!(outcome, Outcome::RolledBack { .. }), "{outcome:?}");
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn a_refused_write_as_root_is_a_security_context_problem_and_nothing_stays() -> TestResult {
    // Astra Linux: a root shell at integrity level 0 cannot write /etc/apt
    // (R-006, N-036). The first write already fails.
    let previous = Desired::empty(PORT);
    let (_dir, root) = system()?;
    let before = tree(&root)?;
    let outcome = apply_with(
        &root,
        &config(&["sampleapp"]),
        &previous,
        Known::default(),
        &Apt::accepts(),
        &mut |_, _| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    );
    let Outcome::RolledBack { known, reason, .. } = outcome else {
        return Err(format!("{outcome:?}").into());
    };
    assert_eq!(reason, ReasonCode::ESecurityContext);
    assert_eq!(known, Known::default());
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn a_crash_at_any_step_is_finished_by_sending_the_same_request_again() -> TestResult {
    let previous = config(&["sampleapp"]);
    let desired = changed_everywhere();
    for step in 0..3 {
        let (_dir, root, recorded, _) = applied(&previous)?;
        // The process dies before change `step`: no restore runs, and the
        // state owner still holds the digests it recorded before.
        let plan = files::plan(&root, &desired.render()?, &recorded);
        let mut scratch = recorded.clone();
        let stopped = files::apply_with(&root, &plan, &mut scratch, &mut |index, _| {
            if index == step {
                Err(io::Error::other("killed"))
            } else {
                Ok(())
            }
        });
        assert!(stopped.is_err());
        let outcome = apply(&root, &desired, &previous, recorded, &Apt::accepts());
        let Outcome::Applied { known, .. } = outcome else {
            return Err(format!("step {step}: {outcome:?}").into());
        };
        assert_eq!(known, desired.digests()?, "step {step}");
        let mut expected: BTreeMap<String, Vec<u8>> = desired
            .render()?
            .into_iter()
            .map(|file| (file.path.trim_start_matches('/').to_owned(), file.bytes))
            .collect();
        expected.insert(DEBIAN_SOURCES.to_owned(), b"Types: deb\n".to_vec());
        assert_eq!(tree(&root)?, expected, "step {step}");
    }
    Ok(())
}

#[test]
fn a_file_someone_else_changed_is_drift_and_nothing_is_written() -> TestResult {
    let previous = config(&["sampleapp"]);
    let (_dir, root, known, _) = applied(&previous)?;
    let ours = root.join(sources_path("sampleapp").trim_start_matches('/'));
    fs::write(&ours, "Types: deb\nURIs: http://mirror.example/\n")?;
    let before = tree(&root)?;
    let desired = changed_everywhere();
    let outcome = apply(&root, &desired, &previous, known, &Apt::accepts());
    let Outcome::Refused { drift } = outcome else {
        return Err(format!("{outcome:?}").into());
    };
    assert_eq!(drift.len(), 1);
    assert_eq!(tree(&root)?, before, "not even the keyring was written");
    Ok(())
}

#[test]
fn a_request_that_does_not_render_touches_nothing() -> TestResult {
    let (_dir, root) = system()?;
    let before = tree(&root)?;
    // A name with a line break would add a field to the preferences file;
    // an invalid previous configuration could never be restored.
    for (desired, previous) in [
        (
            config(&["sampleapp\nPin-Priority: 1001"]),
            Desired::empty(PORT),
        ),
        (config(&["sampleapp"]), config(&["*"])),
        (Desired::empty(0), Desired::empty(PORT)),
    ] {
        let outcome = apply(
            &root,
            &desired,
            &previous,
            Known::default(),
            &Apt::accepts(),
        );
        assert!(matches!(outcome, Outcome::Invalid { .. }), "{outcome:?}");
        assert_eq!(tree(&root)?, before);
    }
    Ok(())
}

#[test]
fn a_file_changed_during_the_apply_stops_the_restore_and_says_so() -> TestResult {
    let previous = config(&["sampleapp"]);
    let (_dir, root, known, _) = applied(&previous)?;
    let desired = changed_everywhere();
    let keyring = root.join("etc/apt/keyrings/pakomichi.gpg");
    let outcome = apply_with(
        &root,
        &desired,
        &previous,
        known,
        &Apt::accepts(),
        &mut |index, _| {
            if index == 1 {
                // Someone replaces the keyring we just wrote, then the
                // next write fails.
                fs::write(&keyring, b"foreign")?;
                Err(io::Error::other("disk full"))
            } else {
                Ok(())
            }
        },
    );
    let Outcome::Failed { detail, .. } = outcome else {
        return Err(format!("{outcome:?}").into());
    };
    assert!(detail.contains("not restored"), "{detail}");
    assert_eq!(fs::read(&keyring)?, b"foreign", "the foreign bytes stay");
    Ok(())
}

#[test]
fn a_recorded_path_outside_pakomichi_files_is_never_removed() -> TestResult {
    // A wrong or compromised state owner records a system file with its
    // current digest: the plan would remove it as "ours, no longer wanted".
    let (_dir, root) = system()?;
    fs::write(
        root.join("etc/passwd"),
        "root:x:0:0::/root:/bin/sh
",
    )?;
    let before = tree(&root)?;
    for path in [
        "/etc/passwd",
        "/etc/apt/sources.list.d/debian.sources",
        "/etc/apt/sources.list.d/pakomichi-../../passwd.sources",
        "/etc/apt/preferences.d/pakomichi-.pref",
    ] {
        let target = root.join(path.trim_start_matches('/'));
        let digest = fs::read(&target)
            .map(|bytes| Sha256Digest::of(&bytes))
            .unwrap_or_else(|_| Sha256Digest::of(b""));
        let known = Known([(path.to_owned(), digest)].into_iter().collect());
        let outcome = apply(
            &root,
            &Desired::empty(PORT),
            &Desired::empty(PORT),
            known,
            &Apt::accepts(),
        );
        assert!(
            matches!(outcome, Outcome::Invalid { .. }),
            "{path}: {outcome:?}"
        );
        assert_eq!(tree(&root)?, before, "{path}");
    }
    Ok(())
}

#[test]
fn a_file_changed_right_after_it_was_written_is_never_reported_applied() -> TestResult {
    // Every write succeeds, but the keyring is replaced before the last
    // one: only reading every file back catches it.
    let previous = config(&["sampleapp"]);
    let (_dir, root, known, _) = applied(&previous)?;
    let keyring = root.join("etc/apt/keyrings/pakomichi.gpg");
    let outcome = apply_with(
        &root,
        &changed_everywhere(),
        &previous,
        known,
        &Apt::accepts(),
        &mut |index, _| {
            if index == 2 {
                fs::write(&keyring, b"foreign")?;
            }
            Ok(())
        },
    );
    assert!(!matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
    Ok(())
}

#[test]
fn when_apt_refuses_the_previous_configuration_too_the_answer_says_so() -> TestResult {
    let previous = config(&["sampleapp"]);
    let (_dir, root, known, before) = applied(&previous)?;
    let always = Apt(RefCell::new(vec![
        Err("E: Malformed line 3".to_owned()),
        Err("E: Malformed line 3".to_owned()),
    ]));
    let outcome = apply(&root, &changed_everywhere(), &previous, known, &always);
    let Outcome::RolledBack { detail, .. } = outcome else {
        return Err(format!("{outcome:?}").into());
    };
    assert!(detail.contains("also refuses the previous"), "{detail}");
    assert_eq!(tree(&root)?, before);
    Ok(())
}

#[test]
fn a_request_with_a_forged_operation_identifier_is_refused() -> TestResult {
    use crate::apt::wire::{desired_to_wire, digests_to_wire};
    use crate::ipc::channels::{ApplyApt, ApplyRequest, ApplyResponse};
    let (_dir, root) = system()?;
    let before = tree(&root)?;
    let request = |id: &str| {
        ApplyRequest::ApplyApt(ApplyApt {
            operation_id: id.to_owned(),
            desired: desired_to_wire(&config(&["sampleapp"])),
            previous: desired_to_wire(&Desired::empty(PORT)),
            known: digests_to_wire(&Known::default().0),
        })
    };
    for id in ["", "../../etc", "0123456789ABCDEF0123456789ABCDEF"] {
        let response = answer(&root, request(id), &Apt::accepts());
        assert!(matches!(response, ApplyResponse::Invalid(_)), "{id:?}");
    }
    assert_eq!(tree(&root)?, before);
    let response = answer(
        &root,
        request("0123456789abcdef0123456789abcdef"),
        &Apt::accepts(),
    );
    assert!(
        matches!(response, ApplyResponse::Applied(_)),
        "{response:?}"
    );
    Ok(())
}
