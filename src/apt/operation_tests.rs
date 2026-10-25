// SPDX-License-Identifier: MIT OR Apache-2.0

//! The state owner's side against the real applier on a temporary root;
//! only the socket is replaced.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::*;
use crate::apt::applier::{self, AptCheck};
use crate::apt::config::{LogicalSource, SourceConfig, sources_path};
use crate::ipc::channels::ManagedDigestWire;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: &str = "2026-10-24T12:00:00Z";
const PORT: u16 = 18080;

fn config(names: &[&str], keyring: &[u8]) -> Desired {
    Desired {
        port: PORT,
        keyring: keyring.to_vec(),
        sources: vec![SourceConfig {
            source_key: "sampleapp".to_owned(),
            repositories: vec![LogicalSource {
                label: "pakomichi-sampleapp-strict".to_owned(),
                activated: names.iter().map(|name| (*name).to_owned()).collect(),
            }],
        }],
    }
}

struct Apt(RefCell<Vec<Result<(), String>>>);

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

/// What can go wrong between the state owner and the applier.
#[derive(Clone, Copy, PartialEq)]
enum Line {
    Up,
    /// The applier is not reached: nothing is written.
    Down,
    /// The applier writes, then the answer is lost (a crash, a timeout).
    LostAnswer,
    /// The answer names a file outside Pakomichi's.
    ForgedAnswer,
}

struct InProcess {
    root: PathBuf,
    apt: Apt,
    line: Cell<Line>,
    calls: Cell<usize>,
}

impl InProcess {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            apt: Apt(RefCell::new(Vec::new())),
            line: Cell::new(Line::Up),
            calls: Cell::new(0),
        }
    }
}

impl Applier for InProcess {
    fn call(&self, request: &ApplyRequest) -> Result<ApplyResponse, String> {
        self.calls.set(self.calls.get() + 1);
        match self.line.get() {
            Line::Down => return Err("connect: connection refused".to_owned()),
            Line::Up | Line::LostAnswer | Line::ForgedAnswer => {}
        }
        let response = applier::answer(&self.root, request.clone(), &self.apt);
        match self.line.get() {
            Line::LostAnswer => Err("read: timed out".to_owned()),
            Line::ForgedAnswer => {
                let ApplyResponse::Applied(mut applied) = response else {
                    return Ok(response);
                };
                applied.known.push(ManagedDigestWire {
                    path: "/etc/shadow".to_owned(),
                    sha256: "00".repeat(32),
                });
                Ok(ApplyResponse::Applied(applied))
            }
            Line::Up | Line::Down => Ok(response),
        }
    }
}

fn setup() -> Result<(TempDir, StateOwner, InProcess), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let owner = StateOwner::open(&dir.join("state.db"))?;
    let root = dir.join("root");
    fs::create_dir_all(root.join("etc/apt/sources.list.d"))?;
    let applier = InProcess::new(&root);
    Ok((dir, owner, applier))
}

fn files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                found.insert(
                    entry.path().strip_prefix(root)?.display().to_string(),
                    fs::read(entry.path())?,
                );
            }
        }
    }
    Ok(found)
}

fn rendered(desired: &Desired) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(desired
        .render()?
        .into_iter()
        .map(|file| (file.path.trim_start_matches('/').to_owned(), file.bytes))
        .collect())
}

#[test]
fn a_verified_apply_becomes_what_the_next_one_starts_from() -> TestResult {
    let (_dir, mut owner, applier) = setup()?;
    let first = config(&["sampleapp"], b"key 1");
    let ended = apply_apt(&mut owner, &applier, &first, AT)?;
    assert!(matches!(ended, Ended::Verified { .. }), "{ended:?}");
    let state = owner.apt_state()?;
    assert_eq!(state.last_good, Some(first.clone()));
    assert_eq!(state.known, target(&first)?);
    assert_eq!(files(&applier.root)?, rendered(&first)?);
    Ok(())
}

#[test]
fn a_refused_configuration_is_rolled_back_and_the_good_one_stays_good() -> TestResult {
    let (_dir, mut owner, applier) = setup()?;
    let first = config(&["sampleapp"], b"key 1");
    apply_apt(&mut owner, &applier, &first, AT)?;
    applier
        .apt
        .0
        .borrow_mut()
        .push(Err("E: Malformed entry 1".to_owned()));
    let second = config(&["sampleapp", "sampleapp-data"], b"key 2");
    let ended = apply_apt(&mut owner, &applier, &second, AT)?;
    let Ended::RolledBack { reason_code, .. } = ended else {
        return Err(format!("{ended:?}").into());
    };
    assert_eq!(reason_code, "E_ADMIN_APPLY_FAILED");
    assert_eq!(files(&applier.root)?, rendered(&first)?);
    let state = owner.apt_state()?;
    assert_eq!(state.last_good, Some(first.clone()));
    assert_eq!(state.known, target(&first)?);
    Ok(())
}

#[test]
fn an_unreachable_applier_leaves_the_operation_open_and_blocks_new_ones() -> TestResult {
    let (_dir, mut owner, applier) = setup()?;
    applier.line.set(Line::Down);
    let desired = config(&["sampleapp"], b"key 1");
    let error = apply_apt(&mut owner, &applier, &desired, AT)
        .err()
        .ok_or("expected no answer")?;
    assert!(matches!(error, OperationError::NoAnswer { .. }), "{error}");
    assert_eq!(owner.unfinished_apt_operations()?.len(), 1);
    // Nothing new may start: the open operation decides what the files hold.
    applier.line.set(Line::Up);
    let blocked = apply_apt(&mut owner, &applier, &config(&["other"], b"k"), AT)
        .err()
        .ok_or("expected a refusal")?;
    assert!(
        matches!(
            blocked,
            OperationError::State(StateError::OperationUnfinished)
        ),
        "{blocked}"
    );
    let finished = recover_apt(&mut owner, &applier, AT)?;
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].1, Ended::Reconciled);
    assert_eq!(files(&applier.root)?, rendered(&desired)?);
    assert!(owner.unfinished_apt_operations()?.is_empty());
    Ok(())
}

#[test]
fn an_answer_lost_after_the_write_is_settled_by_recovery() -> TestResult {
    // The applier wrote everything; the state owner never heard back and
    // still holds the old digests.
    let (_dir, mut owner, applier) = setup()?;
    let first = config(&["sampleapp"], b"key 1");
    apply_apt(&mut owner, &applier, &first, AT)?;
    applier.line.set(Line::LostAnswer);
    let second = config(&["sampleapp", "sampleapp-data"], b"key 2");
    assert!(apply_apt(&mut owner, &applier, &second, AT).is_err());
    assert_eq!(files(&applier.root)?, rendered(&second)?);
    applier.line.set(Line::Up);
    let finished = recover_apt(&mut owner, &applier, AT)?;
    assert_eq!(finished[0].1, Ended::Reconciled);
    // The journal shows that this one was finished after an interruption.
    let status: String = owner.connection().query_row(
        "SELECT status FROM admin_operation ORDER BY rowid DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(status, "reconciled");
    let state = owner.apt_state()?;
    assert_eq!(state.last_good, Some(second.clone()));
    assert_eq!(state.known, target(&second)?);
    Ok(())
}

#[test]
fn a_hand_edited_file_is_reported_and_nothing_is_written() -> TestResult {
    let (_dir, mut owner, applier) = setup()?;
    let first = config(&["sampleapp"], b"key 1");
    apply_apt(&mut owner, &applier, &first, AT)?;
    let ours = applier
        .root
        .join(sources_path("sampleapp").trim_start_matches('/'));
    fs::write(&ours, "Types: deb\nURIs: http://mirror.example/\n")?;
    let before = files(&applier.root)?;
    let ended = apply_apt(&mut owner, &applier, &config(&[], b"key 2"), AT)?;
    assert!(matches!(ended, Ended::Drifted { .. }), "{ended:?}");
    assert_eq!(files(&applier.root)?, before);
    let state = owner.apt_state()?;
    assert_eq!(state.known, target(&first)?, "the record is unchanged");
    Ok(())
}

#[test]
fn an_answer_naming_a_foreign_file_is_not_recorded() -> TestResult {
    let (_dir, mut owner, applier) = setup()?;
    applier.line.set(Line::ForgedAnswer);
    let desired = config(&["sampleapp"], b"key 1");
    let error = apply_apt(&mut owner, &applier, &desired, AT)
        .err()
        .ok_or("expected a refusal")?;
    assert!(matches!(error, OperationError::NoAnswer { .. }), "{error}");
    // The row stays open instead of recording /etc/shadow as ours.
    assert_eq!(owner.unfinished_apt_operations()?.len(), 1);
    Ok(())
}

#[test]
fn an_invalid_configuration_records_nothing_and_calls_nobody() -> TestResult {
    let (_dir, mut owner, applier) = setup()?;
    let error = apply_apt(&mut owner, &applier, &config(&["Bad Name"], b"k"), AT)
        .err()
        .ok_or("expected a refusal")?;
    assert!(matches!(error, OperationError::Invalid(_)), "{error}");
    assert_eq!(applier.calls.get(), 0);
    assert_eq!(owner.apt_state()?, crate::state::AptState::default());
    Ok(())
}
