// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;
use std::os::unix::fs::symlink;

use super::*;
use crate::apt::config::{
    KEYRING_PATH, LogicalSource, SourceConfig, preferences_path, render, sources_path,
};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DEBIAN_SOURCES: &str = "/etc/apt/sources.list.d/debian.sources";

fn desired(names: &[&str]) -> Vec<ManagedFile> {
    let config = SourceConfig {
        source_key: "sampleapp".to_owned(),
        repositories: vec![LogicalSource {
            label: "pakomichi-sampleapp-strict".to_owned(),
            activated: names.iter().map(|name| (*name).to_owned()).collect(),
        }],
    };
    match render(&[config], 18080, b"keyring bytes") {
        Ok(files) => files,
        Err(error) => panic!("{error}"),
    }
}

fn read(root: &Path, path: &str) -> Option<String> {
    fs::read_to_string(under(root, path)).ok()
}

/// A root with the distribution's own sources file.
fn system() -> Result<TempDir, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = dir.join("root");
    fs::create_dir_all(under(&root, "/etc/apt/sources.list.d"))?;
    fs::create_dir_all(under(&root, "/etc/apt/preferences.d"))?;
    fs::write(under(&root, DEBIAN_SOURCES), "Types: deb\n")?;
    Ok(dir)
}

/// The promise between any two steps: every activated name of a present
/// sources file is pinned.
fn pinned_whenever_served(root: &Path, names: &[&str]) -> bool {
    let served = read(root, &sources_path("sampleapp")).is_some();
    let pins = read(root, &preferences_path("sampleapp")).unwrap_or_default();
    !served
        || names
            .iter()
            .all(|name| pins.split_whitespace().any(|word| word == *name))
}

#[test]
fn no_step_serves_an_activated_name_without_its_pin() -> TestResult {
    let dir = system()?;
    let root = dir.join("root");
    let names = ["sampleapp", "sampleapp-helper"];
    let mut known = Known::default();
    // Add the source, one durable step at a time, as a crash would leave it.
    let add = plan(&root, &desired(&names), &known);
    assert_eq!(
        add.changes.iter().map(Change::path).collect::<Vec<_>>(),
        [
            KEYRING_PATH.to_owned(),
            preferences_path("sampleapp"),
            sources_path("sampleapp")
        ]
    );
    for change in &add.changes {
        apply_change(&root, change, &mut known)?;
        assert!(
            pinned_whenever_served(&root, &names),
            "after {}",
            change.path()
        );
    }
    // Remove it the same way.
    let remove = plan(&root, &[], &known);
    assert_eq!(
        remove.changes.iter().map(Change::path).collect::<Vec<_>>(),
        [
            sources_path("sampleapp"),
            preferences_path("sampleapp"),
            KEYRING_PATH.to_owned()
        ]
    );
    for change in &remove.changes {
        apply_change(&root, change, &mut known)?;
        assert!(
            pinned_whenever_served(&root, &names),
            "after {}",
            change.path()
        );
    }
    assert_eq!(known, Known::default());
    // The distribution's own file is untouched.
    assert_eq!(read(&root, DEBIAN_SOURCES).as_deref(), Some("Types: deb\n"));
    Ok(())
}

#[test]
fn a_file_someone_else_changed_or_removed_is_drift_and_stays_as_they_left_it() -> TestResult {
    let dir = system()?;
    let root = dir.join("root");
    let mut known = Known::default();
    apply(
        &root,
        &plan(&root, &desired(&["sampleapp"]), &known),
        &mut known,
    )?;
    // The administrator raised the pin by hand and deleted the keyring.
    let edited = "Package: sampleapp\nPin: release o=Pakomichi\nPin-Priority: 1001\n";
    fs::write(under(&root, &preferences_path("sampleapp")), edited)?;
    fs::remove_file(under(&root, KEYRING_PATH))?;
    let replan = plan(&root, &desired(&["sampleapp", "sampleapp-helper"]), &known);
    assert_eq!(replan.drift.len(), 2, "{:?}", replan.drift);
    assert!(matches!(
        apply(&root, &replan, &mut known),
        Err(ApplyError::Drift(_))
    ));
    assert_eq!(
        read(&root, &preferences_path("sampleapp")).as_deref(),
        Some(edited)
    );
    assert!(
        read(&root, KEYRING_PATH).is_none(),
        "not recreated behind the user's back"
    );
    // Removing the source does not delete the edited file either.
    let removal = plan(&root, &[], &known);
    assert!(removal.drift.iter().any(|drift| matches!(drift, Drift::Changed { path, .. } if *path == preferences_path("sampleapp"))));
    Ok(())
}

#[test]
fn a_file_under_our_name_that_we_did_not_write_is_never_touched() -> TestResult {
    let dir = system()?;
    let root = dir.join("root");
    // Another tool's file at our path, and a symlink at another of ours.
    fs::write(
        under(&root, &sources_path("sampleapp")),
        "Types: deb\nURIs: http://example.invalid\n",
    )?;
    fs::create_dir_all(under(&root, "/etc/apt/keyrings"))?;
    symlink(under(&root, DEBIAN_SOURCES), under(&root, KEYRING_PATH))?;
    let mut known = Known::default();
    let first = plan(&root, &desired(&["sampleapp"]), &known);
    let foreign: BTreeSet<&str> = first
        .drift
        .iter()
        .filter_map(|drift| match drift {
            Drift::Foreign { path } => Some(path.as_str()),
            Drift::Changed { .. } => None,
        })
        .collect();
    assert_eq!(
        foreign,
        BTreeSet::from([KEYRING_PATH, sources_path("sampleapp").as_str()])
    );
    assert!(apply(&root, &first, &mut known).is_err());
    assert_eq!(read(&root, DEBIAN_SOURCES).as_deref(), Some("Types: deb\n"));
    // Nothing we never wrote is removed.
    assert_eq!(plan(&root, &[], &Known::default()).changes, Vec::new());
    Ok(())
}

#[test]
fn an_apply_interrupted_after_its_rename_is_finished_without_a_rewrite() -> TestResult {
    let dir = system()?;
    let root = dir.join("root");
    let files = desired(&["sampleapp"]);
    let mut known = Known::default();
    let first = plan(&root, &files, &known);
    // The keyring and the pin were renamed into place, then the process died
    // before the record was kept; a staging file of the third step remains.
    apply_change(&root, &first.changes[0], &mut Known::default())?;
    apply_change(&root, &first.changes[1], &mut Known::default())?;
    let staging = staging_path(&under(&root, &sources_path("sampleapp")))?;
    fs::write(&staging, "partial")?;
    assert!(
        staging.to_string_lossy().ends_with('~'),
        "APT ignores it silently"
    );
    let again = plan(&root, &files, &known);
    assert_eq!(again.drift, Vec::new());
    assert_eq!(again.adopted.len(), 2);
    assert_eq!(again.changes.len(), 1);
    apply(&root, &again, &mut known)?;
    assert!(!staging.exists());
    assert_eq!(known.0.len(), 3);
    assert_eq!(plan(&root, &files, &known), Plan::default());
    Ok(())
}

#[test]
fn a_target_changed_between_plan_and_apply_is_not_overwritten() -> TestResult {
    let dir = system()?;
    let root = dir.join("root");
    let mut known = Known::default();
    let planned = plan(&root, &desired(&["sampleapp"]), &known);
    fs::write(
        under(&root, &preferences_path("sampleapp")),
        "someone else\n",
    )?;
    let error = apply(&root, &planned, &mut known).err();
    assert!(matches!(error, Some(ApplyError::Raced { .. })), "{error:?}");
    assert_eq!(
        read(&root, &preferences_path("sampleapp")).as_deref(),
        Some("someone else\n")
    );
    // The keyring step before it completed and is recorded.
    assert_eq!(known.0.keys().collect::<Vec<_>>(), [KEYRING_PATH]);
    Ok(())
}
