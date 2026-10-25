// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inspector instance hashes the object before `dpkg-deb` sees it:
//! bytes that are not the pinned ones are never inspected.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::cas::{Store, StoreConfig};
use crate::inspect::runner::{InspectorConfig, ToolPaths};
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A `dpkg-deb` that only leaves a mark: a test fails if it ever runs.
fn marking_inspector(dir: &TempDir) -> Result<DebInspector, Box<dyn std::error::Error>> {
    let tool = dir.join("dpkg-deb");
    fs::write(
        &tool,
        format!("#!/bin/sh\ntouch {}\nexit 1\n", dir.join("ran").display()),
    )?;
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755))?;
    Ok(DebInspector::new(InspectorConfig {
        tools: Some(ToolPaths {
            dpkg_deb: tool,
            prlimit: None,
        }),
        require_resource_limits: false,
        allow_root: true,
        ..InspectorConfig::default()
    })?)
}

fn request(sha256: &str, size: u64) -> InspectRequest {
    InspectRequest::InspectDeb(ObjectRef {
        sha256: sha256.to_owned(),
        size,
    })
}

#[test]
fn bytes_that_are_not_the_pinned_ones_are_refused_before_dpkg_deb_runs() -> TestResult {
    let dir = TempDir::new()?;
    let root = dir.join("cas");
    let store = Store::open(&root, StoreConfig::default())?;
    let stored = store.insert(&b"!<arch>\npackage bytes"[..])?;
    let objects = ObjectReader::open(&root)?;
    let inspector = marking_inspector(&dir)?;
    let digest = stored.digest().to_hex();
    let size = stored.size();
    drop(stored);

    // Another size than the pin, an object the store does not hold, and a
    // value that is not a digest.
    let absent = Sha256Digest::of(b"never stored").to_hex();
    for (sha256, size) in [
        (digest.as_str(), size + 1),
        (absent.as_str(), size),
        ("not-a-digest", size),
    ] {
        let answer = answer_inspect(&inspector, &objects, &root, request(sha256, size));
        assert!(
            matches!(&answer, InspectResponse::Refused(refusal) if refusal.reason_code.is_none()),
            "{sha256} {size}: {answer:?}"
        );
    }
    // The stored file changed after it was written: its name is its old
    // digest, its bytes are other bytes.
    let path = root.join("objects").join(&digest);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    let mut changed = fs::read(&path)?;
    changed[0] ^= 1;
    fs::write(&path, &changed)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
    let answer = answer_inspect(&inspector, &objects, &root, request(&digest, size));
    assert!(matches!(answer, InspectResponse::Refused(_)), "{answer:?}");

    assert!(
        !dir.join("ran").exists(),
        "dpkg-deb ran on bytes that were not pinned"
    );
    Ok(())
}
