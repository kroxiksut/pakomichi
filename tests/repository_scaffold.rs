// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

const SPDX_MARKER: &str = "SPDX-License-Identifier: MIT OR Apache-2.0";

/// Extensions of code and code-like files that must carry the code license.
const CODE_EXTENSIONS: [&str; 10] = [
    "rs", "py", "ps1", "sh", "sql", "toml", "yml", "yaml", "service", "socket",
];

/// Build output, local state, and generated files are not project sources.
const SKIPPED_DIRECTORIES: [&str; 3] = ["target", "temp", "__pycache__"];
const SKIPPED_FILES: [&str; 1] = ["Cargo.lock"];

fn collect_code_files(directory: &Path, found: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => panic!("cannot read {}: {error}", directory.display()),
    };

    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => panic!("cannot read an entry of {}: {error}", directory.display()),
        };
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        if path.is_dir() {
            // Dot directories hold local tool state; `.github` is published.
            let hidden = name.starts_with('.') && name != ".github";
            if !hidden && !SKIPPED_DIRECTORIES.contains(&name) {
                collect_code_files(&path, found);
            }
            continue;
        }

        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        if CODE_EXTENSIONS.contains(&extension) && !SKIPPED_FILES.contains(&name) {
            found.push(path);
        }
    }
}

#[test]
fn package_metadata_matches_repository_policy() {
    assert_eq!(env!("CARGO_PKG_NAME"), "pakomichi");
    assert_eq!(env!("CARGO_PKG_LICENSE"), "MIT OR Apache-2.0");
}

#[test]
fn every_code_file_carries_the_spdx_identifier() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_code_files(root, &mut files);

    // Guard against a walk that silently finds nothing.
    assert!(
        files.iter().any(|path| path.ends_with("src/lib.rs")),
        "the scan did not reach src/lib.rs"
    );

    let missing: Vec<String> = files
        .iter()
        .filter(|path| {
            fs::read_to_string(path)
                .map(|text| !text.lines().take(5).any(|line| line.contains(SPDX_MARKER)))
                .unwrap_or(true)
        })
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();

    assert!(missing.is_empty(), "missing `{SPDX_MARKER}`: {missing:?}");
}
