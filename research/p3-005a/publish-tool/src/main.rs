// SPDX-License-Identifier: MIT OR Apache-2.0
//! Publishes one repository tree as a generation (P3-005a research tool).
//!
//! ```text
//! p3005a-publish --publish-root DIR --cas-root DIR --repo NAME --source ID
//!                --backend apt|dnf4|dnf5 TREE
//! ```
//!
//! Every regular file of TREE is stored in the CAS and listed under its
//! relative path; the manifest classifies each path and refuses anything
//! outside ADR-024 point 1 (for example RPM repodata without digest names).
//! For APT, every plain index also gets its `by-hash/SHA256/<digest>` alias,
//! as the APT index publisher will do. Prints the new generation number.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pakomichi::cas::{ExpectedObject, Store, StoreConfig};
use pakomichi::publish::{
    Backend, GenerationMeta, GenerationStore, RepoName, RepoPath, SourceId, Timestamp,
};

const APT_PLAIN_INDEXES: [&str; 4] = ["Packages", "Packages.gz", "Packages.xz", "Translation-en"];

fn main() -> ExitCode {
    match run() {
        Ok(id) => {
            println!("{id}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("p3005a-publish: {message}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    publish_root: PathBuf,
    cas_root: PathBuf,
    repo: String,
    source: String,
    backend: Backend,
    tree: PathBuf,
}

fn options() -> Result<Options, String> {
    let mut values = std::collections::HashMap::new();
    let mut tree = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if let Some(name) = argument.strip_prefix("--") {
            let value = arguments.next().ok_or(format!("--{name} needs a value"))?;
            values.insert(name.to_owned(), value);
        } else {
            tree = Some(PathBuf::from(argument));
        }
    }
    let mut take = |name: &str| values.remove(name).ok_or(format!("--{name} is required"));
    let backend = match take("backend")?.as_str() {
        "apt" => Backend::Apt,
        "dnf4" => Backend::Dnf4,
        "dnf5" => Backend::Dnf5,
        other => return Err(format!("unknown backend {other}")),
    };
    Ok(Options {
        publish_root: take("publish-root")?.into(),
        cas_root: take("cas-root")?.into(),
        repo: take("repo")?,
        source: take("source")?,
        backend,
        tree: tree.ok_or("the tree to publish is required")?,
    })
}

/// Regular files under `tree`, as sorted relative paths with `/`.
fn files(tree: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut pending = vec![tree.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|e| format!("{}: {e}", directory.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(tree)
                    .map_err(|e| e.to_string())?
                    .to_str()
                    .ok_or("non-UTF-8 path")?
                    .to_owned();
                found.push(relative);
            } else {
                return Err(format!("not a regular file: {}", entry.path().display()));
            }
        }
    }
    found.sort();
    Ok(found)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a time after the epoch.
fn timestamp(time: SystemTime) -> Result<Timestamp, String> {
    let seconds = time.duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Timestamp::new(&format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    ))
    .map_err(|e| e.to_string())
}

fn run() -> Result<u64, String> {
    let options = options()?;
    let cas = Store::open(&options.cas_root, StoreConfig::default()).map_err(|e| e.to_string())?;
    let mut objects = Vec::new();
    for relative in files(&options.tree)? {
        let file = File::open(options.tree.join(&relative)).map_err(|e| format!("{relative}: {e}"))?;
        let stored = cas.insert(file).map_err(|e| format!("{relative}: {e}"))?;
        let object = ExpectedObject::new(stored.digest(), stored.size());
        let path = RepoPath::new(&relative).map_err(|e| format!("{relative}: {e}"))?;
        let name = relative.rsplit('/').next().unwrap_or_default();
        if options.backend == Backend::Apt
            && relative.starts_with("dists/")
            && APT_PLAIN_INDEXES.contains(&name)
        {
            let parent = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
            let alias = format!("{parent}/by-hash/SHA256/{}", object.sha256.to_hex());
            objects.push((RepoPath::new(&alias).map_err(|e| e.to_string())?, object));
        }
        objects.push((path, object));
    }
    let now = SystemTime::now();
    let meta = GenerationMeta {
        repo: RepoName::new(&options.repo).map_err(|e| e.to_string())?,
        source: SourceId::new(&options.source).map_err(|e| e.to_string())?,
        backend: options.backend,
        valid_from: timestamp(now)?,
        valid_until: timestamp(now + Duration::from_secs(7 * 86_400))?,
    };
    let (mut store, _) = GenerationStore::open(&options.publish_root).map_err(|e| e.to_string())?;
    let id = store
        .publish(meta, objects, &cas, now)
        .map_err(|e| e.to_string())?;
    Ok(id.get())
}
