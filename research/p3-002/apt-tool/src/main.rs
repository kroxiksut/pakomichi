// SPDX-License-Identifier: MIT OR Apache-2.0
//! Drives the production APT adapter on a test target (P3-002 research
//! tool; the production caller is the privileged applier of P4-003).
//!
//! ```text
//! p3002-apt apply --state FILE --port PORT --keyring FILE --source KEY
//!                 --repo LABEL[:NAME,NAME...] ...
//! p3002-apt check --port PORT --repo LABEL[:NAME,...] ... [--published NAME,...]
//! ```
//!
//! `apply` reads APT's policy for the requested names, holds every name
//! with an equal version in another source (`E_SOURCE_AMBIGUOUS`), renders
//! the files for the rest, plans against the state file, and applies to
//! `/`. Exit 3 on drift. `check` reads the policy back and prints findings
//! and notices; exit 3 when there is a finding.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pakomichi::apt::config::{LogicalSource, SourceConfig, render};
use pakomichi::apt::files::{Drift, Known, apply, plan};
use pakomichi::apt::policy::{Family, Finding, Held, OurRepository, judge, pins_to_write};
use pakomichi::apt::system::read_policy;
use pakomichi::cas::Sha256Digest;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("p3002-apt: {message}");
            ExitCode::from(2)
        }
    }
}

struct Options {
    command: String,
    values: BTreeMap<String, String>,
    repos: Vec<(String, Vec<String>)>,
}

fn options() -> Result<Options, String> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or("a command is required")?;
    let mut values = BTreeMap::new();
    let mut repos = Vec::new();
    while let Some(argument) = arguments.next() {
        let name = argument
            .strip_prefix("--")
            .ok_or(format!("unexpected {argument}"))?;
        let value = arguments.next().ok_or(format!("--{name} needs a value"))?;
        if name == "repo" {
            let (label, names) = value.split_once(':').unwrap_or((&value, ""));
            let names = names
                .split(',')
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
            repos.push((label.to_owned(), names));
        } else {
            values.insert(name.to_owned(), value);
        }
    }
    Ok(Options {
        command,
        values,
        repos,
    })
}

fn load(path: &Path) -> Result<Known, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Known::default()),
        Err(error) => return Err(error.to_string()),
    };
    let mut known = Known::default();
    for line in text.lines() {
        let (digest, file) = line.split_once(' ').ok_or("malformed state")?;
        let digest = Sha256Digest::from_hex(digest).map_err(|e| e.to_string())?;
        known.0.insert(file.to_owned(), digest);
    }
    Ok(known)
}

fn save(path: &Path, known: &Known) -> Result<(), String> {
    let text: String = known
        .0
        .iter()
        .map(|(file, digest)| format!("{} {file}\n", digest.to_hex()))
        .collect();
    std::fs::write(path, text).map_err(|e| e.to_string())
}

fn run() -> Result<u8, String> {
    let options = options()?;
    let get = |name: &str| {
        options
            .values
            .get(name)
            .cloned()
            .ok_or(format!("--{name} is required"))
    };
    let port: u16 = get("port")?.parse().map_err(|e| format!("--port: {e}"))?;
    let requested: BTreeMap<String, OurRepository> = options
        .repos
        .iter()
        .flat_map(|(label, names)| {
            names
                .iter()
                .map(move |name| (name.clone(), OurRepository::new(port, label)))
        })
        .collect();
    let ours: Vec<OurRepository> = options
        .repos
        .iter()
        .map(|(label, _)| OurRepository::new(port, label))
        .collect();
    match options.command.as_str() {
        "apply" => {
            let state = PathBuf::from(get("state")?);
            let keyring = std::fs::read(get("keyring")?).map_err(|e| format!("--keyring: {e}"))?;
            let names: Vec<String> = requested.keys().cloned().collect();
            let policies = read_policy(&names).map_err(|e| e.to_string())?;
            // Each --repo LABEL:NAMES is one family.
            let families: Vec<Family> = options
                .repos
                .iter()
                .filter(|(_, names)| !names.is_empty())
                .map(|(label, names)| Family {
                    repository: OurRepository::new(port, label),
                    members: names.iter().cloned().collect(),
                })
                .collect();
            let (pins, held) = pins_to_write(&policies, &families);
            for (members, reason) in &held {
                let members: Vec<&str> = members.iter().map(String::as_str).collect();
                match reason {
                    Held::Ambiguous(finding) => println!(
                        "held\t{}\t{}\t{finding:?}",
                        members.join(","),
                        finding.reason().as_str()
                    ),
                    Held::NotListed { name } => {
                        println!("pending\t{}\tnot listed yet: {name}", members.join(","))
                    }
                }
            }
            let mut labels: Vec<String> = Vec::new();
            for (label, _) in &options.repos {
                if !labels.contains(label) {
                    labels.push(label.clone());
                }
            }
            let config = SourceConfig {
                source_key: get("source")?,
                repositories: labels
                    .iter()
                    .map(|label| LogicalSource {
                        label: label.clone(),
                        activated: pins
                            .iter()
                            .filter(|(_, repository)| &repository.label == label)
                            .map(|(name, _)| name.clone())
                            .collect(),
                    })
                    .collect(),
            };
            let configs = if config.repositories.is_empty() {
                Vec::new()
            } else {
                vec![config]
            };
            let files = render(&configs, port, &keyring).map_err(|e| e.to_string())?;
            let mut known = load(&state)?;
            let planned = plan(Path::new("/"), &files, &known);
            for drift in &planned.drift {
                match drift {
                    Drift::Changed { path, .. } => println!("drift\tchanged\t{path}"),
                    Drift::Foreign { path } => println!("drift\tforeign\t{path}"),
                }
            }
            if !planned.drift.is_empty() {
                return Ok(3);
            }
            let result = apply(Path::new("/"), &planned, &mut known);
            save(&state, &known)?;
            result.map_err(|e| e.to_string())?;
            for change in &planned.changes {
                println!("changed\t{}", change.path());
            }
            Ok(0)
        }
        "check" => {
            let published: Vec<String> = options
                .values
                .get("published")
                .map(|list| list.split(',').filter(|n| !n.is_empty()).map(str::to_owned).collect())
                .unwrap_or_default();
            let mut names: Vec<String> = requested.keys().cloned().collect();
            names.extend(published.iter().cloned());
            let policies = read_policy(&names).map_err(|e| e.to_string())?;
            let selection = judge(&policies, &requested, &published, &ours);
            for finding in &selection.findings {
                let name = match finding {
                    Finding::NotProtected { name, .. }
                    | Finding::EqualVersionElsewhere { name, .. }
                    | Finding::TakesOver { name, .. } => name,
                };
                println!("finding\t{name}\t{}\t{finding:?}", finding.reason().as_str());
            }
            for notice in &selection.notices {
                println!("notice\t{}\t{}\t{}", notice.name, notice.version, notice.source);
            }
            Ok(if selection.findings.is_empty() { 0 } else { 3 })
        }
        other => Err(format!("unknown command {other}")),
    }
}
