// SPDX-License-Identifier: MIT OR Apache-2.0
//! Publishes DEB files as one signed APT generation through the production
//! index publisher (P3-001 research tool).
//!
//! ```text
//! p3001-publish --publish-root DIR --cas-root DIR --label LABEL --source ID
//!               (--signer-home DIR | --sign-socket PATH) --key FPR --keyring FILE
//!               --confirmed-ago SECONDS [--max-freshness SECONDS] DEB...
//! ```
//!
//! Each DEB is stored in the CAS, its control paragraph is read by the
//! production inspector from that immutable copy, and the generation is
//! built, signed, checked with `gpgv`, and made current by `publish_apt`.
//! The last confirmed synchronization is `--confirmed-ago` seconds before
//! now. Prints the new generation number; on a refusal prints the reason
//! code and exits 2.

use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use pakomichi::cas::{ExpectedObject, Store, StoreConfig};
use pakomichi::inspect::{DebInspector, InspectorConfig};
use pakomichi::publish::apt::{AptPackage, AptRepository, Freshness};
use pakomichi::publish::sign::{Fingerprint, GpgSigner, GpgvVerifier, MetadataSigner, SocketSigner};
use pakomichi::publish::{AptGeneration, GenerationStore, RepoName, SourceId, publish_apt};

fn main() -> ExitCode {
    match run() {
        Ok(id) => {
            println!("{id}");
            ExitCode::SUCCESS
        }
        Err(Failure::Refused { reason, message }) => {
            eprintln!("p3001-publish: refused {reason}: {message}");
            ExitCode::from(2)
        }
        Err(Failure::Usage(message)) => {
            eprintln!("p3001-publish: {message}");
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    Usage(String),
    Refused { reason: String, message: String },
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Usage(message)
    }
}

fn run() -> Result<u64, Failure> {
    let mut values = HashMap::new();
    let mut debs = Vec::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if let Some(name) = argument.strip_prefix("--") {
            let value = arguments.next().ok_or(format!("--{name} needs a value"))?;
            values.insert(name.to_owned(), value);
        } else {
            debs.push(PathBuf::from(argument));
        }
    }
    let mut take = |name: &str| values.remove(name).ok_or(format!("--{name} is required"));
    let publish_root = PathBuf::from(take("publish-root")?);
    let cas_root = PathBuf::from(take("cas-root")?);
    let label = take("label")?;
    let source = take("source")?;
    let signer_home = take("signer-home").ok().map(PathBuf::from);
    let sign_socket = take("sign-socket").ok().map(PathBuf::from);
    let key = Fingerprint::new(&take("key")?).ok_or("--key is not a fingerprint".to_owned())?;
    let keyring = PathBuf::from(take("keyring")?);
    let number = |text: String| text.parse::<u64>().map_err(|e| format!("{text}: {e}"));
    let confirmed_ago = number(take("confirmed-ago")?)?;
    let max_freshness = take("max-freshness").map_or(Ok(7 * 86_400), number)?;

    let cas = Store::open(&cas_root, StoreConfig::default()).map_err(|e| e.to_string())?;
    let inspector = DebInspector::new(InspectorConfig::default()).map_err(|e| e.to_string())?;
    let mut packages = Vec::new();
    for deb in &debs {
        let file = File::open(deb).map_err(|e| format!("{}: {e}", deb.display()))?;
        let stored = cas.insert(file).map_err(|e| format!("{}: {e}", deb.display()))?;
        let inspection = inspector
            .inspect(stored.path())
            .map_err(|e| format!("{}: {e}", deb.display()))?;
        packages.push(AptPackage {
            control: inspection.control().clone(),
            object: ExpectedObject::new(stored.digest(), stored.size()),
        });
    }

    let now = SystemTime::now();
    let now_seconds = now.duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let apt = AptRepository::new(&label, &["amd64"]).map_err(|e| e.to_string())?;
    let generation = AptGeneration {
        repo: RepoName::new(&label).map_err(|e| e.to_string())?,
        source: SourceId::new(&source).map_err(|e| e.to_string())?,
        apt: &apt,
        packages: &packages,
        freshness: Freshness {
            confirmed_at: now_seconds.saturating_sub(confirmed_ago),
            max_freshness,
        },
    };
    // Through the signer instance (ADR-035), or with a key of our own.
    let signer: Box<dyn MetadataSigner> = match (sign_socket, signer_home) {
        (Some(socket), _) => Box::new(SocketSigner::new(&socket)),
        (None, Some(home)) => {
            Box::new(GpgSigner::new(&home, key.clone()).map_err(|e| e.to_string())?)
        }
        (None, None) => return Err("--signer-home or --sign-socket is required".to_owned().into()),
    };
    let verifier = GpgvVerifier::new(&keyring, key).map_err(|e| e.to_string())?;
    let (mut store, _) = GenerationStore::open(&publish_root).map_err(|e| e.to_string())?;
    let id = publish_apt(&mut store, &cas, signer.as_ref(), &verifier, generation, now).map_err(|error| {
        Failure::Refused {
            reason: error.reason().as_str().to_owned(),
            message: error.to_string(),
        }
    })?;
    Ok(id.get())
}
