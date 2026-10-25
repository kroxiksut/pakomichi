// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converting the `apply.sock` messages (ADR-029 point 2, P4-003a) into the
//! adapter's types and back. Every value is checked here before the root
//! applier sees it: sizes and counts are bounded, a digest is 64 lowercase
//! hex digits, a recorded path must be one Pakomichi manages, a name
//! appears once. The applier checks the paths again itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::config::{Desired, LogicalSource, SourceConfig, is_managed_path};
use crate::cas::Sha256Digest;
use crate::ipc::channels::{AptConfigWire, AptRepositoryWire, AptSourceWire, ManagedDigestWire};
use crate::ipc::protocol::OperationId;

/// Largest local keyring accepted (a few public keys).
pub const MAX_KEYRING_BYTES: usize = 64 * 1024;
pub const MAX_SOURCES: usize = 256;
pub const MAX_REPOSITORIES_PER_SOURCE: usize = 16;
pub const MAX_ACTIVATED_NAMES: usize = 4096;
/// Two files per source and the keyring.
pub const MAX_RECORDED: usize = 2 * MAX_SOURCES + 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireError(pub String);

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

fn invalid(text: impl Into<String>) -> WireError {
    WireError(text.into())
}

pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Lowercase hex only, at most `max` bytes decoded.
pub fn from_hex(text: &str, max: usize) -> Result<Vec<u8>, WireError> {
    if !text.len().is_multiple_of(2) || text.len() / 2 > max {
        return Err(invalid("hex has an odd length or is too long"));
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid("not lowercase hex")),
    };
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// An operation identifier of ADR-029 point 7: 32 lowercase hex digits.
pub fn is_operation_id(text: &str) -> bool {
    OperationId::parse(text).is_some()
}

pub fn desired_to_wire(desired: &Desired) -> AptConfigWire {
    AptConfigWire {
        port: desired.port,
        keyring_hex: to_hex(&desired.keyring),
        sources: desired
            .sources
            .iter()
            .map(|source| AptSourceWire {
                source_key: source.source_key.clone(),
                repositories: source
                    .repositories
                    .iter()
                    .map(|repository| AptRepositoryWire {
                        label: repository.label.clone(),
                        activated: repository.activated.iter().cloned().collect(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// The checks that need no rendering; rendering then checks every key,
/// label, name, and the port.
pub fn desired_from_wire(wire: &AptConfigWire) -> Result<Desired, WireError> {
    if wire.sources.len() > MAX_SOURCES {
        return Err(invalid("too many sources"));
    }
    let mut names = 0usize;
    let mut sources = Vec::with_capacity(wire.sources.len());
    for source in &wire.sources {
        if source.repositories.len() > MAX_REPOSITORIES_PER_SOURCE {
            return Err(invalid("too many repositories in one source"));
        }
        let mut repositories = Vec::with_capacity(source.repositories.len());
        for repository in &source.repositories {
            names += repository.activated.len();
            if names > MAX_ACTIVATED_NAMES {
                return Err(invalid("too many activated names"));
            }
            let activated: BTreeSet<String> = repository.activated.iter().cloned().collect();
            if activated.len() != repository.activated.len() {
                return Err(invalid("a name is activated twice in one repository"));
            }
            repositories.push(LogicalSource {
                label: repository.label.clone(),
                activated,
            });
        }
        sources.push(SourceConfig {
            source_key: source.source_key.clone(),
            repositories,
        });
    }
    Ok(Desired {
        port: wire.port,
        keyring: from_hex(&wire.keyring_hex, MAX_KEYRING_BYTES)?,
        sources,
    })
}

pub fn digests_to_wire(digests: &BTreeMap<String, Sha256Digest>) -> Vec<ManagedDigestWire> {
    digests
        .iter()
        .map(|(path, digest)| ManagedDigestWire {
            path: path.clone(),
            sha256: digest.to_hex(),
        })
        .collect()
}

pub fn digests_from_wire(
    wire: &[ManagedDigestWire],
) -> Result<BTreeMap<String, Sha256Digest>, WireError> {
    if wire.len() > MAX_RECORDED {
        return Err(invalid("too many recorded files"));
    }
    let mut digests = BTreeMap::new();
    for entry in wire {
        if !is_managed_path(&entry.path) {
            return Err(invalid(format!(
                "{:?} is not a file Pakomichi manages",
                entry.path
            )));
        }
        let digest =
            Sha256Digest::from_hex(&entry.sha256).map_err(|_| invalid("not a SHA-256 digest"))?;
        if digests.insert(entry.path.clone(), digest).is_some() {
            return Err(invalid(format!("{:?} is recorded twice", entry.path)));
        }
    }
    Ok(digests)
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
