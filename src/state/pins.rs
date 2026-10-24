// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which asset an accepted object comes from, for the lazy fetch
//! (P3-005b, ADR-035 point 3).

use super::{StateError, StateOwner};
use crate::cas::Sha256Digest;

/// States whose bytes Pakomichi accepted and may serve: verified evidence
/// or an approval is attached, and a retired artifact may still be named by
/// a generation inside the retention window. A held, rejected, or revoked
/// artifact is never fetched again.
const SERVABLE: &str = "('verified', 'eligible', 'published', 'retired')";

/// The pin of an object: GitHub repository ID and asset ID, as text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetPinRow {
    pub repository_id: String,
    pub asset_id: String,
}

impl StateOwner {
    /// The asset whose accepted bytes are exactly `sha256` and `size`.
    /// Several artifacts may share the bytes; any of them names the same
    /// content, the first by artifact ID is returned.
    pub fn pinned_asset(
        &mut self,
        sha256: &Sha256Digest,
        size: u64,
    ) -> Result<Option<AssetPinRow>, StateError> {
        // No artifact is larger than an SQLite integer.
        let Ok(size) = i64::try_from(size) else {
            return Ok(None);
        };
        let mut statement = self.connection().prepare(&format!(
            "SELECT f.repository_id, a.asset_id FROM artifact a \
             JOIN forge_repository f ON f.id = a.source_id \
             WHERE a.sha256 = ?1 AND a.byte_size = ?2 AND f.forge = 'github' \
             AND a.state IN {SERVABLE} ORDER BY a.id LIMIT 1"
        ))?;
        let mut rows = statement.query((sha256.to_hex(), size))?;
        match rows.next()? {
            Some(row) => Ok(Some(AssetPinRow {
                repository_id: row.get(0)?,
                asset_id: row.get(1)?,
            })),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[path = "pins_tests.rs"]
mod tests;
