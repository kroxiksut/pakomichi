// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETag store for conditional requests (R-004 conclusion 14).
//!
//! An entry is written only after a 200 response for that URL and credential
//! was parsed and validated, and it keeps that verified body. A 304 confirms
//! "unchanged" only when the request carried `If-None-Match` with exactly
//! the stored ETag for the same URL and credential; the client then reuses
//! the stored body. A 304 says nothing about asset bytes.
//!
//! The store is in memory. Persisting it is a later decision: the
//! `0001_initial` schema has no ETag column.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use super::token::CredentialId;

/// Default bound on the bytes of stored bodies.
pub const DEFAULT_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CacheKey {
    path: String,
    credential: CredentialId,
}

impl CacheKey {
    pub fn new(path: impl Into<String>, credential: CredentialId) -> Self {
        Self {
            path: path.into(),
            credential,
        }
    }
}

/// A verified 200 response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedResponse {
    pub etag: String,
    pub body: Vec<u8>,
    pub link: Option<String>,
}

#[derive(Default)]
struct Entries {
    map: BTreeMap<CacheKey, (u64, CachedResponse)>,
    next_sequence: u64,
    bytes: usize,
}

/// A bounded, shareable ETag store. Oldest entries are evicted first.
pub struct EtagCache {
    entries: Mutex<Entries>,
    max_bytes: usize,
}

impl Default for EtagCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_BYTES)
    }
}

impl EtagCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            entries: Mutex::new(Entries::default()),
            max_bytes,
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.map.get(key).map(|(_, response)| response.clone())
    }

    /// Stores a verified response; an entry larger than the whole budget is
    /// not stored.
    pub fn put(&self, key: CacheKey, response: CachedResponse) {
        let size = entry_size(&key, &response);
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        remove_entry(&mut entries, &key);
        if size > self.max_bytes {
            return;
        }
        while entries.bytes + size > self.max_bytes {
            let oldest = entries
                .map
                .iter()
                .min_by_key(|(_, (sequence, _))| *sequence)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(oldest) => remove_entry(&mut entries, &oldest),
                None => break,
            }
        }
        let sequence = entries.next_sequence;
        entries.next_sequence += 1;
        entries.bytes += size;
        entries.map.insert(key, (sequence, response));
    }

    pub fn remove(&self, key: &CacheKey) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        remove_entry(&mut entries, key);
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn entry_size(key: &CacheKey, response: &CachedResponse) -> usize {
    key.path.len()
        + response.etag.len()
        + response.body.len()
        + response.link.as_ref().map_or(0, String::len)
}

fn remove_entry(entries: &mut Entries, key: &CacheKey) {
    if let Some((_, old)) = entries.map.remove(key) {
        entries.bytes -= entry_size(key, &old);
    }
}

/// Weak comparison (RFC 9110 section 8.8.3.2): GitHub's ETags are weak, and
/// the `W/` prefix does not take part in the comparison.
pub fn weak_match(left: &str, right: &str) -> bool {
    let opaque = |tag: &str| tag.strip_prefix("W/").unwrap_or(tag).to_owned();
    opaque(left) == opaque(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(etag: &str, body_bytes: usize) -> CachedResponse {
        CachedResponse {
            etag: etag.to_owned(),
            body: vec![b'x'; body_bytes],
            link: None,
        }
    }

    #[test]
    fn keys_bind_url_and_credential() {
        let cache = EtagCache::default();
        cache.put(
            CacheKey::new("/a", CredentialId::Anonymous),
            response("\"1\"", 1),
        );
        assert!(
            cache
                .get(&CacheKey::new("/a", CredentialId::Anonymous))
                .is_some()
        );
        assert!(
            cache
                .get(&CacheKey::new("/b", CredentialId::Anonymous))
                .is_none()
        );
    }

    #[test]
    fn oldest_entries_are_evicted_within_the_budget() {
        let cache = EtagCache::new(100);
        cache.put(
            CacheKey::new("/1", CredentialId::Anonymous),
            response("e", 40),
        );
        cache.put(
            CacheKey::new("/2", CredentialId::Anonymous),
            response("e", 40),
        );
        cache.put(
            CacheKey::new("/3", CredentialId::Anonymous),
            response("e", 40),
        );
        assert!(
            cache
                .get(&CacheKey::new("/1", CredentialId::Anonymous))
                .is_none()
        );
        assert_eq!(cache.len(), 2);
        cache.put(
            CacheKey::new("/big", CredentialId::Anonymous),
            response("e", 200),
        );
        assert!(
            cache
                .get(&CacheKey::new("/big", CredentialId::Anonymous))
                .is_none()
        );
    }

    #[test]
    fn weak_comparison_ignores_the_prefix_only() {
        assert!(weak_match("W/\"abc\"", "\"abc\""));
        assert!(weak_match("W/\"abc\"", "W/\"abc\""));
        assert!(!weak_match("W/\"abc\"", "W/\"abd\""));
    }
}
