// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reachability roots and in-process leases for garbage collection.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use super::digest::Sha256Digest;

/// The set of objects that garbage collection must keep.
///
/// Objects are kept because something reaches them, never because of their
/// own age: a published generation, a retired generation still inside the
/// retention window (clients may hold its indexes), or an explicit pin.
#[derive(Clone, Debug)]
pub struct GcRoots {
    now: SystemTime,
    generation_retention: Duration,
    live: HashSet<Sha256Digest>,
}

impl GcRoots {
    pub fn new(now: SystemTime, generation_retention: Duration) -> Self {
        Self {
            now,
            generation_retention,
            live: HashSet::new(),
        }
    }

    /// Adds a generation's objects when the generation is retained and
    /// returns whether it is. `retired_at` is `None` while the generation is
    /// current or otherwise published. A retirement time in the future
    /// (clock skew) keeps the generation.
    pub fn add_generation(
        &mut self,
        retired_at: Option<SystemTime>,
        objects: impl IntoIterator<Item = Sha256Digest>,
    ) -> bool {
        let retained = match retired_at {
            None => true,
            Some(retired) => match retired.checked_add(self.generation_retention) {
                Some(expiry) => expiry > self.now,
                None => true,
            },
        };
        if retained {
            self.live.extend(objects);
        }
        retained
    }

    /// Keeps an object regardless of generations (user pin, an artifact
    /// awaiting publication, an operation in progress).
    pub fn pin(&mut self, digest: Sha256Digest) {
        self.live.insert(digest);
    }

    pub fn contains(&self, digest: &Sha256Digest) -> bool {
        self.live.contains(digest)
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

/// Outcome of one collection pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GcReport {
    /// Objects deleted because nothing reached them.
    pub removed: Vec<Sha256Digest>,
    pub freed_bytes: u64,
    /// Objects kept because a root reaches them.
    pub kept: usize,
    /// Unreachable objects kept because this process holds a lease on them.
    pub leased: usize,
    /// Entries whose names are not digests; they are reported, not deleted.
    pub unknown_entries: usize,
}

type LeaseCounts = Arc<Mutex<HashMap<Sha256Digest, usize>>>;

/// In-process reference counts for objects that are in use but not yet
/// reachable from a root, such as an object stored a moment ago whose
/// reference is still being recorded.
#[derive(Clone, Debug, Default)]
pub(crate) struct LeaseTable {
    counts: LeaseCounts,
}

impl LeaseTable {
    pub(crate) fn acquire(&self, digest: Sha256Digest) -> Lease {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        *counts.entry(digest).or_insert(0) += 1;
        Lease {
            counts: self.counts.clone(),
            digest,
        }
    }

    pub(crate) fn is_leased(&self, digest: &Sha256Digest) -> bool {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(digest)
    }
}

/// Keeps one object from garbage collection in this process while held.
#[derive(Debug)]
pub struct Lease {
    counts: LeaseCounts,
    digest: Sha256Digest,
}

impl Lease {
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl Clone for Lease {
    fn clone(&self) -> Self {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        *counts.entry(self.digest).or_insert(0) += 1;
        Self {
            counts: self.counts.clone(),
            digest: self.digest,
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.digest) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.digest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn published_generations_are_always_roots() {
        let mut roots = GcRoots::new(at(1_000_000), HOUR);
        let digest = Sha256Digest::of(b"current");
        assert!(roots.add_generation(None, [digest]));
        assert!(roots.contains(&digest));
    }

    #[test]
    fn retired_generations_stay_inside_the_window() {
        let now = at(1_000_000);
        let mut roots = GcRoots::new(now, HOUR);
        let recent = Sha256Digest::of(b"recent");
        let expired = Sha256Digest::of(b"expired");
        let skewed = Sha256Digest::of(b"future");
        assert!(roots.add_generation(Some(at(1_000_000 - 3599)), [recent]));
        assert!(!roots.add_generation(Some(at(1_000_000 - 3600)), [expired]));
        assert!(roots.add_generation(Some(at(2_000_000)), [skewed]));
        assert!(roots.contains(&recent));
        assert!(!roots.contains(&expired));
        assert!(roots.contains(&skewed));
    }

    #[test]
    fn an_object_shared_with_a_retained_generation_stays_live() {
        let mut roots = GcRoots::new(at(1_000_000), HOUR);
        let shared = Sha256Digest::of(b"shared");
        assert!(!roots.add_generation(Some(at(0)), [shared]));
        assert!(roots.add_generation(None, [shared]));
        assert!(roots.contains(&shared));
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn pins_are_roots() {
        let mut roots = GcRoots::new(at(0), HOUR);
        assert!(roots.is_empty());
        let digest = Sha256Digest::of(b"pinned");
        roots.pin(digest);
        assert!(roots.contains(&digest));
    }

    #[test]
    fn leases_count_clones_and_release_on_drop() {
        let table = LeaseTable::default();
        let digest = Sha256Digest::of(b"leased");
        let first = table.acquire(digest);
        let second = first.clone();
        assert_eq!(second.digest(), digest);
        drop(first);
        assert!(table.is_leased(&digest));
        drop(second);
        assert!(!table.is_leased(&digest));
    }
}
