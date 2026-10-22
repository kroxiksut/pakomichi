// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-process single-flight: at most one writer per key at a time.

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::{Condvar, Mutex, PoisonError};

/// Serialises work per key. A second caller for the same key waits until
/// the first finishes, then re-checks the store itself; results are not
/// shared, so a failed attempt is never replayed to waiters.
pub(crate) struct SingleFlight<K> {
    busy: Mutex<HashSet<K>>,
    released: Condvar,
}

impl<K: Eq + Hash + Clone> SingleFlight<K> {
    pub(crate) fn new() -> Self {
        Self {
            busy: Mutex::new(HashSet::new()),
            released: Condvar::new(),
        }
    }

    pub(crate) fn acquire(&self, key: K) -> FlightGuard<'_, K> {
        // A poisoned set only means a holder panicked after inserting; its
        // guard's drop still removes the key, so the set stays meaningful.
        let mut busy = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        while busy.contains(&key) {
            busy = self
                .released
                .wait(busy)
                .unwrap_or_else(PoisonError::into_inner);
        }
        busy.insert(key.clone());
        FlightGuard { flight: self, key }
    }
}

pub(crate) struct FlightGuard<'a, K: Eq + Hash> {
    flight: &'a SingleFlight<K>,
    key: K,
}

impl<K: Eq + Hash> Drop for FlightGuard<'_, K> {
    fn drop(&mut self) {
        let mut busy = self
            .flight
            .busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        busy.remove(&self.key);
        drop(busy);
        self.flight.released.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn same_key_never_runs_concurrently() {
        let flight = Arc::new(SingleFlight::new());
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (flight, active, peak) = (flight.clone(), active.clone(), peak.clone());
                thread::spawn(move || {
                    let _guard = flight.acquire("same");
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(5));
                    active.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for worker in workers {
            assert!(worker.join().is_ok());
        }
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn different_keys_do_not_block_each_other() {
        let flight = SingleFlight::new();
        let first = flight.acquire(1);
        let second = flight.acquire(2);
        drop(first);
        drop(second);
        let _again = flight.acquire(1);
    }
}
