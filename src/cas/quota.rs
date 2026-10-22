// SPDX-License-Identifier: MIT OR Apache-2.0

//! Byte accounting for the store quota.

use std::sync::{Mutex, PoisonError};

use super::error::CasError;

/// Tracks stored and in-flight bytes against an optional limit. Space is
/// reserved before a byte is written, so a quota failure never leaves a
/// partial object behind. The ledger covers this process only; the store
/// lock makes it the single writer.
#[derive(Debug)]
pub(crate) struct QuotaLedger {
    limit: Option<u64>,
    used: Mutex<u64>,
}

impl QuotaLedger {
    pub(crate) fn new(limit: Option<u64>, used: u64) -> Self {
        Self {
            limit,
            used: Mutex::new(used),
        }
    }

    pub(crate) fn used(&self) -> u64 {
        *self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserves `bytes`, or fails without changing the ledger.
    pub(crate) fn reserve(&self, bytes: u64) -> Result<Reservation<'_>, CasError> {
        let mut reservation = Reservation {
            ledger: self,
            bytes: 0,
        };
        reservation.grow(bytes)?;
        Ok(reservation)
    }

    /// Returns space of objects that left the store (GC or quarantine).
    pub(crate) fn release(&self, bytes: u64) {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        *used = used.saturating_sub(bytes);
    }

    fn try_add(&self, bytes: u64) -> Result<(), CasError> {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        let total = used.saturating_add(bytes);
        if let Some(limit) = self.limit
            && total > limit
        {
            return Err(CasError::QuotaExceeded {
                requested: bytes,
                available: limit.saturating_sub(*used),
            });
        }
        *used = total;
        Ok(())
    }
}

/// Space held for a write in progress. Dropping it returns the space;
/// [`Reservation::commit`] keeps it as stored bytes.
#[derive(Debug)]
pub(crate) struct Reservation<'a> {
    ledger: &'a QuotaLedger,
    bytes: u64,
}

impl Reservation<'_> {
    pub(crate) fn grow(&mut self, bytes: u64) -> Result<(), CasError> {
        self.ledger.try_add(bytes)?;
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }

    /// Keeps exactly `bytes` (the final object size) and returns the rest.
    pub(crate) fn commit(mut self, bytes: u64) {
        let surplus = self.bytes.saturating_sub(bytes);
        self.ledger.release(surplus);
        self.bytes = 0;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.ledger.release(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_is_returned_on_drop() -> Result<(), CasError> {
        let ledger = QuotaLedger::new(Some(10), 4);
        {
            let _reservation = ledger.reserve(6)?;
            assert_eq!(ledger.used(), 10);
        }
        assert_eq!(ledger.used(), 4);
        Ok(())
    }

    #[test]
    fn over_quota_fails_without_side_effects() {
        let ledger = QuotaLedger::new(Some(10), 4);
        let result = ledger.reserve(7);
        assert!(matches!(
            result,
            Err(CasError::QuotaExceeded {
                requested: 7,
                available: 6
            })
        ));
        assert_eq!(ledger.used(), 4);
    }

    #[test]
    fn growth_stops_at_the_limit() -> Result<(), CasError> {
        let ledger = QuotaLedger::new(Some(10), 0);
        let mut reservation = ledger.reserve(8)?;
        assert!(reservation.grow(3).is_err());
        assert_eq!(ledger.used(), 8);
        reservation.commit(5);
        assert_eq!(ledger.used(), 5);
        ledger.release(5);
        assert_eq!(ledger.used(), 0);
        Ok(())
    }

    #[test]
    fn unlimited_ledger_only_counts() -> Result<(), CasError> {
        let ledger = QuotaLedger::new(None, u64::MAX - 1);
        ledger.reserve(5)?.commit(5);
        assert_eq!(ledger.used(), u64::MAX);
        Ok(())
    }
}
