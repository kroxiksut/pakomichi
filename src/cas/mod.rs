// SPDX-License-Identifier: MIT OR Apache-2.0

//! Content-addressed storage (CAS) for verified artifacts and generated
//! repository files.
//!
//! Objects are named by SHA-256 and published only after their size and
//! digest match. Deduplication follows from the naming; garbage collection
//! is by reachability from [`GcRoots`] and in-process leases, never by the
//! age of a file. The module is synchronous and is meant for the single
//! state-owner process; files are the source of truth and database records
//! about the cache are rebuilt from them.
//!
//! The filesystem store needs POSIX semantics (`O_NOFOLLOW`, directory
//! `fsync`, permission bits) and exists only on Unix; identity, error,
//! quota, and reachability types are portable.

// The helpers below serve the Unix store; on other targets only their own
// unit tests use them.
#[cfg_attr(not(unix), allow(dead_code))]
mod digest;
#[cfg_attr(not(unix), allow(dead_code))]
mod error;
#[cfg_attr(not(unix), allow(dead_code))]
mod flight;
#[cfg_attr(not(unix), allow(dead_code))]
mod gc;
#[cfg_attr(not(unix), allow(dead_code))]
mod quota;
#[cfg(unix)]
mod store;

pub use digest::{ExpectedObject, InvalidDigest, Sha256Digest};
pub use error::CasError;
pub use gc::{GcReport, GcRoots, Lease};
#[cfg(unix)]
pub use store::{
    DEFAULT_MAX_OBJECT_BYTES, ObjectReader, ScrubReport, Store, StoreConfig, StoredObject,
    Verification, VerifiedObject,
};
