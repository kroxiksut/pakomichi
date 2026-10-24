// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SQLite state database and its single owner (P2-012).
//!
//! ADR-013 keeps states and decisions in SQLite and package bytes in the
//! CAS; ADR-017 point 2 and ADR-020 fix `rusqlite 0.40.2` over the
//! distribution SQLite, version 3.34.1 or newer, without `STRICT` tables.
//!
//! - `floor`: the version floor and the SQL features newer than it; portable,
//!   so the migrations are checked on every target.
//! - `owner` (Unix only, as the product): [`StateOwner`] checks the runtime
//!   library before opening anything, refuses a second owner, creates the
//!   database with mode 0600, enforces foreign keys, runs in defensive mode
//!   with an untrusted schema, applies the forward-only migrations, refuses
//!   a database from a newer build, and backs up and restores through the
//!   online backup API with the source validated first.
//! - `owners` (Unix only): the confirmed owner IDs of a source (migration
//!   0002, R-003); a recorded transfer confirmation moves the current owner.
//!
//! The Windows development host has no system SQLite to link against, and
//! ADR-020 forbids the bundled library, so the owner is built and tested on
//! Linux.

#[cfg(unix)]
mod decisions;
mod floor;
#[cfg(unix)]
mod owner;
#[cfg(unix)]
mod owners;
#[cfg(unix)]
mod pins;
#[cfg(all(test, unix))]
pub(crate) mod test_support;

#[cfg(unix)]
pub use decisions::{DecisionObject, LoggedDecision, Recorded, Replay, replay};
pub use floor::{
    JSON_FUNCTION, MIN_SQLITE_VERSION, NEWER_THAN_FLOOR, format_version, newer_features,
};
#[cfg(unix)]
pub use owner::{SCHEMA_VERSION, StateError, StateOwner, check_sqlite_version};
#[cfg(unix)]
pub use owners::{OwnerConfirmation, OwnerConfirmationKind};
#[cfg(unix)]
pub use pins::AssetPinRow;
