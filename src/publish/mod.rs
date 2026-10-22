// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable generations of the logical repositories (P3-008).
//!
//! ADR-008 and ADR-024 points 1–3, confirmed by R-004:
//!
//! - every generation is one immutable manifest of paths, digests, and
//!   sizes; the bytes live in the CAS;
//! - every path is either mutable metadata, served only from the current
//!   generation, or content-addressed and served from any retained
//!   generation, and its bytes never change (`manifest`);
//! - generation numbers grow per source and backend, are recorded before
//!   use, and are never reused; `current` only moves forward (`store`);
//! - a retired generation stays reachable for the retention window, and
//!   garbage collection follows reachability from the current and retained
//!   generations;
//! - files are the source of truth, and `reconcile` rebuilds the
//!   `snapshot` rows from them.
//!
//! Building the APT and RPM indexes and signing them belong to the index
//! publishers (P3-001, P3-003); serving belongs to the reader (P3-005). An
//! empty DNF generation after the maximum freshness (ADR-024 point 3) is an
//! ordinary generation whose indexes list no packages.

mod manifest;
#[cfg(unix)]
mod store;

pub use manifest::{
    Backend, Entry, GenerationId, GenerationMeta, MAX_ENTRIES, Manifest, ManifestError, PathClass,
    RepoName, RepoPath, SourceId, Timestamp, check_immutable_paths, classify,
};
#[cfg(unix)]
pub use store::{
    GenerationInfo, GenerationStore, PublishError, ReconcileReport, Recovery, snapshot_id,
};
