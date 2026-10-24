// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared Pakomichi contracts that have executable acceptance tests.
//!
//! Product integrations remain blocked on the required architecture prototypes
//! and research.

pub mod apt;
pub mod attest;
pub mod cas;
pub mod compat;
pub mod error;
pub mod family;
pub mod github;
pub mod inspect;
pub mod inventory;
pub mod ipc;
#[cfg(unix)]
pub mod lazy;
pub mod namespace;
pub mod policy;
#[cfg(target_os = "linux")]
pub mod process;
pub mod publish;
pub mod reader;
pub mod state;
