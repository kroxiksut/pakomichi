// SPDX-License-Identifier: MIT OR Apache-2.0

//! The APT adapter (P3-002, ADR-004, ADR-022, `specifications/apt.md`).
//!
//! - `config` renders the files Pakomichi owns: the local keyring, one
//!   deb822 `.sources` file and one preferences file per source, with a
//!   `Pin: release o=Pakomichi,l=<label>` at 990 for every activated name.
//! - `files` (Unix) plans and applies changes to exactly those files under a
//!   root directory: staged next to the target, renamed into place, and
//!   ordered so that no activated name is ever served without its pin.
//!   A file that someone else changed or created under our name is never
//!   overwritten: it is drift, shown to the user.
//! - `policy` reads back `apt-cache policy` and judges APT's choice: every
//!   activated name is protected, no equal version hides in another source,
//!   and a newer version elsewhere is a notice.
//!
//! - `applier` (Unix): the root side of an apply (P4-003a): renders the
//!   files from the desired configuration itself, writes, reads back, asks
//!   APT, and restores the previous configuration on any failure.
//! - `operation` (Unix): the state owner's side: intent in `admin_operation`,
//!   the applier over `apply.sock`, the outcome, and recovery.
//! - `wire`: the `apply.sock` messages to and from these types, checked.

#[cfg(unix)]
pub mod applier;
pub mod config;
#[cfg(unix)]
pub mod files;
#[cfg(unix)]
pub mod operation;
pub mod policy;
#[cfg(unix)]
pub mod system;
pub mod wire;
