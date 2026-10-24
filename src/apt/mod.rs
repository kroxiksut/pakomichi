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
//! The privileged applier that runs this as root, records the operation,
//! and rolls it back is P4-003.

pub mod config;
#[cfg(unix)]
pub mod files;
pub mod policy;
#[cfg(unix)]
pub mod system;
