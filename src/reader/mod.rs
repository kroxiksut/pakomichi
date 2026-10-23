// SPDX-License-Identifier: MIT OR Apache-2.0

//! The repository reader (P3-005a; ADR-007, ADR-017 point 6, ADR-024).
//!
//! A separate unprivileged process serves the logical APT and RPM
//! repositories on a loopback socket inherited from systemd:
//!
//! - only `GET` and `HEAD`; nothing changes state (N-025);
//! - exactly one `Host` naming the loopback endpoint, no request body;
//! - the target is `/<repo>/<path>`, decoded segment by segment and
//!   validated like a manifest path (N-018);
//! - a mutable path only from the current generation, a content-addressed
//!   path from the current or a retained generation inside the window
//!   (`PublishReader::resolve`);
//! - every object is hashed in full before its first byte is sent, and an
//!   object that does not match its manifest is not served (N-017).
//!
//! The reader opens the publish root and the CAS read-only and takes no
//! lock: the single writer publishes by replacing `current` atomically.
//! Draining on `SIGTERM` and per-client limits belong to P3-005c.

mod target;
pub use target::{MAX_TARGET_BYTES, TargetError, host_allowed, parse_target};

#[cfg(unix)]
mod route;
#[cfg(unix)]
mod server;

#[cfg(unix)]
pub use route::{DEFAULT_RETENTION, Lookup, OpenError, Repositories};
#[cfg(unix)]
pub use server::{Limits, ReplyBody, check_loopback, handle, serve};

#[cfg(all(test, unix))]
#[path = "server_tests.rs"]
mod server_tests;
