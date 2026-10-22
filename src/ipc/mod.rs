// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local IPC between Pakomichi's processes and its CLI (ADR-029, P2-013).
//!
//! - `frame`: 4-byte big-endian length plus UTF-8 JSON, refused before the
//!   body is read when empty or over the limit;
//! - `protocol`: version 1 messages; one request type per channel, so the
//!   status channel cannot express an administrative request; no defaults
//!   on fields that confirm an action; shared by the CLI and the server;
//! - `server` (Unix only): one listener per channel, `SO_PEERCRED` checked
//!   against the channel's peer rule before the first frame, connection
//!   limits and deadlines, `ping` answered by the connection itself while
//!   administrative work runs as operations on a worker, unguessable
//!   operation identifiers bound to the caller's uid, confirmations bound
//!   to the digest of the plan that was shown, and responses flushed and
//!   half-closed before the socket is closed.

pub mod frame;
pub mod protocol;
#[cfg(unix)]
pub mod server;
