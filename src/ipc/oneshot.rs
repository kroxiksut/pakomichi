// SPDX-License-Identifier: MIT OR Apache-2.0

//! One request per connection, for the channels of ADR-035.
//!
//! - [`serve_channel`]: a listener the process inherited from systemd
//!   (`fetch.sock`); the peer is checked from `SO_PEERCRED` before the
//!   first frame, connection slots are limited, and each connection gets
//!   one request and one response.
//! - [`serve_stdio`]: one `Accept=yes` instance (`sign.sock`,
//!   `inspect.sock`) whose standard input and output are the connection;
//!   the peer of that connection is checked the same way.
//! - [`call`]: the client side.
//!
//! A refused peer gets no response at all; a malformed request gets an
//! error and the handler never runs. The response is flushed and the write
//! side is shut down before the socket is closed (ADR-029 point 10).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::channels::{ApplyResponse, FetchResponse, InspectResponse, SignResponse};
use super::frame::{FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, read_frame, write_frame};
use super::protocol::{ErrorBody, ErrorKind, PROTOCOL_VERSION, ProtocolError, decode, encode};
use super::server::{Counters, Limits, PeerRule, take_slot};

/// A response type that can carry a protocol refusal.
pub trait ChannelResponse: Serialize {
    fn refused(error: ErrorBody) -> Self;
}

fn refusal(kind: ErrorKind) -> ErrorBody {
    ErrorBody {
        error: kind,
        message: "request refused; nothing was applied".to_owned(),
        supported_versions: vec![PROTOCOL_VERSION],
    }
}

impl ChannelResponse for FetchResponse {
    fn refused(error: ErrorBody) -> Self {
        Self::Error(error)
    }
}

impl ChannelResponse for SignResponse {
    fn refused(error: ErrorBody) -> Self {
        Self::Error(error)
    }
}

impl ChannelResponse for InspectResponse {
    fn refused(error: ErrorBody) -> Self {
        Self::Error(error)
    }
}

impl ChannelResponse for ApplyResponse {
    fn refused(error: ErrorBody) -> Self {
        Self::Error(error)
    }
}

/// Limits of the channels added by ADR-035: four connections, a short
/// first-frame deadline, and room for a slow download before the answer.
pub const FETCH_LIMITS: Limits = Limits {
    first_frame: Duration::from_secs(5),
    idle: Duration::from_secs(35 * 60),
    per_uid: 16,
    total: 16,
};

/// Why one request was not served.
#[derive(Debug)]
pub enum ServeError {
    /// The peer's uid is not the channel's; nothing was read.
    PeerRefused {
        uid: u32,
    },
    /// No peer credentials (standard input is not a Unix socket).
    NoPeer(io::Error),
    Frame(FrameError),
    Io(io::Error),
}

impl fmt::Display for ServeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerRefused { uid } => write!(formatter, "peer uid {uid} refused"),
            Self::NoPeer(error) => write!(formatter, "no peer credentials: {error}"),
            Self::Frame(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ServeError {}

fn peer_uid(socket: impl AsFd) -> Result<u32, ServeError> {
    getsockopt(&socket, PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(|error| ServeError::NoPeer(io::Error::from(error)))
}

/// Reads one request, answers it, and half-closes. `peer` is the socket
/// whose credentials are checked; `input` and `output` are its two
/// directions (standard input and output of an `Accept=yes` instance).
pub fn serve_one<Req, Resp, H>(
    peer: impl AsFd,
    mut input: impl Read,
    mut output: impl Write,
    rule: PeerRule,
    handler: H,
) -> Result<(), ServeError>
where
    Req: DeserializeOwned,
    Resp: ChannelResponse,
    H: FnOnce(Req, u32) -> Resp,
{
    let uid = peer_uid(&peer)?;
    if !rule.admits(uid) {
        return Err(ServeError::PeerRefused { uid });
    }
    let text = read_frame(&mut input, MAX_REQUEST_BYTES).map_err(ServeError::Frame)?;
    let response = match decode::<Req>(&text) {
        Ok(request) => handler(request, uid),
        Err(error) => Resp::refused(refusal(error.kind())),
    };
    write_frame(&mut output, &encode(&response), MAX_RESPONSE_BYTES).map_err(ServeError::Frame)?;
    output.flush().map_err(ServeError::Io)?;
    nix::sys::socket::shutdown(peer.as_fd().as_raw_fd(), nix::sys::socket::Shutdown::Write)
        .map_err(|error| ServeError::Io(io::Error::from(error)))?;
    Ok(())
}

/// Serves an `Accept=yes` instance: its standard input and output are the
/// connection.
pub fn serve_stdio<Req, Resp, H>(rule: PeerRule, handler: H) -> Result<(), ServeError>
where
    Req: DeserializeOwned,
    Resp: ChannelResponse,
    H: FnOnce(Req, u32) -> Resp,
{
    let stdin = io::stdin();
    let peer = stdin.as_fd().try_clone_to_owned().map_err(ServeError::Io)?;
    serve_one(peer, stdin.lock(), io::stdout().lock(), rule, handler)
}

/// Serves `listener` until the process ends: a thread per admitted
/// connection, one request each.
pub fn serve_channel<Req, Resp, H>(
    listener: UnixListener,
    rule: PeerRule,
    limits: Limits,
    handler: H,
) -> io::Result<JoinHandle<()>>
where
    Req: DeserializeOwned + Send + 'static,
    Resp: ChannelResponse + Send + 'static,
    H: Fn(Req, u32) -> Resp + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let counters = Arc::new(Mutex::new(Counters::default()));
    thread::Builder::new()
        .name("ipc-channel".to_owned())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let Ok(uid) = peer_uid(&stream) else { continue };
                if !rule.admits(uid) {
                    continue;
                }
                let Some(slot) = take_slot(&counters, uid, limits) else {
                    continue;
                };
                let handler = Arc::clone(&handler);
                let _ = thread::Builder::new()
                    .name("ipc-request".to_owned())
                    .spawn(move || {
                        let _ = answer::<Req, Resp, _>(stream, limits, |request, uid| {
                            handler(request, uid)
                        });
                        drop(slot);
                    });
            }
        })
}

fn answer<Req, Resp, H>(stream: UnixStream, limits: Limits, handler: H) -> Result<(), ServeError>
where
    Req: DeserializeOwned,
    Resp: ChannelResponse,
    H: FnOnce(Req, u32) -> Resp,
{
    stream
        .set_read_timeout(Some(limits.first_frame))
        .and_then(|()| stream.set_write_timeout(Some(limits.idle)))
        .map_err(ServeError::Io)?;
    let input = stream.try_clone().map_err(ServeError::Io)?;
    let output = stream.try_clone().map_err(ServeError::Io)?;
    serve_one(stream, input, output, PeerRule::AnyUser, handler)
}

/// Why a call failed.
#[derive(Debug)]
pub enum CallError {
    Connect(io::Error),
    Frame(FrameError),
    Protocol(ProtocolError),
}

impl fmt::Display for CallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(formatter, "connect: {error}"),
            Self::Frame(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CallError {}

/// Sends one request on a new connection to `path` and reads its answer.
pub fn call<Req, Resp>(path: &Path, request: &Req, timeout: Duration) -> Result<Resp, CallError>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let mut stream = UnixStream::connect(path).map_err(CallError::Connect)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(CallError::Connect)?;
    write_frame(&mut stream, &encode(request), MAX_REQUEST_BYTES).map_err(CallError::Frame)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(CallError::Connect)?;
    let text = read_frame(&mut stream, MAX_RESPONSE_BYTES).map_err(CallError::Frame)?;
    decode(&text).map_err(CallError::Protocol)
}

#[cfg(test)]
#[path = "oneshot_tests.rs"]
mod tests;
