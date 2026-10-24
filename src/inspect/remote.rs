// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inspector as its own process (ADR-035): an instance gets one
//! request on `inspect.sock`, opens the object read-only in the CAS,
//! checks its digest, and inspects it; the state owner reads the answer
//! back with the parser's own validation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::deb::DebInspection;
use super::error::InspectError;
use super::runner::DebInspector;
use crate::cas::{ExpectedObject, ObjectReader, Sha256Digest, Verification};
use crate::ipc::channels::{InspectRefusal, InspectRequest, InspectResponse, ObjectRef};
use crate::ipc::oneshot::call;

/// The instance's answer to its one request. The object is hashed before
/// `dpkg-deb` sees it, so only the pinned bytes are inspected.
pub fn answer_inspect(
    inspector: &DebInspector,
    objects: &ObjectReader,
    cas_root: &Path,
    request: InspectRequest,
) -> InspectResponse {
    let InspectRequest::InspectDeb(object) = request;
    let refused = |reason: Option<String>, message: String| {
        InspectResponse::Refused(InspectRefusal {
            reason_code: reason,
            message,
        })
    };
    let Ok(sha256) = Sha256Digest::from_hex(&object.sha256) else {
        return refused(None, "not a SHA-256 digest".to_owned());
    };
    let expected = ExpectedObject::new(sha256, object.size);
    if let Err(error) = objects.open_object(expected, Verification::Full) {
        return refused(None, format!("object unavailable: {error}"));
    }
    let path = cas_root.join("objects").join(sha256.to_hex());
    match inspector.inspect(&path) {
        Ok(inspection) => InspectResponse::Deb(inspection.to_wire()),
        Err(error) => refused(
            error.reason_code().map(|code| code.as_str().to_owned()),
            error.to_string(),
        ),
    }
}

/// Why a remote inspection gave no result.
#[derive(Debug)]
pub enum RemoteInspectError {
    /// The package itself is refused; the code is the reason when there is
    /// one (`E_ARTIFACT_MALFORMED`, `E_PLATFORM_UNSUPPORTED`).
    Refused {
        reason_code: Option<String>,
        message: String,
    },
    /// The instance's answer is not a valid inspection.
    Invalid(InspectError),
    /// No instance answered.
    Unavailable(String),
}

impl std::fmt::Display for RemoteInspectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { message, .. } => write!(formatter, "refused: {message}"),
            Self::Invalid(error) => write!(formatter, "invalid inspector answer: {error}"),
            Self::Unavailable(message) => write!(formatter, "inspector unavailable: {message}"),
        }
    }
}

impl std::error::Error for RemoteInspectError {}

/// The state owner's side of `inspect.sock`.
#[derive(Clone, Debug)]
pub struct SocketInspector {
    socket: PathBuf,
    timeout: Duration,
}

impl SocketInspector {
    pub fn new(socket: &Path, timeout: Duration) -> Self {
        Self {
            socket: socket.to_owned(),
            timeout,
        }
    }

    pub fn inspect_deb(&self, object: ExpectedObject) -> Result<DebInspection, RemoteInspectError> {
        let request = InspectRequest::InspectDeb(ObjectRef {
            sha256: object.sha256.to_hex(),
            size: object.size,
        });
        match call::<_, InspectResponse>(&self.socket, &request, self.timeout) {
            Ok(InspectResponse::Deb(wire)) => {
                DebInspection::from_wire(wire).map_err(RemoteInspectError::Invalid)
            }
            Ok(InspectResponse::Refused(refusal)) => Err(RemoteInspectError::Refused {
                reason_code: refusal.reason_code,
                message: refusal.message,
            }),
            Ok(InspectResponse::Error(body)) => Err(RemoteInspectError::Unavailable(body.message)),
            Err(error) => Err(RemoteInspectError::Unavailable(error.to_string())),
        }
    }
}
