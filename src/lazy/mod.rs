// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lazy fetch of a pinned package that a published generation references
//! but the CAS does not hold, or holds corrupt (P3-005b,
//! `architecture/delivery-recovery.md` "Lazy fetch").
//!
//! The object is identified by its pinned digest and size only. The pin
//! names the asset by numeric IDs (`Locate`); a digest without a pin is
//! never fetched, so an index or any generated file is not "repaired" from
//! the network. The download streams into a CAS staging file through
//! [`Store::ensure`]: the object is published only after its size and
//! SHA-256 match, concurrent requests for one digest share one download,
//! and a corrupt copy is quarantined first. Nothing reaches a client until
//! the reader has opened and hashed the stored object again.
//!
//! The fetcher owns the CAS writer and the network; in the deployed
//! process model the read-only reader asks it over IPC (P2-013b).

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::runtime::Handle;

use crate::cas::{CasError, ExpectedObject, Sha256Digest, Store};
use crate::error::ReasonCode;
use crate::github::{AssetDownloader, AssetLocator, DownloadError, Resolve, SecureConnector};
use crate::ipc::channels::{FetchFailure, FetchRequest, FetchResponse, ObjectRef, Stored};
use crate::ipc::oneshot::call;

/// Chunks buffered between the download and the staging file.
const CHANNEL_CHUNKS: usize = 16;

/// Which asset a pinned object comes from.
pub trait Locate: Send + Sync {
    fn locate(&self, object: &ExpectedObject) -> Option<AssetLocator>;
}

/// Why an object could not be fetched; each maps to the answer the reader
/// gives the package manager.
#[derive(Debug)]
pub enum FetchError {
    /// No pin names this object: nothing is fetched.
    NotPinned,
    Download(DownloadError),
    /// The store refused the bytes (another digest or size) or could not
    /// keep them (quota, full disk).
    Store(CasError),
    /// The state owner answered over `fetch.sock` with this status, or
    /// could not be reached (503).
    Remote {
        status: u16,
        message: String,
    },
}

impl FetchError {
    /// The HTTP status the reader answers with: 502 for an upstream that
    /// is gone, refuses, misdirects, or sends other bytes; 504 for a
    /// timeout; 507 when the store is full; 500 otherwise.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NotPinned => 500,
            // Only the statuses the reader may answer with pass through.
            Self::Remote { status, .. } => match status {
                502 | 503 | 504 | 507 => *status,
                _ => 500,
            },
            Self::Download(DownloadError::Timeout)
            | Self::Download(DownloadError::Transport(crate::github::TransportError::Timeout)) => {
                504
            }
            Self::Download(DownloadError::Sink(_)) => 500,
            Self::Download(_) => 502,
            Self::Store(error) => match error.reason_code() {
                Some(ReasonCode::EDiskExhausted) => 507,
                Some(ReasonCode::ECacheDigestMismatch) => 502,
                _ => 500,
            },
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPinned => formatter.write_str("no pinned asset for this object"),
            Self::Download(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Remote { status, message } => write!(formatter, "{message} (status {status})"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Fetches one object into the CAS; blocking.
pub trait Fetch: Send + Sync {
    fn fetch(&self, object: ExpectedObject) -> Result<(), FetchError>;
}

/// The production fetcher: pins from `locate`, bytes from GitHub.
pub struct LazyFetcher<C, R, L> {
    cas: Arc<Store>,
    downloader: Arc<AssetDownloader<C, R>>,
    locate: L,
    runtime: Handle,
}

impl<C, R, L> LazyFetcher<C, R, L> {
    pub fn new(
        cas: Arc<Store>,
        downloader: Arc<AssetDownloader<C, R>>,
        locate: L,
        runtime: Handle,
    ) -> Self {
        Self {
            cas,
            downloader,
            locate,
            runtime,
        }
    }
}

type Failure = Arc<Mutex<Option<DownloadError>>>;

/// The staging side of the download: chunks in order, then the end; a
/// download failure is an I/O error, so the store discards the staging
/// file.
struct ChannelReader {
    receiver: Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    offset: usize,
    failure: Failure,
}

impl Read for ChannelReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.offset == self.chunk.len() {
            match self.receiver.recv() {
                Ok(chunk) => {
                    self.chunk = chunk;
                    self.offset = 0;
                }
                Err(_) => {
                    let failed = self
                        .failure
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .is_some();
                    return if failed {
                        Err(io::Error::other("download failed"))
                    } else {
                        Ok(0)
                    };
                }
            }
        }
        let count = buffer.len().min(self.chunk.len() - self.offset);
        buffer[..count].copy_from_slice(&self.chunk[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

impl<C, R, L> Fetch for LazyFetcher<C, R, L>
where
    C: SecureConnector + 'static,
    R: Resolve + 'static,
    L: Locate,
{
    fn fetch(&self, object: ExpectedObject) -> Result<(), FetchError> {
        let locator = self.locate.locate(&object).ok_or(FetchError::NotPinned)?;
        let failure: Failure = Arc::new(Mutex::new(None));
        let result = self.cas.ensure(object, || {
            let (sender, receiver): (SyncSender<Vec<u8>>, _) = sync_channel(CHANNEL_CHUNKS);
            let downloader = Arc::clone(&self.downloader);
            let slot = Arc::clone(&failure);
            self.runtime.spawn(async move {
                let mut sink = |chunk: &[u8]| {
                    sender
                        .send(chunk.to_vec())
                        .map_err(|_| io::Error::other("the store stopped reading"))
                };
                if let Err(error) = downloader.download(locator, object.size, &mut sink).await {
                    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(error);
                }
                // `sender` drops here, after the failure is recorded.
            });
            Ok(ChannelReader {
                receiver,
                chunk: Vec::new(),
                offset: 0,
                failure: Arc::clone(&failure),
            })
        });
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                let download = failure
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                match (download, error) {
                    // The store's own refusal (another digest or size, a
                    // full disk) comes first.
                    (
                        _,
                        error @ (CasError::DigestMismatch { .. }
                        | CasError::SizeMismatch { .. }
                        | CasError::QuotaExceeded { .. }
                        | CasError::StorageFull { .. }
                        | CasError::ObjectTooLarge { .. }),
                    ) => Err(FetchError::Store(error)),
                    (Some(download), _) => Err(FetchError::Download(download)),
                    (None, error) => Err(FetchError::Store(error)),
                }
            }
        }
    }
}

/// Pins from the state database: the asset of an accepted artifact with
/// these exact bytes (`StateOwner::pinned_asset`).
pub struct StatePins(pub std::sync::Arc<Mutex<crate::state::StateOwner>>);

impl Locate for StatePins {
    fn locate(&self, object: &ExpectedObject) -> Option<AssetLocator> {
        let mut owner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let row = owner.pinned_asset(&object.sha256, object.size).ok()??;
        Some(AssetLocator {
            repository: crate::github::RepositoryId::new(row.repository_id.parse().ok()?).ok()?,
            asset: crate::github::AssetId::new(row.asset_id.parse().ok()?).ok()?,
        })
    }
}

/// The state owner's answer to one `fetch.sock` request.
pub fn answer_fetch(fetcher: &dyn Fetch, request: FetchRequest) -> FetchResponse {
    let FetchRequest::Fetch(object) = request;
    let Ok(sha256) = Sha256Digest::from_hex(&object.sha256) else {
        return FetchResponse::Failed(FetchFailure {
            http_status: 500,
            message: "not a SHA-256 digest".to_owned(),
        });
    };
    match fetcher.fetch(ExpectedObject::new(sha256, object.size)) {
        Ok(()) => FetchResponse::Stored(Stored {
            sha256: object.sha256,
        }),
        Err(error) => FetchResponse::Failed(FetchFailure {
            http_status: error.http_status(),
            message: error.to_string(),
        }),
    }
}

/// The reader's side: asks the state owner over `fetch.sock`.
#[derive(Clone, Debug)]
pub struct FetchClient {
    socket: PathBuf,
    timeout: Duration,
}

impl FetchClient {
    /// `timeout` bounds the whole answer, so it covers a slow download.
    pub fn new(socket: &Path, timeout: Duration) -> Self {
        Self {
            socket: socket.to_owned(),
            timeout,
        }
    }
}

impl Fetch for FetchClient {
    fn fetch(&self, object: ExpectedObject) -> Result<(), FetchError> {
        let sha256 = object.sha256.to_hex();
        let request = FetchRequest::Fetch(ObjectRef {
            sha256: sha256.clone(),
            size: object.size,
        });
        let remote = |status, message: String| FetchError::Remote { status, message };
        match call::<_, FetchResponse>(&self.socket, &request, self.timeout) {
            Ok(FetchResponse::Stored(stored)) if stored.sha256 == sha256 => Ok(()),
            Ok(FetchResponse::Stored(_)) => {
                Err(remote(500, "answer for another object".to_owned()))
            }
            Ok(FetchResponse::Failed(failure)) => Err(remote(failure.http_status, failure.message)),
            Ok(FetchResponse::Error(body)) => Err(remote(500, body.message)),
            Err(error) => Err(remote(503, format!("fetch service unavailable: {error}"))),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
