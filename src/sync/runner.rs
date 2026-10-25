// SPDX-License-Identifier: MIT OR Apache-2.0

//! The production pipeline of `pakomichi-state` (P4-001a step 1b, Linux).
//!
//! Network and the CAS writer stay in the state owner (ADR-035 point 4).
//! Packages are inspected by the isolated inspector over `inspect.sock`,
//! metadata is signed over `sign.sock` and checked with `gpgv` against the
//! exported public key, and the APT configuration goes to the root
//! applier over `apply.sock`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::SystemTime;

use tokio::runtime::Handle;

use super::evidence::GitHubEvidence;
use super::publish::{AptPublisher, apply_and_record, desired_apt};
use super::{AssetFetch, Sync, SyncError, SyncReport, SystemView, synchronize};
use crate::apt::operation::{Ended, SocketApplier, recover_apt};
use crate::apt::policy::OurRepository;
use crate::attest::AttestationVerifier;
use crate::cas::{ExpectedObject, Sha256Digest, Store, Verification};
use crate::compat::detect;
use crate::github::{AssetDownloader, AssetLocator, GitHubClient, RustlsConnector, Transport};
use crate::inspect::SocketInspector;
use crate::inventory::{Ecosystem, InventoryPolicy};
use crate::namespace::collect::system::{CollectorConfig, collect};
use crate::policy::level::{Level, logical_repository};
use crate::publish::GenerationStore;
use crate::publish::sign::{GpgvVerifier, SocketSigner};
use crate::service::Pipeline;
use crate::state::StateOwner;

/// Chunks of a download in flight to the CAS writer; an error ends it.
struct ChunkReader {
    chunks: Receiver<Result<Vec<u8>, String>>,
    current: Vec<u8>,
    offset: usize,
}

impl Read for ChunkReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.offset == self.current.len() {
            match self.chunks.recv() {
                Ok(Ok(chunk)) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                Ok(Err(detail)) => return Err(io::Error::other(detail)),
                // The sender finished: the download is complete.
                Err(_) => return Ok(0),
            }
        }
        let count = buffer.len().min(self.current.len() - self.offset);
        buffer[..count].copy_from_slice(&self.current[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

/// Downloads into the CAS, keeping the digest of the bytes received.
pub struct CasFetch {
    pub cas: Arc<Store>,
    pub downloader: Arc<AssetDownloader<RustlsConnector>>,
    pub runtime: Handle,
}

impl AssetFetch for CasFetch {
    fn fetch(
        &self,
        locator: AssetLocator,
        size: u64,
        api_digest: Option<Sha256Digest>,
    ) -> Result<ExpectedObject, String> {
        // Bytes already verified in the CAS are not downloaded again; the
        // API digest only names them, the CAS hashes them.
        if let Some(sha256) = api_digest {
            let expected = ExpectedObject::new(sha256, size);
            if self.cas.open_object(expected, Verification::Full).is_ok() {
                return Ok(expected);
            }
        }
        let (sender, receiver): (SyncSender<Result<Vec<u8>, String>>, _) = sync_channel(16);
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                self.cas.insert(ChunkReader {
                    chunks: receiver,
                    current: Vec::new(),
                    offset: 0,
                })
            });
            let mut sink = |chunk: &[u8]| -> io::Result<()> {
                sender
                    .send(Ok(chunk.to_vec()))
                    .map_err(|_| io::Error::other("the CAS writer stopped"))
            };
            let downloaded = self
                .runtime
                .block_on(self.downloader.download(locator, size, &mut sink));
            if let Err(error) = &downloaded {
                let _ = sender.send(Err(error.to_string()));
            }
            drop(sender);
            let stored = writer
                .join()
                .map_err(|_| "the CAS writer panicked".to_owned())?;
            downloaded.map_err(|error| error.to_string())?;
            let stored = stored.map_err(|error| error.to_string())?;
            Ok(ExpectedObject::new(stored.digest(), stored.size()))
        })
    }
}

/// Everything the production pipeline talks to.
pub struct Production<T> {
    pub github: GitHubClient<T>,
    pub verifier: Option<Arc<AttestationVerifier>>,
    pub runtime: Handle,
    pub fetch: CasFetch,
    pub inspector: SocketInspector,
    pub publish_root: PathBuf,
    pub signer: SocketSigner,
    pub metadata_verifier: GpgvVerifier,
    /// The exported public key APT trusts (`Signed-By`).
    pub keyring: Vec<u8>,
    pub applier: SocketApplier,
    pub port: u16,
    /// A private, writable directory for the namespace collector.
    pub collector_home: PathBuf,
    pub max_freshness: u64,
}

impl<T: Transport> Production<T> {
    /// Every logical repository of every source, and what Pakomichi
    /// published, so the collector does not count our own packages as the
    /// system's.
    fn system_view(&self, owner: &mut StateOwner) -> Result<SystemView, SyncError> {
        let mut ours = Vec::new();
        let mut published: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for row in owner.sources()? {
            for level in Level::ALL {
                if let Ok(repository) = logical_repository(&row.id, level) {
                    ours.push(OurRepository::new(self.port, &repository.apt_label));
                }
            }
            for artifact in owner.published_artifacts(&row.id)? {
                published
                    .entry(artifact.key.name)
                    .or_default()
                    .insert(artifact.version);
            }
        }
        let names: Vec<String> = published.keys().cloned().collect();
        let installed_from_pakomichi = match crate::apt::system::read_policy(&names) {
            Ok(policies) => {
                crate::apt::policy::installed_from_pakomichi(&policies, &published, &ours)
            }
            Err(_) => {
                return Ok(SystemView::Unknown(
                    crate::error::ReasonCode::ESystemNamespaceUnknown,
                ));
            }
        };
        let config = CollectorConfig {
            dnf_home: self.collector_home.clone(),
            installed_from_pakomichi,
            pakomichi_sources: ours
                .iter()
                .map(|repository| repository.uri.clone())
                .collect(),
        };
        Ok(match collect(&config) {
            Ok(collected) => SystemView::Known {
                namespace: collected.namespace,
                packages: collected.packages,
            },
            Err(error) => SystemView::Unknown(error.reason_code()),
        })
    }
}

impl<T: Transport + Send + std::marker::Sync> Pipeline for Production<T> {
    fn synchronize(
        &self,
        owner: &mut StateOwner,
        source_id: &str,
        at: &str,
    ) -> Result<SyncReport, SyncError> {
        let target = detect::target(Ecosystem::Deb)
            .map_err(|error| SyncError::Platform(error.to_string()))?;
        let system = self.system_view(owner)?;
        let evidence = GitHubEvidence {
            github: &self.github,
            verifier: self.verifier.clone(),
            runtime: self.runtime.clone(),
        };
        let (mut store, _) = GenerationStore::open(&self.publish_root)
            .map_err(|error| SyncError::Platform(error.to_string()))?;
        let mut publisher = AptPublisher {
            store: &mut store,
            cas: &self.fetch.cas,
            signer: &self.signer,
            verifier: &self.metadata_verifier,
            architecture: target.platform.native_arch().to_owned(),
            max_freshness: self.max_freshness,
            now: SystemTime::now(),
        };
        let sync = Sync {
            github: &self.github,
            runtime: self.runtime.clone(),
            fetch: &self.fetch,
            inspect: &self.inspector,
            evidence: &evidence,
            target: &target,
            system: &system,
            policy: InventoryPolicy::default(),
        };
        synchronize(&sync, owner, &mut publisher, source_id, at)
    }

    fn configure(&self, owner: &mut StateOwner, at: &str) -> Result<Ended, String> {
        // An apply left without an answer is finished first.
        recover_apt(owner, &self.applier, at).map_err(|error| error.to_string())?;
        let desired =
            desired_apt(owner, self.port, self.keyring.clone()).map_err(|e| e.to_string())?;
        apply_and_record(owner, &self.applier, &desired, at).map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::StoreConfig;
    use crate::state::test_support::TempDir;

    #[test]
    fn a_download_cut_short_stores_nothing() -> Result<(), Box<dyn std::error::Error>> {
        // The connection drops after the first chunk: the part received
        // must not become an object, or the next pass would find it.
        let dir = TempDir::new()?;
        let cas = Store::open(&dir.join("cas"), StoreConfig::default())?;
        let (sender, receiver) = sync_channel(4);
        sender.send(Ok(b"first part".to_vec()))?;
        sender.send(Err("connection reset".to_owned()))?;
        drop(sender);
        let stored = cas.insert(ChunkReader {
            chunks: receiver,
            current: Vec::new(),
            offset: 0,
        });
        assert!(stored.is_err());
        let part = ExpectedObject::new(Sha256Digest::of(b"first part"), 10);
        assert!(cas.open_object(part, Verification::Full).is_err());
        Ok(())
    }
}
