// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pakomichi-state`: the state owner (ADR-017 point 7, ADR-035).
//!
//! ```text
//! pakomichi-state --state-db FILE --cas-root DIR
//!                 --fetch-socket /run/pakomichi/fetch.sock
//!                 [--allow-range CIDR,CIDR] [--tuf-cache DIR]
//!                 [--publish-root DIR --sign-socket PATH --inspect-socket PATH
//!                  --apply-socket PATH --keyring FILE --key-fingerprint FPR
//!                  [--loopback-port PORT] [--collector-home DIR]]
//! ```
//!
//! The lazy-fetch channel (P2-013b): the listener comes from systemd under
//! the name `fetch`; only the uid owning the socket file (the reader) is
//! admitted; a request downloads a pinned object into the CAS
//! (`lazy::LazyFetcher`, pins from the state database). The status and
//! administrative channels (P4-001a): listeners `status` (any local user,
//! read-only) and `admin` (uid 0 only), served by `service::StateService`.
//! With `--tuf-cache`, the trusted roots are refreshed through TUF at start
//! (ADR-030 point 8) and attestations are checked; without it, or when the
//! refresh fails, plans say that nothing was checked.
//!
//! The synchronization pipeline (P4-001a step 1b) needs the publication
//! root, the signer, inspector, and applier sockets, and the exported
//! public metadata key with its fingerprint; these arguments go together.
//! Without them, `source activate` and `sync` are refused. The loopback
//! port is a setting (ADR-036 point 2; default 879 after N-034): it
//! must equal the reader socket's `ListenStream=`.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match linux::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("event=fatal error={message}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("pakomichi-state runs only on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use pakomichi::apt::operation::SocketApplier;
    use pakomichi::attest::{
        AttestationVerifier, TufHttp, TufInstance, TufRepository, ensure_crypto_provider,
        refresh_trusted_roots,
    };
    use pakomichi::cas::{Store, StoreConfig};
    use pakomichi::github::{
        AddressRange, AssetDownloader, DownloadConfig, GitHubClient, HttpConfig, HttpTransport,
        RustlsConnector,
    };
    use pakomichi::inspect::SocketInspector;
    use pakomichi::ipc::channels::{FetchRequest, FetchResponse};
    use pakomichi::ipc::oneshot::{FETCH_LIMITS, serve_channel};
    use pakomichi::ipc::server::{Limits, PeerRule, Server};
    use pakomichi::lazy::{LazyFetcher, StatePins, answer_fetch};
    use pakomichi::process::{inherited_unix_listener, require_unprivileged, socket_owner};
    use pakomichi::publish::sign::{Fingerprint, GpgvVerifier, SocketSigner};
    use pakomichi::service::StateService;
    use pakomichi::state::StateOwner;
    use pakomichi::sync::runner::{CasFetch, Production};

    /// The loopback port: privileged, so no unprivileged user can take it
    /// while the socket is down (N-034; owner decision of 2026-10-24).
    const DEFAULT_PORT: u16 = 879;
    /// The maximum freshness of a generation (`delivery-recovery.md`).
    const MAX_FRESHNESS: u64 = 7 * 24 * 60 * 60;

    fn now() -> String {
        jiff::Timestamp::now().to_string()
    }

    /// The verifier over roots refreshed through TUF, or why there is none.
    fn verifier(
        runtime: &tokio::runtime::Runtime,
        cache: &Path,
        ranges: Vec<AddressRange>,
    ) -> Result<AttestationVerifier, String> {
        ensure_crypto_provider().map_err(|e| e.to_string())?;
        let http = Arc::new(
            TufHttp::new(
                RustlsConnector::with_native_roots().map_err(|e| e.to_string())?,
                HttpConfig::default(),
            )
            .allowing_ranges(ranges),
        );
        let repository =
            |instance: TufInstance| TufRepository::new(Arc::clone(&http), instance.host());
        let (roots, sources) = runtime
            .block_on(refresh_trusted_roots(
                repository(TufInstance::GitHub),
                repository(TufInstance::PublicGood),
                cache,
                jiff::Timestamp::now(),
            ))
            .map_err(|e| e.to_string())?;
        eprintln!("event=trusted_roots sources={sources:?}");
        AttestationVerifier::new(&roots).map_err(|e| e.to_string())
    }

    #[derive(Default)]
    struct PipelineArgs {
        publish_root: Option<PathBuf>,
        sign_socket: Option<PathBuf>,
        inspect_socket: Option<PathBuf>,
        apply_socket: Option<PathBuf>,
        keyring: Option<PathBuf>,
        fingerprint: Option<String>,
        port: Option<u16>,
        collector_home: Option<PathBuf>,
    }

    /// The pieces the pipeline needs, all or none.
    struct PipelineParts {
        publish_root: PathBuf,
        sign_socket: PathBuf,
        inspect_socket: PathBuf,
        apply_socket: PathBuf,
        keyring: PathBuf,
        fingerprint: Fingerprint,
    }

    impl PipelineArgs {
        fn parts(&self) -> Result<Option<PipelineParts>, String> {
            match (
                &self.publish_root,
                &self.sign_socket,
                &self.inspect_socket,
                &self.apply_socket,
                &self.keyring,
                &self.fingerprint,
            ) {
                (None, None, None, None, None, None) => Ok(None),
                (
                    Some(publish_root),
                    Some(sign_socket),
                    Some(inspect_socket),
                    Some(apply_socket),
                    Some(keyring),
                    Some(fingerprint),
                ) => Ok(Some(PipelineParts {
                    publish_root: publish_root.clone(),
                    sign_socket: sign_socket.clone(),
                    inspect_socket: inspect_socket.clone(),
                    apply_socket: apply_socket.clone(),
                    keyring: keyring.clone(),
                    fingerprint: Fingerprint::new(fingerprint)
                        .ok_or("--key-fingerprint is not a key fingerprint")?,
                })),
                _ => Err("the pipeline arguments (--publish-root, --sign-socket, \
                          --inspect-socket, --apply-socket, --keyring, --key-fingerprint) \
                          go together"
                    .to_owned()),
            }
        }
    }

    pub fn run() -> Result<(), String> {
        // The role is checked before anything else is read.
        require_unprivileged().map_err(|e| e.to_string())?;
        let mut state_db = None;
        let mut cas_root = None;
        let mut fetch_socket = None;
        let mut tuf_cache = None;
        let mut pipeline = PipelineArgs::default();
        let mut config = DownloadConfig::default();
        let mut arguments = std::env::args().skip(1);
        while let Some(name) = arguments.next() {
            let value = arguments.next().ok_or(format!("{name} needs a value"))?;
            match name.as_str() {
                "--state-db" => state_db = Some(PathBuf::from(value)),
                "--cas-root" => cas_root = Some(PathBuf::from(value)),
                "--fetch-socket" => fetch_socket = Some(PathBuf::from(value)),
                "--tuf-cache" => tuf_cache = Some(PathBuf::from(value)),
                "--publish-root" => pipeline.publish_root = Some(PathBuf::from(value)),
                "--sign-socket" => pipeline.sign_socket = Some(PathBuf::from(value)),
                "--inspect-socket" => pipeline.inspect_socket = Some(PathBuf::from(value)),
                "--apply-socket" => pipeline.apply_socket = Some(PathBuf::from(value)),
                "--keyring" => pipeline.keyring = Some(PathBuf::from(value)),
                "--key-fingerprint" => pipeline.fingerprint = Some(value),
                "--collector-home" => pipeline.collector_home = Some(PathBuf::from(value)),
                "--loopback-port" => {
                    pipeline.port = Some(
                        value
                            .parse::<u16>()
                            .ok()
                            .filter(|port| *port != 0)
                            .ok_or("--loopback-port is 1-65535")?,
                    );
                }
                "--allow-range" => {
                    config.extra_ranges = value
                        .split(',')
                        .map(AddressRange::parse)
                        .collect::<Result<_, _>>()
                        .map_err(|e| e.to_string())?;
                }
                _ => return Err(format!("unknown argument {name}")),
            }
        }
        let parts = pipeline.parts()?;
        let fetch_socket = fetch_socket.ok_or("--fetch-socket is required")?;
        let reader = socket_owner(&fetch_socket).map_err(|e| e.to_string())?;
        let listener = inherited_unix_listener("fetch").map_err(|e| e.to_string())?;
        let state_db = state_db.ok_or("--state-db is required")?;
        let owner = Arc::new(Mutex::new(
            StateOwner::open(&state_db).map_err(|e| e.to_string())?,
        ));
        let cas = Arc::new(
            Store::open(
                &cas_root.ok_or("--cas-root is required")?,
                StoreConfig::default(),
            )
            .map_err(|e| e.to_string())?,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        // The operator's ranges apply to every download: assets and TUF.
        let ranges = config.extra_ranges.clone();
        let connector = RustlsConnector::with_native_roots().map_err(|e| e.to_string())?;
        let downloader = Arc::new(AssetDownloader::new(connector, config, None));
        let fetcher = LazyFetcher::new(
            Arc::clone(&cas),
            Arc::clone(&downloader),
            StatePins(Arc::clone(&owner)),
            runtime.handle().clone(),
        );
        serve_channel(
            listener,
            PeerRule::OnlyUid(reader),
            FETCH_LIMITS,
            move |request: FetchRequest, _uid| -> FetchResponse { answer_fetch(&fetcher, request) },
        )
        .map_err(|e| e.to_string())?;
        // The status and administrative channels, when systemd passed them
        // (P4-001a). There is no fallback bind (ADR-029 point 1).
        let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
        let mut channels = Vec::new();
        if names
            .split(':')
            .any(|name| name == "status" || name == "admin")
        {
            let status = inherited_unix_listener("status").map_err(|e| e.to_string())?;
            let admin = inherited_unix_listener("admin").map_err(|e| e.to_string())?;
            let client = || -> Result<GitHubClient<HttpTransport<RustlsConnector>>, String> {
                Ok(GitHubClient::new(
                    HttpTransport::new(
                        RustlsConnector::with_native_roots().map_err(|e| e.to_string())?,
                        HttpConfig::default(),
                    ),
                    None,
                ))
            };
            let verifier = match &tuf_cache {
                None => None,
                Some(cache) => match verifier(&runtime, cache, ranges.clone()) {
                    Ok(verifier) => Some(Arc::new(verifier)),
                    Err(error) => {
                        eprintln!("event=trusted_roots_unavailable error={error}");
                        None
                    }
                },
            };
            let mut service = StateService::new(
                Arc::clone(&owner),
                client()?,
                verifier.clone(),
                runtime.handle().clone(),
                now,
            )
            .map_err(|e| e.to_string())?;
            if let Some(parts) = parts {
                let collector_home = pipeline.collector_home.clone().unwrap_or_else(|| {
                    state_db
                        .parent()
                        .unwrap_or_else(|| Path::new("/"))
                        .join("collector")
                });
                let production = Production {
                    github: client()?,
                    verifier,
                    runtime: runtime.handle().clone(),
                    fetch: CasFetch {
                        cas: Arc::clone(&cas),
                        downloader: Arc::clone(&downloader),
                        runtime: runtime.handle().clone(),
                    },
                    inspector: SocketInspector::new(
                        &parts.inspect_socket,
                        Duration::from_secs(120),
                    ),
                    publish_root: parts.publish_root,
                    signer: SocketSigner::new(&parts.sign_socket),
                    metadata_verifier: GpgvVerifier::new(&parts.keyring, parts.fingerprint)
                        .map_err(|e| e.to_string())?,
                    keyring: std::fs::read(&parts.keyring).map_err(|e| e.to_string())?,
                    applier: SocketApplier {
                        path: parts.apply_socket,
                        timeout: Duration::from_secs(120),
                    },
                    port: pipeline.port.unwrap_or(DEFAULT_PORT),
                    collector_home,
                    max_freshness: MAX_FRESHNESS,
                };
                service = service.with_pipeline(Box::new(production));
            }
            let server = Server::new(service).map_err(|e| e.to_string())?;
            server
                .serve_status(status, PeerRule::AnyUser, Limits::STATUS)
                .map_err(|e| e.to_string())?;
            // Administrative requests need root (ADR-029 point 2).
            server
                .serve_admin(admin, PeerRule::OnlyUid(0), Limits::ADMIN)
                .map_err(|e| e.to_string())?;
            channels.push(server);
        } else if parts.is_some() {
            return Err("the pipeline needs the status and admin listeners".to_owned());
        }
        eprintln!(
            "event=start pid={} reader_uid={reader} admin={}",
            std::process::id(),
            !channels.is_empty()
        );
        // The downloads run on this runtime; the channel threads block on them.
        runtime.block_on(std::future::pending::<()>());
        Ok(())
    }
}
