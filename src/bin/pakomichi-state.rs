// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pakomichi-state`: the state owner (ADR-017 point 7, ADR-035).
//!
//! ```text
//! pakomichi-state --state-db FILE --cas-root DIR
//!                 --fetch-socket /run/pakomichi/fetch.sock
//!                 [--allow-range CIDR,CIDR]
//! ```
//!
//! This part (P2-013b) serves the lazy-fetch channel: the listener comes
//! from systemd under the name `fetch`; only the uid owning the socket
//! file (the reader) is admitted; a request downloads a pinned object into
//! the CAS (`lazy::LazyFetcher`, pins from the state database). The status
//! and administrative channels join with the CLI (P4-001a).

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
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use pakomichi::cas::{Store, StoreConfig};
    use pakomichi::github::{AddressRange, AssetDownloader, DownloadConfig, RustlsConnector};
    use pakomichi::ipc::channels::{FetchRequest, FetchResponse};
    use pakomichi::ipc::oneshot::{FETCH_LIMITS, serve_channel};
    use pakomichi::ipc::server::PeerRule;
    use pakomichi::lazy::{LazyFetcher, StatePins, answer_fetch};
    use pakomichi::process::{inherited_unix_listener, require_unprivileged, socket_owner};
    use pakomichi::state::StateOwner;

    pub fn run() -> Result<(), String> {
        // The role is checked before anything else is read.
        require_unprivileged().map_err(|e| e.to_string())?;
        let mut state_db = None;
        let mut cas_root = None;
        let mut fetch_socket = None;
        let mut config = DownloadConfig::default();
        let mut arguments = std::env::args().skip(1);
        while let Some(name) = arguments.next() {
            let value = arguments.next().ok_or(format!("{name} needs a value"))?;
            match name.as_str() {
                "--state-db" => state_db = Some(PathBuf::from(value)),
                "--cas-root" => cas_root = Some(PathBuf::from(value)),
                "--fetch-socket" => fetch_socket = Some(PathBuf::from(value)),
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
        let fetch_socket = fetch_socket.ok_or("--fetch-socket is required")?;
        let reader = socket_owner(&fetch_socket).map_err(|e| e.to_string())?;
        let listener = inherited_unix_listener("fetch").map_err(|e| e.to_string())?;
        let owner = StateOwner::open(&state_db.ok_or("--state-db is required")?)
            .map_err(|e| e.to_string())?;
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
        let connector = RustlsConnector::with_native_roots().map_err(|e| e.to_string())?;
        let downloader = Arc::new(AssetDownloader::new(connector, config, None));
        let fetcher = LazyFetcher::new(
            cas,
            downloader,
            StatePins(Mutex::new(owner)),
            runtime.handle().clone(),
        );
        serve_channel(
            listener,
            PeerRule::OnlyUid(reader),
            FETCH_LIMITS,
            move |request: FetchRequest, _uid| -> FetchResponse { answer_fetch(&fetcher, request) },
        )
        .map_err(|e| e.to_string())?;
        eprintln!("event=start pid={} reader_uid={reader}", std::process::id());
        // The downloads run on this runtime; the channel threads block on them.
        runtime.block_on(std::future::pending::<()>());
        Ok(())
    }
}
