// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fetches one pinned GitHub release asset into a CAS through the
//! production lazy fetcher (P3-005b research tool).
//!
//! ```text
//! p3005b-fetch --cas DIR --repository ID --asset ID --sha256 HEX --size N
//!              [--asset-hosts HOST,HOST|none] [--allow-range CIDR,CIDR]
//! ```
//!
//! Real TLS (rustls with the system roots), the system resolver, public
//! addresses only, anonymous. Prints `stored <sha256>` or
//! `failed <http status> <error>`; exit 0, 3 on a refusal, 2 on misuse.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use pakomichi::cas::{ExpectedObject, Sha256Digest, Store, StoreConfig};
use pakomichi::github::{
    AddressRange, AssetDownloader, AssetId, AssetLocator, DownloadConfig, RepositoryId,
    RustlsConnector,
};
use pakomichi::lazy::{Fetch, LazyFetcher, Locate};

struct One(Sha256Digest, AssetLocator);

impl Locate for One {
    fn locate(&self, object: &ExpectedObject) -> Option<AssetLocator> {
        (object.sha256 == self.0).then_some(self.1)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("p3005b-fetch: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8, String> {
    let mut values = HashMap::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let name = argument.strip_prefix("--").ok_or(format!("unexpected {argument}"))?;
        values.insert(name.to_owned(), arguments.next().ok_or(format!("--{name} needs a value"))?);
    }
    let get = |name: &str| values.get(name).cloned().ok_or(format!("--{name} is required"));
    let number = |name: &str| -> Result<u64, String> {
        get(name)?.parse().map_err(|e| format!("--{name}: {e}"))
    };
    let locator = AssetLocator {
        repository: RepositoryId::new(number("repository")?).map_err(|e| e.to_string())?,
        asset: AssetId::new(number("asset")?).map_err(|e| e.to_string())?,
    };
    let sha256 = Sha256Digest::from_hex(&get("sha256")?).map_err(|e| e.to_string())?;
    let expected = ExpectedObject::new(sha256, number("size")?);
    let mut config = DownloadConfig::default();
    if let Some(hosts) = values.get("asset-hosts") {
        config.asset_hosts = if hosts == "none" {
            Vec::new()
        } else {
            hosts.split(',').map(str::to_owned).collect()
        };
    }
    if let Some(ranges) = values.get("allow-range") {
        config.extra_ranges = ranges
            .split(',')
            .map(AddressRange::parse)
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
    }
    let cas = Arc::new(
        Store::open(&PathBuf::from(get("cas")?), StoreConfig::default()).map_err(|e| e.to_string())?,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let connector = RustlsConnector::with_native_roots().map_err(|e| e.to_string())?;
    let downloader = Arc::new(AssetDownloader::new(connector, config, None));
    let fetcher = LazyFetcher::new(Arc::clone(&cas), downloader, One(sha256, locator), runtime.handle().clone());
    // The fetch blocks; the download runs on the runtime meanwhile.
    let result = runtime.block_on(async move {
        tokio::task::spawn_blocking(move || fetcher.fetch(expected))
            .await
            .map_err(|e| e.to_string())
    })?;
    match result {
        Ok(()) => {
            println!("stored {}", sha256.to_hex());
            Ok(0)
        }
        Err(error) => {
            println!("failed {} {error}", error.http_status());
            Ok(3)
        }
    }
}
