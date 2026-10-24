// SPDX-License-Identifier: MIT OR Apache-2.0
//! Calls the channels of ADR-035 through the production clients (P2-013b
//! research tool).
//!
//! ```text
//! p2013b-call sign SOCKET TEXT-FILE OUT-FILE
//! p2013b-call inspect SOCKET SHA256 SIZE
//! p2013b-call fetch SOCKET SHA256 SIZE
//! ```
//!
//! Prints one result line; exit 0 on success, 3 on a refusal or error.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use pakomichi::cas::{ExpectedObject, Sha256Digest};
use pakomichi::inspect::SocketInspector;
use pakomichi::lazy::{Fetch, FetchClient};
use pakomichi::publish::sign::{MetadataSigner, SocketSigner};

fn main() -> ExitCode {
    match run() {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(line) => {
            println!("{line}");
            ExitCode::from(3)
        }
    }
}

fn object(sha: &str, size: &str) -> Result<ExpectedObject, String> {
    Ok(ExpectedObject::new(
        Sha256Digest::from_hex(sha).map_err(|e| format!("usage: {e}"))?,
        size.parse().map_err(|e| format!("usage: {e}"))?,
    ))
}

fn run() -> Result<String, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let argument = |index: usize| arguments.get(index).cloned().ok_or("usage: missing argument".to_owned());
    let socket = argument(1)?;
    let socket = Path::new(&socket);
    match argument(0)?.as_str() {
        "sign" => {
            let text = std::fs::read(argument(2)?).map_err(|e| e.to_string())?;
            let message = SocketSigner::new(socket)
                .clearsign(&text)
                .map_err(|e| format!("failed {e}"))?;
            std::fs::write(argument(3)?, &message).map_err(|e| e.to_string())?;
            Ok(format!("signed {} bytes", message.len()))
        }
        "inspect" => {
            let inspection = SocketInspector::new(socket, Duration::from_secs(60))
                .inspect_deb(object(&argument(2)?, &argument(3)?)?)
                .map_err(|e| format!("failed {e}"))?;
            let control = inspection.control();
            Ok(format!(
                "deb {} {} {} scripts={}",
                control.package(),
                control.version(),
                control.architecture(),
                inspection.maintainer_scripts().len()
            ))
        }
        "fetch" => {
            FetchClient::new(socket, Duration::from_secs(120))
                .fetch(object(&argument(2)?, &argument(3)?)?)
                .map_err(|e| format!("failed {} {e}", e.http_status()))?;
            Ok("stored".to_owned())
        }
        other => Err(format!("usage: unknown command {other}")),
    }
}
