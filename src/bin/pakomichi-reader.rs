// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pakomichi-reader`: serves the published logical repositories read-only
//! on loopback (P3-005a).
//!
//! ```text
//! pakomichi-reader --publish-root DIR --cas-root DIR
//!                  [--retention-seconds N] [--listen 127.0.0.1:PORT]
//! ```
//!
//! The socket comes from systemd socket activation (`LISTEN_FDS`). Without
//! an inherited socket the reader binds only an explicit loopback address
//! given with `--listen` (the ordinary-service fallback of ADR-007); it never
//! picks an address itself and never binds a non-loopback one.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match unix::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("event=fatal error={message}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("pakomichi-reader runs only on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
mod unix {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use pakomichi::reader::{DEFAULT_RETENTION, Limits, Repositories, serve};

    struct Options {
        publish_root: PathBuf,
        cas_root: PathBuf,
        retention: Duration,
        listen: Option<SocketAddr>,
    }

    fn options() -> Result<Options, String> {
        let mut publish_root = None;
        let mut cas_root = None;
        let mut retention = DEFAULT_RETENTION;
        let mut listen = None;
        let mut arguments = std::env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            let name = argument.to_string_lossy().into_owned();
            let value = arguments
                .next()
                .ok_or_else(|| format!("{name} needs a value"))?;
            match name.as_str() {
                "--publish-root" => publish_root = Some(PathBuf::from(value)),
                "--cas-root" => cas_root = Some(PathBuf::from(value)),
                "--retention-seconds" => {
                    let seconds = value
                        .to_str()
                        .and_then(|text| text.parse::<u64>().ok())
                        .ok_or("--retention-seconds needs a number")?;
                    retention = Duration::from_secs(seconds);
                }
                "--listen" => {
                    let address = value
                        .to_str()
                        .and_then(|text| text.parse::<SocketAddr>().ok())
                        .ok_or("--listen needs an address such as 127.0.0.1:8080")?;
                    if !address.ip().is_loopback() {
                        return Err(format!("refusing non-loopback --listen {address}"));
                    }
                    listen = Some(address);
                }
                _ => return Err(format!("unknown argument {name}")),
            }
        }
        Ok(Options {
            publish_root: publish_root.ok_or("--publish-root is required")?,
            cas_root: cas_root.ok_or("--cas-root is required")?,
            retention,
            listen,
        })
    }

    fn listener(listen: Option<SocketAddr>) -> Result<std::net::TcpListener, String> {
        let mut inherited = listenfd::ListenFd::from_env();
        if let Some(listener) = inherited
            .take_tcp_listener(0)
            .map_err(|error| format!("inherited socket: {error}"))?
        {
            return Ok(listener);
        }
        let address = listen.ok_or("no socket from systemd and no --listen address")?;
        std::net::TcpListener::bind(address).map_err(|error| format!("bind {address}: {error}"))
    }

    pub fn run() -> Result<(), String> {
        let options = options()?;
        let repositories =
            Repositories::open(&options.publish_root, &options.cas_root, options.retention)
                .map_err(|error| error.to_string())?;
        let listener = listener(options.listen)?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("socket: {error}"))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(16)
            .build()
            .map_err(|error| format!("runtime: {error}"))?;
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener)
                .map_err(|error| format!("socket: {error}"))?;
            eprintln!(
                "event=start pid={} listen={} retention_s={}",
                std::process::id(),
                listener
                    .local_addr()
                    .map_or_else(|_| "?".to_owned(), |address| address.to_string()),
                options.retention.as_secs()
            );
            serve(listener, Arc::new(repositories), Limits::default())
                .await
                .map_err(|error| error.to_string())
        })
    }
}
