// SPDX-License-Identifier: MIT OR Apache-2.0
//! R-004 research tool. Subcommands:
//!   serve                     socket-activated (or R004_LISTEN fallback) reader
//!   publish ROOT REPO ID DIR [--lazy FILE] [--keyring FILE]
//!   check ROOT | reconcile ROOT | gc ROOT KEEP
//!   bench ADDR TARGET CONNECTIONS REQUESTS

mod fetch;
mod serve;
mod store;

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn env_secs(name: &str, default: u64) -> Duration {
    Duration::from_secs(std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default))
}

fn listener() -> Result<TcpListener, String> {
    let mut descriptors = listenfd::ListenFd::from_env();
    if let Some(listener) = descriptors.take_tcp_listener(0).map_err(|e| e.to_string())? {
        return Ok(listener);
    }
    // ADR-007 fallback: an ordinary service binds the same loopback address.
    let address: SocketAddr = std::env::var("R004_LISTEN")
        .map_err(|_| "no socket-activated listener and no R004_LISTEN".to_owned())?
        .parse()
        .map_err(|e| format!("R004_LISTEN: {e}"))?;
    if !address.ip().is_loopback() {
        return Err("refusing a non-loopback R004_LISTEN".to_owned());
    }
    TcpListener::bind(address).map_err(|e| format!("bind {address}: {e}"))
}

fn serve() -> Result<(), String> {
    let root = PathBuf::from(std::env::var("R004_ROOT").map_err(|_| "R004_ROOT is required")?);
    let idle = std::env::var("R004_IDLE_EXIT_SECS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let upstream_allow = match std::env::var("R004_UPSTREAM_ALLOW") {
        Ok(v) => Some(v.parse::<SocketAddr>().map_err(|e| format!("R004_UPSTREAM_ALLOW: {e}"))?),
        Err(_) => None,
    };
    let config = serve::ServeConfig {
        root,
        idle_exit: (idle > 0).then(|| Duration::from_secs(idle)),
        verify_on_serve: std::env::var("R004_VERIFY_ON_SERVE").as_deref() != Ok("0"),
        retention: std::env::var("R004_RETENTION").as_deref() != Ok("0"),
        pin_connection: std::env::var("R004_PIN_CONNECTION").as_deref() == Ok("1"),
        max_connections: 64,
        hold: std::env::var("R004_TEST_HOLD").ok(),
        gate: std::env::var("R004_TEST_GATE").ok().map(PathBuf::from),
        fetch: fetch::FetchConfig {
            upstream_allow,
            connect_timeout: env_secs("R004_FETCH_CONNECT_SECS", 5),
            idle_timeout: env_secs("R004_FETCH_IDLE_SECS", 10),
            total_timeout: env_secs("R004_FETCH_TOTAL_SECS", 120),
            max_hops: 3,
        },
    };
    let listener = listener()?;
    serve::run(config, listener).map_err(|e| e.to_string())
}

struct BenchStats {
    ok: AtomicUsize,
    failed: AtomicUsize,
    bytes: AtomicUsize,
}

async fn one_request(address: SocketAddr, target: &str) -> Result<usize, String> {
    let mut stream = tokio::net::TcpStream::connect(address).await.map_err(|e| e.to_string())?;
    let request = format!("GET {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.map_err(|e| e.to_string())?;
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no response head")?;
    let head = String::from_utf8_lossy(&response[..end]);
    if !head.starts_with("HTTP/1.1 200 ") {
        return Err(head.lines().next().unwrap_or_default().to_owned());
    }
    let length = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .ok_or("no Content-Length")?;
    let body = response.len() - end - 4;
    if body != length {
        return Err(format!("body {body} != Content-Length {length}"));
    }
    Ok(body)
}

fn bench(args: &[String]) -> Result<(), String> {
    let [address, target, connections, requests] = args else {
        return Err("bench ADDR TARGET CONNECTIONS REQUESTS".to_owned());
    };
    let address: SocketAddr = address.parse().map_err(|e| format!("{e}"))?;
    let connections: usize = connections.parse().map_err(|e| format!("{e}"))?;
    let requests: usize = requests.parse().map_err(|e| format!("{e}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let stats = Arc::new(BenchStats { ok: AtomicUsize::new(0), failed: AtomicUsize::new(0), bytes: AtomicUsize::new(0) });
    let next = Arc::new(AtomicUsize::new(0));
    let latencies = Arc::new(std::sync::Mutex::new(Vec::with_capacity(requests)));
    let started = Instant::now();
    runtime.block_on(async {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..connections {
            let (stats, next, latencies, target) =
                (Arc::clone(&stats), Arc::clone(&next), Arc::clone(&latencies), target.clone());
            tasks.spawn(async move {
                while next.fetch_add(1, Ordering::SeqCst) < requests {
                    let t = Instant::now();
                    match one_request(address, &target).await {
                        Ok(bytes) => {
                            stats.ok.fetch_add(1, Ordering::SeqCst);
                            stats.bytes.fetch_add(bytes, Ordering::SeqCst);
                        }
                        Err(error) => {
                            if stats.failed.fetch_add(1, Ordering::SeqCst) < 3 {
                                eprintln!("bench error: {error}");
                            }
                        }
                    }
                    if let Ok(mut l) = latencies.lock() {
                        l.push(t.elapsed().as_micros());
                    }
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    });
    let seconds = started.elapsed().as_secs_f64();
    let mut l = latencies.lock().map_err(|e| e.to_string())?.clone();
    l.sort_unstable();
    let pct = |p: f64| l.get(((l.len() as f64 - 1.0) * p) as usize).copied().unwrap_or(0) as f64 / 1000.0;
    let ok = stats.ok.load(Ordering::SeqCst);
    let bytes = stats.bytes.load(Ordering::SeqCst);
    println!(
        "bench target={target} connections={connections} ok={ok} failed={} seconds={seconds:.3} req_per_s={:.1} mib_per_s={:.1} p50_ms={:.2} p99_ms={:.2}",
        stats.failed.load(Ordering::SeqCst),
        ok as f64 / seconds,
        bytes as f64 / seconds / 1_048_576.0,
        pct(0.5),
        pct(0.99)
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or_default();
    match command {
        "serve" => serve(),
        "publish" => {
            let [_, root, repo, id, from, rest @ ..] = args.as_slice() else {
                return Err("publish ROOT REPO ID DIR [--lazy FILE] [--keyring FILE]".to_owned());
            };
            let mut publish = store::PublishArgs {
                root: root.into(),
                repo: repo.clone(),
                id: id.clone(),
                from: from.into(),
                lazy: None,
                keyring: None,
            };
            let mut rest = rest.iter();
            while let Some(flag) = rest.next() {
                let value = rest.next().ok_or(format!("{flag} needs a value"))?;
                match flag.as_str() {
                    "--lazy" => publish.lazy = Some(value.into()),
                    "--keyring" => publish.keyring = Some(value.into()),
                    _ => return Err(format!("unknown flag {flag}")),
                }
            }
            println!("{}", store::publish(&publish)?);
            Ok(())
        }
        "check" | "reconcile" | "gc" => {
            let root = args.get(1).ok_or("ROOT is required")?;
            let store = store::Store::new(std::path::Path::new(root));
            let lines = match command {
                "check" => store::check(&store)?,
                "reconcile" => store::reconcile(&store)?,
                _ => {
                    let keep = args.get(2).and_then(|v| v.parse().ok()).ok_or("gc ROOT KEEP")?;
                    store::gc(&store, keep)?
                }
            };
            for line in &lines {
                println!("{line}");
            }
            if command == "check" && !lines.is_empty() {
                return Err(format!("{} problem(s)", lines.len()));
            }
            println!("{command}: ok");
            Ok(())
        }
        "bench" => bench(&args[1..]),
        _ => Err("usage: serve | publish | check | reconcile | gc | bench".to_owned()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
