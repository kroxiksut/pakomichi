// SPDX-License-Identifier: MIT OR Apache-2.0

use listenfd::ListenFd;
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_IN_FLIGHT: usize = 4;
const MAX_PROBE_REQUESTS: usize = 32;

fn activated_loopback_listener() -> io::Result<TcpListener> {
    let mut descriptors = ListenFd::from_env();
    let listener = descriptors.take_tcp_listener(0)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "exactly one socket-activated TCP listener is required",
        )
    })?;
    let address = listener.local_addr()?;
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing a non-loopback listener",
        ));
    }
    Ok(listener)
}

fn expected_requests() -> io::Result<usize> {
    let raw = std::env::var("PAKOMICHI_PROBE_REQUESTS").unwrap_or_else(|_| "1".to_owned());
    let count = raw.parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid PAKOMICHI_PROBE_REQUESTS: {error}"),
        )
    })?;
    if count == 0 || count > MAX_PROBE_REQUESTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("request count must be between 1 and {MAX_PROBE_REQUESTS}"),
        ));
    }
    Ok(count)
}

async fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut request = [0_u8; MAX_REQUEST_BYTES];
    let count = timeout(Duration::from_secs(2), stream.read(&mut request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request read timed out"))??;
    let request_line = request[..count]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();

    let (status, body) = if request_line.starts_with(b"GET /health HTTP/")
        || request_line.starts_with(b"HEAD /health HTTP/")
    {
        ("200 OK", "ok\n")
    } else if request_line.starts_with(b"GET /blocking-probe HTTP/") {
        tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(2)))
            .await
            .map_err(|error| io::Error::other(format!("blocking worker failed: {error}")))?;
        ("200 OK", "blocking work completed\n")
    } else {
        ("405 Method Not Allowed", "method not allowed\n")
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> io::Result<()> {
    let listener = activated_loopback_listener()?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = JoinSet::new();

    for _ in 0..expected_requests()? {
        let (stream, _) = listener.accept().await?;
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .map_err(|error| io::Error::other(format!("request limiter closed: {error}")))?;
        tasks.spawn(async move {
            let _permit = permit;
            handle_connection(stream).await
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.map_err(|error| io::Error::other(format!("request task failed: {error}")))??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_work_does_not_starve_async_timers() -> Result<(), Box<dyn Error>> {
        let blocking = tokio::task::spawn_blocking(|| {
            std::thread::sleep(Duration::from_millis(100));
        });
        timeout(
            Duration::from_millis(50),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await?;
        blocking.await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn semaphore_bounds_parallel_work() -> Result<(), Box<dyn Error>> {
        let permits = Arc::new(Semaphore::new(2));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        for _ in 0..8 {
            let permit = Arc::clone(&permits).acquire_owned().await?;
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            tasks.spawn(async move {
                let _permit = permit;
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while let Some(result) = tasks.join_next().await {
            result?;
        }

        assert_eq!(peak.load(Ordering::SeqCst), 2);
        Ok(())
    }
}
