// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lazy fetch of a pinned object from an upstream URL into the CAS.
//!
//! Every hop is resolved once, each resolved address is checked against the
//! address policy, and the connection goes to the vetted address (no second
//! resolution). The body goes to a staging file and becomes an object only
//! after the size and SHA-256 match the manifest. Plain HTTP only: the
//! research upstream is a local fault-injecting mock; TLS is not in scope.

use crate::store::{Entry, Store, sync_dir, to_hex};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct FetchConfig {
    /// The one upstream origin allowed despite being loopback (the mock).
    pub upstream_allow: Option<SocketAddr>,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_hops: usize,
}

#[derive(Debug)]
pub enum FetchError {
    Policy(String),
    Network(String),
    Timeout(String),
    Integrity(String),
    Storage(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(m) => write!(f, "policy: {m}"),
            Self::Network(m) => write!(f, "network: {m}"),
            Self::Timeout(m) => write!(f, "timeout: {m}"),
            Self::Integrity(m) => write!(f, "integrity: {m}"),
            Self::Storage(m) => write!(f, "storage: {m}"),
        }
    }
}

pub fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0))
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return ip_allowed(IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x64 && s[1] == 0xff9b))
        }
    }
}

struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<Url, FetchError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| FetchError::Policy(format!("unsupported scheme in {url}")))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains('@') || authority.is_empty() {
        return Err(FetchError::Policy("credentials or empty host in URL".to_owned()));
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (h, tail) = stripped
            .split_once(']')
            .ok_or_else(|| FetchError::Policy("bad IPv6 literal".to_owned()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| FetchError::Policy("bad port".to_owned()))?,
            None => 80,
        };
        (h.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().map_err(|_| FetchError::Policy("bad port".to_owned()))?),
            None => (authority.to_owned(), 80),
        }
    };
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(FetchError::Policy("control or space in URL path".to_owned()));
    }
    Ok(Url { host, port, path: path.to_owned() })
}

async fn vetted_address(config: &FetchConfig, url: &Url) -> Result<SocketAddr, FetchError> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await
        .map_err(|e| FetchError::Network(format!("resolve {}: {e}", url.host)))?
        .collect();
    if addresses.is_empty() {
        return Err(FetchError::Network(format!("{} resolved to nothing", url.host)));
    }
    // Every resolved address must pass; a mixed answer is refused.
    for address in &addresses {
        let allowed = config.upstream_allow == Some(*address) || ip_allowed(address.ip());
        if !allowed {
            return Err(FetchError::Policy(format!("address {address} of {} is not allowed", url.host)));
        }
    }
    Ok(addresses[0])
}

/// Fetches `entry` into the CAS. On any error nothing is published and the
/// staging file is removed.
pub async fn fetch_into_store(store: &Store, config: &FetchConfig, entry: &Entry) -> Result<(), FetchError> {
    let start = Instant::now();
    let mut url_text = entry
        .url
        .clone()
        .ok_or_else(|| FetchError::Policy("entry has no upstream URL".to_owned()))?;
    for hop in 0..=config.max_hops {
        let url = parse_url(&url_text)?;
        let address = vetted_address(config, &url).await?;
        let mut stream = timeout(config.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| FetchError::Timeout(format!("connect {address}")))?
            .map_err(|e| FetchError::Network(format!("connect {address}: {e}")))?;
        let host_header = if url.port == 80 { url.host.clone() } else { format!("{}:{}", url.host, url.port) };
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: pakomichi-r004\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            url.path
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?;

        let (status, headers, leftover) = read_head(&mut stream, config).await?;
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if hop == config.max_hops {
                return Err(FetchError::Policy("too many redirects".to_owned()));
            }
            let location = header("location").ok_or_else(|| FetchError::Network("redirect without Location".to_owned()))?;
            url_text = if location.starts_with('/') {
                format!("http://{host_header}{location}")
            } else {
                location
            };
            eprintln!("event=fetch-redirect object={} to={url_text}", entry.sha256);
            continue;
        }
        if status != 200 {
            return Err(FetchError::Network(format!("upstream status {status}")));
        }
        if header("transfer-encoding").is_some() {
            return Err(FetchError::Network("chunked/encoded upstream bodies are not accepted".to_owned()));
        }
        match header("content-length").map(|v| v.parse::<u64>()) {
            Some(Ok(length)) if length == entry.size => {}
            Some(Ok(length)) => {
                return Err(FetchError::Integrity(format!(
                    "upstream length {length} differs from pinned size {}",
                    entry.size
                )));
            }
            _ => return Err(FetchError::Network("missing or invalid Content-Length".to_owned())),
        }
        return write_body(store, config, entry, stream, leftover, start).await;
    }
    Err(FetchError::Policy("too many redirects".to_owned()))
}

async fn read_head(
    stream: &mut TcpStream,
    config: &FetchConfig,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), FetchError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
            let leftover = buffer[end + 4..].to_vec();
            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap_or_default();
            let status = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or_else(|| FetchError::Network(format!("bad status line {status_line:?}")))?;
            let headers = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
                .collect();
            return Ok((status, headers, leftover));
        }
        if buffer.len() > 16 * 1024 {
            return Err(FetchError::Network("upstream header too large".to_owned()));
        }
        let count = timeout(config.idle_timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| FetchError::Timeout("waiting for upstream headers".to_owned()))?
            .map_err(|e| FetchError::Network(e.to_string()))?;
        if count == 0 {
            return Err(FetchError::Network("upstream closed before headers".to_owned()));
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
}

async fn write_body(
    store: &Store,
    config: &FetchConfig,
    entry: &Entry,
    mut stream: TcpStream,
    leftover: Vec<u8>,
    start: Instant,
) -> Result<(), FetchError> {
    let staging = store.fetch_tmp().join(format!(
        "{}.{}.{}.part",
        entry.sha256,
        std::process::id(),
        start.elapsed().as_nanos()
    ));
    let result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staging)
            .await
            .map_err(|e| FetchError::Storage(e.to_string()))?;
        let mut hasher = Sha256::new();
        let mut received = 0_u64;
        let mut pending = leftover;
        let mut chunk = vec![0_u8; 128 * 1024];
        loop {
            if !pending.is_empty() {
                received += pending.len() as u64;
                if received > entry.size {
                    return Err(FetchError::Integrity("upstream sent more bytes than pinned".to_owned()));
                }
                hasher.update(&pending);
                file.write_all(&pending).await.map_err(|e| FetchError::Storage(e.to_string()))?;
                pending.clear();
            }
            if received == entry.size {
                break;
            }
            if start.elapsed() > config.total_timeout {
                return Err(FetchError::Timeout("total download time exceeded".to_owned()));
            }
            let count = timeout(config.idle_timeout, stream.read(&mut chunk))
                .await
                .map_err(|_| FetchError::Timeout(format!("upstream stalled after {received} bytes")))?
                .map_err(|e| FetchError::Network(e.to_string()))?;
            if count == 0 {
                return Err(FetchError::Network(format!(
                    "upstream closed after {received} of {} bytes",
                    entry.size
                )));
            }
            pending.extend_from_slice(&chunk[..count]);
        }
        let actual = to_hex(&hasher.finalize());
        if actual != entry.sha256 {
            return Err(FetchError::Integrity(format!("downloaded bytes hash to {actual}")));
        }
        file.flush().await.map_err(|e| FetchError::Storage(e.to_string()))?;
        pause_async("fetch-after-write").await;
        file.sync_all().await.map_err(|e| FetchError::Storage(e.to_string()))?;
        drop(file);
        pause_async("fetch-after-fsync").await;
        tokio::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o444))
            .await
            .map_err(|e| FetchError::Storage(e.to_string()))?;
        tokio::fs::rename(&staging, store.object_path(&entry.sha256))
            .await
            .map_err(|e| FetchError::Storage(e.to_string()))?;
        pause_async("fetch-after-rename").await;
        let objects = store.objects();
        tokio::task::spawn_blocking(move || sync_dir(&objects))
            .await
            .map_err(|e| FetchError::Storage(e.to_string()))?
            .map_err(|e| FetchError::Storage(e.to_string()))?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&staging).await;
    }
    result
}

async fn pause_async(name: &str) {
    if std::env::var("R004_TEST_PAUSE_AT").as_deref() == Ok(name) {
        eprintln!("event=pause point={name} pid={}", std::process::id());
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_policy() -> Result<(), std::net::AddrParseError> {
        for denied in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0",
            "100.64.0.1", "198.18.0.1", "224.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1",
        ] {
            assert!(!ip_allowed(denied.parse()?), "{denied} must be denied");
        }
        for allowed in ["140.82.112.3", "185.199.108.153", "2606:50c0:8000::153"] {
            assert!(ip_allowed(allowed.parse()?), "{allowed} must be allowed");
        }
        Ok(())
    }

    #[test]
    fn url_parsing() {
        assert!(parse_url("https://example.com/x").is_err());
        assert!(parse_url("http://user:pw@example.com/x").is_err());
        assert!(matches!(parse_url("http://[::1]:8080/a"), Ok(Url { port: 8080, .. })));
        assert!(matches!(parse_url("http://example.com/a"), Ok(Url { port: 80, .. })));
    }
}
