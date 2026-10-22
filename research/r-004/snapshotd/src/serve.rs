// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only loopback HTTP/1.1 server for logical repositories.
//!
//! URL: /<repo>/<path>. Mutable paths (InRelease, repomd.xml, plain
//! Packages) come only from the current generation; content-addressed paths
//! come from any retained generation. GET and HEAD only.

use crate::fetch::{FetchConfig, FetchError, fetch_into_store};
use crate::store::{self, Entry, Store, is_immutable, open_nofollow, valid_name, valid_repo_path};
use std::collections::HashMap;
use std::io::{self, Seek, SeekFrom};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

const MAX_HEAD: usize = 8 * 1024;
const MAX_TARGET: usize = 2 * 1024;

pub struct ServeConfig {
    pub root: PathBuf,
    pub idle_exit: Option<Duration>,
    pub verify_on_serve: bool,
    pub retention: bool,
    pub pin_connection: bool,
    pub max_connections: usize,
    pub hold: Option<String>,
    pub gate: Option<PathBuf>,
    pub fetch: FetchConfig,
}

/// Repository path -> manifest entry of one generation.
type PathMap = Arc<HashMap<String, Entry>>;

struct RepoView {
    current: String,
    current_map: HashMap<String, Entry>,
    retained: HashMap<String, Entry>,
}

struct Server {
    config: ServeConfig,
    store: Store,
    allowed_hosts: Vec<String>,
    views: Mutex<HashMap<String, Arc<RepoView>>>,
    generation_maps: Mutex<HashMap<(String, String), PathMap>>,
    inflight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    active: AtomicUsize,
    last_activity: Mutex<Instant>,
}

enum Reply {
    Status(u16, &'static str),
    File { file: std::fs::File, size: u64, generation: String },
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        507 => "Insufficient Storage",
        _ => "Error",
    }
}

pub fn run(config: ServeConfig, listener: TcpListener) -> io::Result<()> {
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "refusing a non-loopback listener"));
    }
    let store = Store::new(&config.root);
    // Startup recovery for this process's own staging area.
    if let Ok(entries) = std::fs::read_dir(store.fetch_tmp()) {
        for entry in entries.flatten() {
            eprintln!("event=startup-remove-staging file={}", entry.file_name().to_string_lossy());
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let port = local.port();
    let allowed_hosts = vec![
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    let server = Arc::new(Server {
        config,
        store,
        allowed_hosts,
        views: Mutex::new(HashMap::new()),
        generation_maps: Mutex::new(HashMap::new()),
        inflight: Mutex::new(HashMap::new()),
        active: AtomicUsize::new(0),
        last_activity: Mutex::new(Instant::now()),
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .enable_all()
        .build()?;
    runtime.block_on(accept_loop(server, listener, local))
}

async fn accept_loop(server: Arc<Server>, listener: TcpListener, local: SocketAddr) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let permits = Arc::new(Semaphore::new(server.config.max_connections));
    eprintln!(
        "event=start pid={} listen={local} verify_on_serve={} retention={} pin_connection={}",
        std::process::id(),
        server.config.verify_on_serve,
        server.config.retention,
        server.config.pin_connection
    );
    loop {
        let accepted = match server.config.idle_exit {
            Some(idle) => match timeout(Duration::from_secs(1), listener.accept()).await {
                Ok(result) => Some(result),
                Err(_) => {
                    let quiet = server.last_activity.lock().map(|t| t.elapsed()).unwrap_or_default();
                    if server.active.load(Ordering::SeqCst) == 0 && quiet >= idle {
                        eprintln!("event=idle-exit quiet_ms={}", quiet.as_millis());
                        return Ok(());
                    }
                    None
                }
            },
            None => Some(listener.accept().await),
        };
        let Some(accepted) = accepted else { continue };
        let (stream, peer) = accepted?;
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let server = Arc::clone(&server);
        server.active.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = connection(&server, stream, peer.port()).await {
                eprintln!("event=connection-error error={error}");
            }
            server.active.fetch_sub(1, Ordering::SeqCst);
            if let Ok(mut last) = server.last_activity.lock() {
                *last = Instant::now();
            }
        });
    }
}

async fn connection(server: &Server, mut stream: TcpStream, peer_port: u16) -> io::Result<()> {
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let mut first = true;
    let mut pins: HashMap<String, String> = HashMap::new();
    loop {
        // Read one request head; pipelined bytes stay in the buffer.
        let head_end = loop {
            let found = buffer.windows(4).position(|w| w == b"\r\n\r\n");
            if found.map_or(buffer.len(), |end| end) > MAX_HEAD {
                write_status(&mut stream, 431, "header too large\n", false).await?;
                return Ok(());
            }
            if let Some(end) = found {
                break end;
            }
            let wait = if first { Duration::from_secs(10) } else { Duration::from_secs(30) };
            let count = match timeout(wait, stream.read(&mut chunk)).await {
                Ok(result) => result?,
                Err(_) => return Ok(()),
            };
            if count == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..count]);
        };
        first = false;
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        buffer.drain(..head_end + 4);
        let started = Instant::now();
        let (method, target, keep_alive, reply) = route(server, &head, &mut pins).await;
        let status = match &reply {
            Reply::Status(code, _) => *code,
            Reply::File { .. } => 200,
        };
        let generation = match &reply {
            Reply::File { generation, .. } => generation.clone(),
            Reply::Status(..) => "-".to_owned(),
        };
        let keep_alive = keep_alive && status < 400;
        let sent = match reply {
            Reply::Status(code, body) => {
                write_status(&mut stream, code, body, keep_alive).await?;
                0
            }
            Reply::File { file, size, .. } => {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nCache-Control: no-store\r\nConnection: {}\r\n\r\n",
                    if keep_alive { "keep-alive" } else { "close" }
                );
                stream.write_all(header.as_bytes()).await?;
                if method == "GET" {
                    let mut file = tokio::fs::File::from_std(file);
                    let copied = tokio::io::copy(&mut (&mut file).take(size), &mut stream).await?;
                    if copied != size {
                        return Err(io::Error::other("object shrank while sending"));
                    }
                    copied
                } else {
                    0
                }
            }
        };
        eprintln!(
            "req method={method} target={target} status={status} bytes={sent} ms={} generation={generation} peer_port={peer_port}",
            started.elapsed().as_millis()
        );
        if !keep_alive {
            stream.shutdown().await.ok();
            return Ok(());
        }
    }
}

async fn write_status(stream: &mut TcpStream, code: u16, body: &str, keep_alive: bool) -> io::Result<()> {
    let extra = if code == 405 { "Allow: GET, HEAD\r\n" } else { "" };
    let response = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{extra}Connection: {}\r\n\r\n{body}",
        reason(code),
        body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    );
    stream.write_all(response.as_bytes()).await
}

/// Percent-decodes one path segment and rejects anything that could change
/// the path structure.
fn decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = segment.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let text = String::from_utf8(out).ok()?;
    if text.is_empty() || text == "." || text == ".." || text.contains(['/', '\\', '\0']) {
        return None;
    }
    Some(text)
}

pub fn parse_target(target: &str) -> Option<(String, String)> {
    if target.len() > MAX_TARGET || !target.starts_with('/') || target.contains(['?', '#']) {
        return None;
    }
    let mut segments = Vec::new();
    for raw in target[1..].split('/') {
        segments.push(decode_segment(raw)?);
    }
    if segments.len() < 2 || !valid_name(&segments[0]) {
        return None;
    }
    let path = segments[1..].join("/");
    valid_repo_path(&path).then(|| (segments[0].clone(), path))
}

async fn route(
    server: &Server,
    head: &str,
    pins: &mut HashMap<String, String>,
) -> (String, String, bool, Reply) {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() != 3 || !parts[2].starts_with("HTTP/1.") {
        return ("-".into(), "-".into(), false, Reply::Status(400, "bad request line\n"));
    }
    let (method, target, version) = (parts[0].to_owned(), parts[1].to_owned(), parts[2]);
    let shown: String = target.chars().take(200).collect();
    if target.len() > MAX_TARGET {
        return (method, shown, false, Reply::Status(414, "target too long\n"));
    }
    let mut host = None;
    let mut connection_close = version == "HTTP/1.0";
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return (method, shown, false, Reply::Status(400, "bad header\n"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return (method, shown, false, Reply::Status(400, "duplicate Host\n"));
            }
            host = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close") {
            connection_close = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value != "0")
        {
            return (method, shown, false, Reply::Status(400, "request bodies are not accepted\n"));
        }
    }
    if method != "GET" && method != "HEAD" {
        return (method, shown, false, Reply::Status(405, "read-only service\n"));
    }
    match host {
        Some(h) if server.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(&h)) => {}
        _ => return (method, shown, false, Reply::Status(400, "unexpected Host\n")),
    }
    let Some((repo, path)) = parse_target(&target) else {
        return (method, shown, !connection_close, Reply::Status(404, "not found\n"));
    };
    if let (Some(hold), Some(gate)) = (&server.config.hold, &server.config.gate)
        && target.contains(hold.as_str()) {
            eprintln!("event=hold target={shown}");
            let deadline = Instant::now() + Duration::from_secs(300);
            while !gate.exists() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            eprintln!("event=release target={shown}");
        }
    let reply = resolve(server, &repo, &path, pins).await;
    (method, shown, !connection_close, reply)
}

async fn view(server: &Server, repo: &str) -> Result<Arc<RepoView>, String> {
    let current_path = server.store.current_path(repo);
    let current = match tokio::fs::read_to_string(&current_path).await {
        Ok(text) => text.trim().to_owned(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err("no such repository".to_owned()),
        Err(error) => return Err(error.to_string()),
    };
    if !valid_name(&current) {
        return Err("invalid current pointer".to_owned());
    }
    if let Ok(views) = server.views.lock()
        && let Some(view) = views.get(repo)
            && view.current == current {
                return Ok(Arc::clone(view));
            }
    let store = Store::new(&server.store.root);
    let repo_name = repo.to_owned();
    let retention = server.config.retention;
    let current_id = current.clone();
    let view = tokio::task::spawn_blocking(move || -> Result<RepoView, String> {
        let current_map: HashMap<String, Entry> = store::load_manifest(&store, &repo_name, &current_id)?
            .into_iter()
            .map(|e| (e.path.clone(), e))
            .collect();
        let mut retained: HashMap<String, Entry> = HashMap::new();
        let ids = if retention {
            store.generation_ids(&repo_name).map_err(|e| e.to_string())?
        } else {
            vec![current_id.clone()]
        };
        let mut conflicts = Vec::new();
        for id in ids {
            for entry in store::load_manifest(&store, &repo_name, &id)? {
                if !is_immutable(&entry.path) {
                    continue;
                }
                if let Some(existing) = retained.get(&entry.path) {
                    if existing.sha256 != entry.sha256 {
                        conflicts.push(entry.path.clone());
                    }
                    continue;
                }
                retained.insert(entry.path.clone(), entry);
            }
        }
        // An immutable path with two contents is served by no generation.
        for path in conflicts {
            eprintln!("event=immutable-conflict path={path}");
            retained.remove(&path);
        }
        Ok(RepoView { current: current_id, current_map, retained })
    })
    .await
    .map_err(|e| e.to_string())??;
    let view = Arc::new(view);
    if let Ok(mut views) = server.views.lock() {
        views.insert(repo.to_owned(), Arc::clone(&view));
    }
    eprintln!("event=view-loaded repo={repo} generation={current}");
    Ok(view)
}

/// The mutable paths of one generation (cached; manifests never change).
async fn generation_map(server: &Server, repo: &str, id: &str) -> Result<PathMap, String> {
    let key = (repo.to_owned(), id.to_owned());
    if let Ok(maps) = server.generation_maps.lock()
        && let Some(map) = maps.get(&key)
    {
        return Ok(Arc::clone(map));
    }
    let store = Store::new(&server.store.root);
    let (repo_name, id_name) = key.clone();
    let map = tokio::task::spawn_blocking(move || -> Result<HashMap<String, Entry>, String> {
        Ok(store::load_manifest(&store, &repo_name, &id_name)?
            .into_iter()
            .map(|e| (e.path.clone(), e))
            .collect())
    })
    .await
    .map_err(|e| e.to_string())??;
    let map = Arc::new(map);
    if let Ok(mut maps) = server.generation_maps.lock() {
        maps.insert(key, Arc::clone(&map));
    }
    Ok(map)
}

async fn resolve(server: &Server, repo: &str, path: &str, pins: &mut HashMap<String, String>) -> Reply {
    let view = match view(server, repo).await {
        Ok(view) => view,
        Err(message) if message == "no such repository" => return Reply::Status(404, "not found\n"),
        Err(message) => {
            eprintln!("event=repo-unavailable repo={repo} error={message}");
            return Reply::Status(503, "repository unavailable\n");
        }
    };
    // Connection pinning: every mutable path requested on one connection
    // comes from the generation that connection saw first, so a client that
    // fetches repomd.xml and repomd.xml.asc on one connection gets a pair.
    let mut generation = view.current.clone();
    let mut pinned_map = None;
    if server.config.pin_connection {
        match pins.get(repo) {
            Some(pinned) if *pinned != view.current => match generation_map(server, repo, pinned).await {
                Ok(map) => {
                    generation = pinned.clone();
                    pinned_map = Some(map);
                }
                Err(_) => {
                    pins.insert(repo.to_owned(), view.current.clone());
                }
            },
            Some(_) => {}
            None => {
                pins.insert(repo.to_owned(), view.current.clone());
            }
        }
    }
    let mutable_map = pinned_map.as_deref().unwrap_or(&view.current_map);
    let entry = match mutable_map.get(path).or_else(|| view.current_map.get(path).filter(|_| is_immutable(path))) {
        Some(entry) => entry.clone(),
        None if is_immutable(path) => match view.retained.get(path) {
            Some(entry) => entry.clone(),
            None => return Reply::Status(404, "not found\n"),
        },
        None => return Reply::Status(404, "not found\n"),
    };
    let object = server.store.object_path(&entry.sha256);
    if entry.url.is_some() && tokio::fs::symlink_metadata(&object).await.is_err()
        && let Err(reply) = lazy_fetch(server, &entry).await {
            return reply;
        }
    let verify = server.config.verify_on_serve;
    let expected = entry.clone();
    let opened = tokio::task::spawn_blocking(move || -> Result<(std::fs::File, u64), String> {
        let mut file = open_nofollow(&object).map_err(|e| format!("open: {e}"))?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.len() != expected.size {
            return Err(format!("object is not a regular file of {} bytes", expected.size));
        }
        if verify {
            let (sha256, size) = store::hash_reader(&mut file).map_err(|e| e.to_string())?;
            if sha256 != expected.sha256 || size != expected.size {
                return Err(format!("DIGEST MISMATCH object={} actual={sha256}", expected.sha256));
            }
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        }
        Ok((file, expected.size))
    })
    .await;
    match opened {
        Ok(Ok((file, size))) => Reply::File { file, size, generation },
        Ok(Err(message)) => {
            eprintln!("event=object-refused repo={repo} path={path} error={message}");
            Reply::Status(500, "object unavailable\n")
        }
        Err(error) => {
            eprintln!("event=object-refused repo={repo} path={path} error={error}");
            Reply::Status(500, "object unavailable\n")
        }
    }
}

async fn lazy_fetch(server: &Server, entry: &Entry) -> Result<(), Reply> {
    let lock = {
        let Ok(mut inflight) = server.inflight.lock() else {
            return Err(Reply::Status(500, "internal error\n"));
        };
        Arc::clone(inflight.entry(entry.sha256.clone()).or_default())
    };
    let _guard = lock.lock().await;
    if tokio::fs::symlink_metadata(server.store.object_path(&entry.sha256)).await.is_ok() {
        return Ok(());
    }
    eprintln!("event=fetch-start object={}", entry.sha256);
    let started = Instant::now();
    let result = fetch_into_store(&server.store, &server.config.fetch, entry).await;
    match result {
        Ok(()) => {
            eprintln!("event=fetch-ok object={} ms={}", entry.sha256, started.elapsed().as_millis());
            Ok(())
        }
        Err(error) => {
            eprintln!("event=fetch-failed object={} error={error}", entry.sha256);
            Err(match error {
                FetchError::Timeout(_) => Reply::Status(504, "upstream timeout\n"),
                FetchError::Storage(message) if message.contains("No space left") => {
                    Reply::Status(507, "no space for the object\n")
                }
                FetchError::Storage(_) => Reply::Status(500, "storage error\n"),
                FetchError::Policy(_) | FetchError::Network(_) | FetchError::Integrity(_) => {
                    Reply::Status(502, "upstream object unavailable\n")
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            parse_target("/alpha/dists/stable/InRelease"),
            Some(("alpha".to_owned(), "dists/stable/InRelease".to_owned()))
        );
        assert_eq!(
            parse_target("/alpha/pool/libstdc%2b%2b6_1_amd64.deb"),
            Some(("alpha".to_owned(), "pool/libstdc++6_1_amd64.deb".to_owned()))
        );
        for bad in [
            "/alpha/../etc/passwd", "/alpha/%2e%2e/etc/passwd", "/alpha/a%2fb", "/alpha//x",
            "/alpha/x?y", "http://evil/alpha/x", "/alpha/a%5cb", "/alpha/a%00b", "/alpha/", "/.x/y",
            "/alpha/a%zz",
        ] {
            assert_eq!(parse_target(bad), None, "{bad}");
        }
    }
}
