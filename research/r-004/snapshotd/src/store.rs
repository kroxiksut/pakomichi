// SPDX-License-Identifier: MIT OR Apache-2.0
//! Content-addressed storage, manifests, and generation publication.
//!
//! Layout under the root:
//!   objects/<sha256>                    immutable objects, mode 0444
//!   quarantine/                         objects whose bytes did not match their name
//!   tmp/publish/, tmp/fetch/            staging; never served
//!   repos/<repo>/generations/<id>.manifest
//!   repos/<repo>/current                id of the served generation
//!   state.db                            SQLite: generations and objects

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

pub fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !value.starts_with('.')
}

/// Paths whose bytes never change for a given URL: package files and
/// content-addressed indexes. They may be served from any retained
/// generation; every other path only from the current one.
pub fn is_immutable(path: &str) -> bool {
    if path.starts_with("pool/") || path.starts_with("packages/") || path.contains("/by-hash/") {
        return true;
    }
    if let Some(name) = path.strip_prefix("repodata/") {
        return name.len() > 65 && is_hex_digest(&name[..64]) && name.as_bytes()[64] == b'-';
    }
    false
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Sleeps for a long time when R004_TEST_PAUSE_AT names this point, so the
/// harness can kill the process exactly there.
pub fn pause_point(name: &str) {
    if std::env::var("R004_TEST_PAUSE_AT").as_deref() == Ok(name) {
        eprintln!("event=pause point={name} pid={}", std::process::id());
        std::thread::sleep(Duration::from_secs(600));
    }
}

pub fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub fn hash_reader<R: Read>(mut reader: R) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total += count as u64;
    }
    Ok((to_hex(&hasher.finalize()), total))
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// Upstream URL for an object fetched on first request.
    pub url: Option<String>,
}

pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(root: &Path) -> Self {
        Self { root: root.to_path_buf() }
    }
    pub fn objects(&self) -> PathBuf {
        self.root.join("objects")
    }
    pub fn object_path(&self, sha256: &str) -> PathBuf {
        self.objects().join(sha256)
    }
    pub fn quarantine(&self) -> PathBuf {
        self.root.join("quarantine")
    }
    pub fn fetch_tmp(&self) -> PathBuf {
        self.root.join("tmp").join("fetch")
    }
    pub fn publish_tmp(&self) -> PathBuf {
        self.root.join("tmp").join("publish")
    }
    pub fn repo_dir(&self, repo: &str) -> PathBuf {
        self.root.join("repos").join(repo)
    }
    pub fn generations_dir(&self, repo: &str) -> PathBuf {
        self.repo_dir(repo).join("generations")
    }
    pub fn manifest_path(&self, repo: &str, id: &str) -> PathBuf {
        self.generations_dir(repo).join(format!("{id}.manifest"))
    }
    pub fn current_path(&self, repo: &str) -> PathBuf {
        self.repo_dir(repo).join("current")
    }
    pub fn db_path(&self) -> PathBuf {
        self.root.join("state.db")
    }

    pub fn ensure_layout(&self) -> io::Result<()> {
        for dir in [self.objects(), self.quarantine(), self.fetch_tmp(), self.publish_tmp()] {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn read_current(&self, repo: &str) -> io::Result<Option<String>> {
        match fs::read_to_string(self.current_path(repo)) {
            Ok(text) => {
                let id = text.trim().to_owned();
                if valid_name(&id) {
                    Ok(Some(id))
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "invalid current pointer"))
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn repos(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        match fs::read_dir(self.root.join("repos")) {
            Ok(entries) => {
                for entry in entries {
                    let name = entry?.file_name().to_string_lossy().into_owned();
                    if valid_name(&name) {
                        names.push(name);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        names.sort();
        Ok(names)
    }

    pub fn generation_ids(&self, repo: &str) -> io::Result<Vec<String>> {
        let mut ids = Vec::new();
        match fs::read_dir(self.generations_dir(repo)) {
            Ok(entries) => {
                for entry in entries {
                    let name = entry?.file_name().to_string_lossy().into_owned();
                    if let Some(id) = name.strip_suffix(".manifest")
                        && valid_name(id) {
                            ids.push(id.to_owned());
                        }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        ids.sort();
        Ok(ids)
    }

    /// Verifies that the object exists, is a regular file, and has the
    /// expected digest. Returns false for missing; an error for corruption.
    pub fn verify_object(&self, sha256: &str, size: u64) -> io::Result<bool> {
        let file = match open_nofollow(&self.object_path(sha256)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "object is not a regular file"));
        }
        let (actual, actual_size) = hash_reader(file)?;
        if actual != sha256 || actual_size != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {sha256} hashes to {actual} ({actual_size} bytes)"),
            ));
        }
        Ok(true)
    }

    pub fn quarantine_object(&self, sha256: &str) -> io::Result<()> {
        let target = self.quarantine().join(format!("{sha256}.{}", now_unix()));
        fs::rename(self.object_path(sha256), target)?;
        sync_dir(&self.objects())
    }

    /// Copies a file into the CAS: staging file, digest check, fsync,
    /// read-only mode, rename, directory fsync.
    pub fn insert_file(&self, source: &Path) -> io::Result<(String, u64, bool)> {
        let mut input = open_nofollow(source)?;
        if !input.metadata()?.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "source is not a regular file"));
        }
        let (sha256, size) = hash_reader(&mut input)?;
        match self.verify_object(&sha256, size) {
            Ok(true) => return Ok((sha256, size, false)),
            Ok(false) => {}
            Err(error) => {
                eprintln!("event=quarantine object={sha256} reason={error}");
                self.quarantine_object(&sha256)?;
            }
        }
        input.seek(SeekFrom::Start(0))?;
        let staging = self.publish_tmp().join(format!(
            "{sha256}.{}.{}.part",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
        ));
        let result = (|| {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&staging)?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0_u8; 128 * 1024];
            let mut copied = 0_u64;
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
                copied += count as u64;
            }
            if to_hex(&hasher.finalize()) != sha256 || copied != size {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "source changed while copying"));
            }
            pause_point("publish-object-after-write");
            output.sync_all()?;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o444))?;
            pause_point("publish-object-after-fsync");
            fs::rename(&staging, self.object_path(&sha256))?;
            sync_dir(&self.objects())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&staging);
            return Err(error);
        }
        Ok((sha256, size, true))
    }
}

pub fn manifest_text(repo: &str, id: &str, entries: &BTreeMap<String, Entry>) -> String {
    let mut text = format!("# r004-manifest v1 repo={repo} generation={id}\n");
    for entry in entries.values() {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            entry.sha256,
            entry.size,
            entry.path,
            entry.url.as_deref().unwrap_or("-")
        ));
    }
    text
}

pub fn parse_manifest(text: &str) -> Result<Vec<Entry>, String> {
    let mut lines = text.lines();
    match lines.next() {
        Some(header) if header.starts_with("# r004-manifest v1 ") => {}
        _ => return Err("missing manifest header".to_owned()),
    }
    let mut entries = Vec::new();
    for (number, line) in lines.enumerate() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err(format!("line {}: expected 4 fields", number + 2));
        }
        let size = fields[1].parse::<u64>().map_err(|e| format!("line {}: {e}", number + 2))?;
        if !is_hex_digest(fields[0]) || !valid_repo_path(fields[2]) {
            return Err(format!("line {}: invalid digest or path", number + 2));
        }
        entries.push(Entry {
            sha256: fields[0].to_owned(),
            size,
            path: fields[2].to_owned(),
            url: (fields[3] != "-").then(|| fields[3].to_owned()),
        });
    }
    Ok(entries)
}

pub fn load_manifest(store: &Store, repo: &str, id: &str) -> Result<Vec<Entry>, String> {
    let file = open_nofollow(&store.manifest_path(repo, id)).map_err(|e| format!("manifest {repo}/{id}: {e}"))?;
    let mut text = String::new();
    io::BufReader::new(file)
        .read_to_string(&mut text)
        .map_err(|e| format!("manifest {repo}/{id}: {e}"))?;
    parse_manifest(&text)
}

/// A repository-relative path: segments of safe characters, no `.`/`..`.
pub fn valid_repo_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-+~:@,=".contains(&b))
        })
}

// ---------------------------------------------------------------- database

pub fn open_db(store: &Store) -> Result<rusqlite::Connection, String> {
    let connection = rusqlite::Connection::open(store.db_path()).map_err(|e| format!("state database: {e}"))?;
    let check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|e| format!("state database quick_check: {e}"))?;
    if check != "ok" {
        return Err(format!("state database quick_check: {check}"));
    }
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS generations (
                 repo TEXT NOT NULL, id TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
                 state TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (repo, id));
             CREATE TABLE IF NOT EXISTS objects (sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL);",
        )
        .map_err(|e| format!("state database schema: {e}"))?;
    Ok(connection)
}

// ---------------------------------------------------------------- publish

pub struct PublishArgs {
    pub root: PathBuf,
    pub repo: String,
    pub id: String,
    pub from: PathBuf,
    pub lazy: Option<PathBuf>,
    pub keyring: Option<PathBuf>,
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.is_dir() {
            walk(base, &path, out)?;
        } else if meta.is_file() {
            let relative = path
                .strip_prefix(base)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .into_owned();
            if !valid_repo_path(&relative) {
                return Err(format!("refusing unsafe path {relative}"));
            }
            out.push((relative, path));
        } else {
            return Err(format!("refusing non-regular file {}", path.display()));
        }
    }
    Ok(())
}

pub fn publish(args: &PublishArgs) -> Result<String, String> {
    if !valid_name(&args.repo) || !valid_name(&args.id) {
        return Err("invalid repository or generation name".to_owned());
    }
    let store = Store::new(&args.root);
    store.ensure_layout().map_err(|e| e.to_string())?;
    let mut db = open_db(&store)?;
    fs::create_dir_all(store.generations_dir(&args.repo)).map_err(|e| e.to_string())?;
    if store.manifest_path(&args.repo, &args.id).exists() {
        return Err(format!("generation {} already exists; generations are immutable", args.id));
    }

    let mut files = Vec::new();
    walk(&args.from, &args.from, &mut files)?;
    let mut entries = BTreeMap::new();
    let mut new_objects = 0_usize;
    for (relative, path) in &files {
        let (sha256, size, created) = store.insert_file(path).map_err(|e| format!("{relative}: {e}"))?;
        new_objects += usize::from(created);
        entries.insert(
            relative.clone(),
            Entry { path: relative.clone(), sha256, size, url: None },
        );
    }
    pause_point("publish-after-objects");

    // APT by-hash aliases for every index below dists/.
    let aliases: Vec<Entry> = entries
        .values()
        .filter(|e| e.path.starts_with("dists/") && !e.path.contains("/by-hash/"))
        .filter(|e| {
            let name = e.path.rsplit('/').next().unwrap_or_default();
            !matches!(name, "InRelease" | "Release" | "Release.gpg")
        })
        .map(|e| {
            let parent = e.path.rsplit_once('/').map(|(p, _)| p).unwrap_or_default();
            Entry {
                path: format!("{parent}/by-hash/SHA256/{}", e.sha256),
                sha256: e.sha256.clone(),
                size: e.size,
                url: None,
            }
        })
        .collect();
    for alias in aliases {
        entries.insert(alias.path.clone(), alias);
    }

    if let Some(lazy) = &args.lazy {
        let text = fs::read_to_string(lazy).map_err(|e| format!("{}: {e}", lazy.display()))?;
        for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 4 || !valid_repo_path(fields[0]) || !is_hex_digest(fields[1]) {
                return Err(format!("invalid lazy line: {line}"));
            }
            if !is_immutable(fields[0]) {
                return Err(format!("lazy path must be content-addressed: {}", fields[0]));
            }
            let size = fields[2].parse::<u64>().map_err(|e| e.to_string())?;
            entries.insert(
                fields[0].to_owned(),
                Entry {
                    path: fields[0].to_owned(),
                    sha256: fields[1].to_owned(),
                    size,
                    url: Some(fields[3].to_owned()),
                },
            );
        }
    }

    self_check(&store, &args.from, &entries, args.keyring.as_deref())?;

    // Immutable paths must keep their bytes across retained generations.
    for id in store.generation_ids(&args.repo).map_err(|e| e.to_string())? {
        for old in load_manifest(&store, &args.repo, &id)? {
            if is_immutable(&old.path)
                && let Some(new) = entries.get(&old.path)
                    && new.sha256 != old.sha256 {
                        return Err(format!(
                            "immutable path {} changes bytes against generation {id}",
                            old.path
                        ));
                    }
        }
    }

    let text = manifest_text(&args.repo, &args.id, &entries);
    let manifest_sha = {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        to_hex(&hasher.finalize())
    };
    let generations = store.generations_dir(&args.repo);
    write_atomic(&store, &generations, &format!("{}.manifest", args.id), text.as_bytes())?;

    let transaction = db.transaction().map_err(|e| e.to_string())?;
    transaction
        .execute(
            "INSERT INTO generations (repo, id, manifest_sha256, state, created_at) VALUES (?1, ?2, ?3, 'staged', ?4)",
            rusqlite::params![args.repo, args.id, manifest_sha, now_unix()],
        )
        .map_err(|e| format!("state database: {e}"))?;
    for entry in entries.values().filter(|e| e.url.is_none()) {
        transaction
            .execute(
                "INSERT OR IGNORE INTO objects (sha256, size) VALUES (?1, ?2)",
                rusqlite::params![entry.sha256, i64::try_from(entry.size).unwrap_or(i64::MAX)],
            )
            .map_err(|e| format!("state database: {e}"))?;
    }
    transaction.commit().map_err(|e| format!("state database: {e}"))?;

    pause_point("publish-before-switch");
    write_atomic(&store, &store.repo_dir(&args.repo), "current", format!("{}\n", args.id).as_bytes())?;
    pause_point("publish-after-switch");
    db.execute(
        "UPDATE generations SET state = 'published' WHERE repo = ?1 AND id = ?2",
        rusqlite::params![args.repo, args.id],
    )
    .map_err(|e| format!("state database: {e}"))?;

    Ok(format!(
        "published repo={} generation={} paths={} new_objects={} manifest_sha256={manifest_sha}",
        args.repo,
        args.id,
        entries.len(),
        new_objects
    ))
}

fn write_atomic(store: &Store, dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let staging = store.publish_tmp().join(format!("{name}.{}.part", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staging)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&staging, dir.join(name))?;
        sync_dir(dir)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&staging);
        return Err(format!("{}: {error}", dir.join(name).display()));
    }
    Ok(())
}

// ---------------------------------------------------------------- self-check

fn self_check(
    _store: &Store,
    from: &Path,
    entries: &BTreeMap<String, Entry>,
    keyring: Option<&Path>,
) -> Result<(), String> {
    let by_path: HashMap<&str, &Entry> = entries.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let expect = |path: &str, sha256: &str, size: u64, what: &str| -> Result<(), String> {
        match by_path.get(path) {
            Some(entry) if entry.sha256 == sha256 && entry.size == size => Ok(()),
            Some(entry) => Err(format!(
                "{what}: {path} is {}/{} but metadata says {sha256}/{size}",
                entry.sha256, entry.size
            )),
            None => Err(format!("{what}: {path} is referenced but not published")),
        }
    };
    let mut checked = 0_usize;

    for entry in entries.values().filter(|e| e.path.ends_with("/InRelease") && e.url.is_none()) {
        let keyring = keyring.ok_or("an InRelease file needs --keyring for the self-check")?;
        let output = Command::new("gpgv")
            .arg("--keyring")
            .arg(keyring)
            .arg("--output")
            .arg("-")
            .arg(from.join(&entry.path))
            .output()
            .map_err(|e| format!("gpgv: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "signature check of {} failed: {}",
                entry.path,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let release = String::from_utf8_lossy(&output.stdout).into_owned();
        let suite_dir = entry.path.trim_end_matches("/InRelease");
        let now = now_unix();
        let mut section = false;
        for line in release.lines() {
            if let Some(value) = line.strip_prefix("Valid-Until:") {
                let until = parse_rfc2822(value.trim()).ok_or("unparsable Valid-Until")?;
                if until <= now {
                    return Err(format!("{} is already expired", entry.path));
                }
            } else if let Some(value) = line.strip_prefix("Date:") {
                let date = parse_rfc2822(value.trim()).ok_or("unparsable Date")?;
                if date > now + 60 {
                    return Err(format!("{} has a Date in the future", entry.path));
                }
            }
            if line.starts_with("SHA256:") {
                section = true;
                continue;
            }
            if section {
                if !line.starts_with(' ') {
                    section = false;
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() != 3 {
                    return Err(format!("bad SHA256 line in {}: {line}", entry.path));
                }
                let size = fields[1].parse::<u64>().map_err(|e| e.to_string())?;
                expect(&format!("{suite_dir}/{}", fields[2]), fields[0], size, "Release")?;
                checked += 1;
            }
        }
    }

    for entry in entries.values().filter(|e| e.path.ends_with("/Packages") && e.url.is_none()) {
        let text = fs::read_to_string(from.join(&entry.path)).map_err(|e| format!("{}: {e}", entry.path))?;
        for stanza in text.split("\n\n").filter(|s| !s.trim().is_empty()) {
            let field = |name: &str| {
                stanza
                    .lines()
                    .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_owned()))
            };
            let filename = field("Filename:").ok_or("Packages stanza without Filename")?;
            let sha256 = field("SHA256:").ok_or("Packages stanza without SHA256")?;
            let size = field("Size:")
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or("Packages stanza without Size")?;
            expect(&filename, &sha256, size, "Packages")?;
            checked += 1;
        }
    }

    if let Some(repomd) = entries.get("repodata/repomd.xml") {
        let keyring = keyring.ok_or("repomd.xml needs --keyring for the self-check")?;
        if !entries.contains_key("repodata/repomd.xml.asc") {
            return Err("repodata/repomd.xml.asc is missing".to_owned());
        }
        let output = Command::new("gpgv")
            .arg("--keyring")
            .arg(keyring)
            .arg(from.join("repodata/repomd.xml.asc"))
            .arg(from.join(&repomd.path))
            .output()
            .map_err(|e| format!("gpgv: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "signature check of repomd.xml failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let xml = fs::read_to_string(from.join(&repomd.path)).map_err(|e| e.to_string())?;
        for block in xml.split("<data ").skip(1) {
            let sha = between(block, "<checksum type=\"sha256\">", "</checksum>").ok_or("repomd data without sha256")?;
            let href = between(block, "<location href=\"", "\"").ok_or("repomd data without location")?;
            let size = between(block, "<size>", "</size>")
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or("repomd data without size")?;
            expect(href, sha, size, "repomd.xml")?;
            checked += 1;
            if block.starts_with("type=\"primary\"") {
                let tool = if href.ends_with(".gz") {
                    "gzip"
                } else if href.ends_with(".zst") {
                    "zstd"
                } else if href.ends_with(".xz") {
                    "xz"
                } else {
                    return Err(format!("unknown primary compression: {href}"));
                };
                let output = Command::new(tool)
                    .arg("-dc")
                    .arg(from.join(href))
                    .output()
                    .map_err(|e| format!("{tool}: {e}"))?;
                if !output.status.success() {
                    return Err(format!("{tool} could not read {href}"));
                }
                let primary = String::from_utf8_lossy(&output.stdout).into_owned();
                for package in primary.split("<package ").skip(1) {
                    let sha = between(package, "pkgid=\"YES\">", "</checksum>").ok_or("primary package without pkgid")?;
                    let href = between(package, "<location href=\"", "\"").ok_or("primary package without location")?;
                    let size = between(package, "<size package=\"", "\"")
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or("primary package without size")?;
                    expect(href, sha, size, "primary.xml")?;
                    checked += 1;
                }
            }
        }
    }
    eprintln!("event=self-check references={checked}");
    Ok(())
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = text.find(start)? + start.len();
    let to = text[from..].find(end)? + from;
    Some(&text[from..to])
}

/// Parses `Tue, 20 Oct 2026 10:00:00 UTC` (APT Release dates).
pub fn parse_rfc2822(value: &str) -> Option<i64> {
    let value = value.split_once(", ").map(|(_, rest)| rest).unwrap_or(value);
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let day: i64 = parts[0].parse().ok()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        .iter()
        .position(|m| *m == parts[1])? as i64
        + 1;
    let year: i64 = parts[2].parse().ok()?;
    let hms: Vec<i64> = parts[3].split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    if hms.len() != 3 {
        return None;
    }
    if let Some(zone) = parts.get(4)
        && !matches!(*zone, "UTC" | "GMT" | "+0000" | "Z") {
            return None;
        }
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms[2])
}

// ---------------------------------------------------------------- check, reconcile, gc

/// Verifies every object, manifest, and current pointer. Returns problems.
pub fn check(store: &Store) -> Result<Vec<String>, String> {
    let mut problems = Vec::new();
    for dir in [store.fetch_tmp(), store.publish_tmp()] {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                problems.push(format!("staging leftover {}", entry.path().display()));
            }
        }
    }
    let mut verified = HashMap::new();
    if let Ok(entries) = fs::read_dir(store.objects()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_hex_digest(&name) {
                problems.push(format!("unexpected object name {name}"));
                continue;
            }
            match open_nofollow(&entry.path()).and_then(|f| {
                if f.metadata()?.is_file() {
                    hash_reader(f)
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"))
                }
            }) {
                Ok((sha256, size)) if sha256 == name => {
                    verified.insert(name, size);
                }
                Ok((sha256, _)) => problems.push(format!("object {name} hashes to {sha256}")),
                Err(error) => problems.push(format!("object {name}: {error}")),
            }
        }
    }
    for repo in store.repos().map_err(|e| e.to_string())? {
        let current = match store.read_current(&repo) {
            Ok(current) => current,
            Err(error) => {
                problems.push(format!("{repo}: current: {error}"));
                None
            }
        };
        let ids = store.generation_ids(&repo).map_err(|e| e.to_string())?;
        if let Some(current) = &current
            && !ids.contains(current) {
                problems.push(format!("{repo}: current {current} has no manifest"));
            }
        for id in ids {
            match load_manifest(store, &repo, &id) {
                Ok(entries) => {
                    for entry in entries.iter().filter(|e| e.url.is_none()) {
                        match verified.get(&entry.sha256) {
                            Some(size) if *size == entry.size => {}
                            Some(_) => problems.push(format!("{repo}/{id}: {} size mismatch", entry.path)),
                            None => problems.push(format!("{repo}/{id}: {} object missing", entry.path)),
                        }
                    }
                }
                Err(error) => problems.push(format!("{repo}/{id}: {error}")),
            }
        }
    }
    Ok(problems)
}

/// Startup/after-crash recovery: removes staging files, quarantines
/// corrupt objects, and rebuilds the state database from manifests when it
/// is unreadable. Manifests and objects are the source of truth.
pub fn reconcile(store: &Store) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    store.ensure_layout().map_err(|e| e.to_string())?;
    for dir in [store.fetch_tmp(), store.publish_tmp()] {
        for entry in fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
            fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            actions.push(format!("removed staging {}", entry.file_name().to_string_lossy()));
        }
    }
    for entry in fs::read_dir(store.objects()).map_err(|e| e.to_string())?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let bad = match open_nofollow(&entry.path()).and_then(|f| {
            if f.metadata()?.is_file() { hash_reader(f) } else { Err(io::Error::other("not a regular file")) }
        }) {
            Ok((sha256, _)) => sha256 != name,
            Err(_) => true,
        };
        if bad {
            let target = store.quarantine().join(format!("{name}.{}", now_unix()));
            fs::rename(entry.path(), target).map_err(|e| e.to_string())?;
            actions.push(format!("quarantined object {name}"));
        }
    }
    let db_ok = open_db(store).is_ok();
    if !db_ok {
        let aside = store.root.join(format!("state.db.corrupt-{}", now_unix()));
        fs::rename(store.db_path(), &aside).map_err(|e| e.to_string())?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let _ = fs::remove_file(store.root.join(format!("state.db{suffix}")));
        }
        actions.push(format!("moved unreadable state database to {}", aside.display()));
        let db = open_db(store)?;
        for repo in store.repos().map_err(|e| e.to_string())? {
            let current = store.read_current(&repo).ok().flatten();
            for id in store.generation_ids(&repo).map_err(|e| e.to_string())? {
                let text = fs::read(store.manifest_path(&repo, &id)).map_err(|e| e.to_string())?;
                let mut hasher = Sha256::new();
                hasher.update(&text);
                let state = if current.as_deref() == Some(id.as_str()) { "published" } else { "retained" };
                db.execute(
                    "INSERT INTO generations (repo, id, manifest_sha256, state, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![repo, id, to_hex(&hasher.finalize()), state, now_unix()],
                )
                .map_err(|e| e.to_string())?;
                for entry in load_manifest(store, &repo, &id)?.iter().filter(|e| e.url.is_none()) {
                    db.execute(
                        "INSERT OR IGNORE INTO objects (sha256, size) VALUES (?1, ?2)",
                        rusqlite::params![entry.sha256, i64::try_from(entry.size).unwrap_or(i64::MAX)],
                    )
                    .map_err(|e| e.to_string())?;
                }
                actions.push(format!("recorded {repo}/{id} as {state}"));
            }
        }
    }
    Ok(actions)
}

/// Keeps the current generation and the `keep` newest others per repo,
/// then removes objects that no remaining manifest references.
pub fn gc(store: &Store, keep: usize) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    let mut live = std::collections::HashSet::new();
    for repo in store.repos().map_err(|e| e.to_string())? {
        let current = store.read_current(&repo).map_err(|e| e.to_string())?;
        let mut ids = store.generation_ids(&repo).map_err(|e| e.to_string())?;
        ids.retain(|id| Some(id) != current.as_ref());
        let mut dated: Vec<(SystemTime, String)> = ids
            .into_iter()
            .map(|id| {
                let time = fs::metadata(store.manifest_path(&repo, &id))
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH);
                (time, id)
            })
            .collect();
        dated.sort();
        let drop_count = dated.len().saturating_sub(keep);
        for (_, id) in dated.iter().take(drop_count) {
            fs::remove_file(store.manifest_path(&repo, id)).map_err(|e| e.to_string())?;
            actions.push(format!("removed generation {repo}/{id}"));
        }
        sync_dir(&store.generations_dir(&repo)).map_err(|e| e.to_string())?;
        for id in store.generation_ids(&repo).map_err(|e| e.to_string())? {
            for entry in load_manifest(store, &repo, &id)? {
                live.insert(entry.sha256);
            }
        }
    }
    for entry in fs::read_dir(store.objects()).map_err(|e| e.to_string())?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !live.contains(&name) {
            fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            actions.push(format!("removed object {name}"));
        }
    }
    sync_dir(&store.objects()).map_err(|e| e.to_string())?;
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_paths() {
        assert!(is_immutable("pool/ab/x.deb"));
        assert!(is_immutable("dists/stable/main/binary-amd64/by-hash/SHA256/aa"));
        assert!(is_immutable(&format!("repodata/{}-primary.xml.gz", "a".repeat(64))));
        assert!(!is_immutable("repodata/repomd.xml"));
        assert!(!is_immutable("dists/stable/InRelease"));
        assert!(!is_immutable("dists/stable/main/binary-amd64/Packages"));
    }

    #[test]
    fn repo_paths() {
        assert!(valid_repo_path("dists/stable/InRelease"));
        assert!(valid_repo_path("pool/libstdc++6_1.0~rc1_amd64.deb"));
        assert!(!valid_repo_path("../etc/passwd"));
        assert!(!valid_repo_path("dists//InRelease"));
        assert!(!valid_repo_path("dists/./InRelease"));
        assert!(!valid_repo_path("/etc/passwd"));
        assert!(!valid_repo_path("a\\b"));
        assert!(!valid_repo_path("a%2fb"));
    }

    #[test]
    fn release_dates() {
        assert_eq!(parse_rfc2822("Thu, 01 Jan 1970 00:00:00 UTC"), Some(0));
        assert_eq!(parse_rfc2822("Tue, 20 Oct 2026 10:00:00 UTC"), Some(1_792_490_400));
        assert_eq!(parse_rfc2822("Tue, 20 Oct 2026 10:00:00 +0300"), None);
    }

    #[test]
    fn manifest_round_trip() -> Result<(), String> {
        let mut entries = BTreeMap::new();
        let digest = "b".repeat(64);
        entries.insert(
            "pool/x.deb".to_owned(),
            Entry { path: "pool/x.deb".to_owned(), sha256: digest.clone(), size: 3, url: Some("http://h/x".to_owned()) },
        );
        let parsed = parse_manifest(&manifest_text("r", "g1", &entries))?;
        assert_eq!(parsed, entries.into_values().collect::<Vec<_>>());
        Ok(())
    }
}
