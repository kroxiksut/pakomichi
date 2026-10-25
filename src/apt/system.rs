// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading APT's choice on this system: `apt-cache policy NAME...` without
//! a shell, with `LC_ALL=C`, an empty environment otherwise, a deadline,
//! and capped output; and whether APT accepts its configuration at all.

use std::fmt;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::policy::{PackagePolicy, PolicyParseError, parse_policy};

const APT_CACHE: &str = "/usr/bin/apt-cache";
const TIMEOUT: Duration = Duration::from_secs(120);
const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 64 * 1024;

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    Failed(String),
    Parse(PolicyParseError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "apt-cache: {error}"),
            Self::Failed(detail) => write!(formatter, "apt-cache failed: {detail}"),
            Self::Parse(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The output of one `apt-cache` run.
struct Run {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn capped(
    mut stream: impl Read + Send + 'static,
    cap: usize,
) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        (&mut stream).take(cap as u64 + 1).read_to_end(&mut bytes)?;
        // Drain the rest so the child never blocks on a full pipe.
        io::copy(&mut stream, &mut io::sink())?;
        Ok(bytes)
    })
}

fn run_apt_cache(args: &[&str], names: &[String]) -> Result<Run, ReadError> {
    let mut child = Command::new(APT_CACHE)
        .args(args)
        .args(names)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("no stderr"))?;
    let stdout = capped(stdout, MAX_OUTPUT);
    let stderr = capped(stderr, MAX_DIAGNOSTICS);
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ReadError::Failed("timed out".to_owned()));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let join = |handle: thread::JoinHandle<io::Result<Vec<u8>>>| {
        handle
            .join()
            .map_err(|_| ReadError::Failed("reader panicked".to_owned()))?
            .map_err(ReadError::Io)
    };
    let stdout = join(stdout)?;
    let stderr = join(stderr)?;
    if stdout.len() > MAX_OUTPUT {
        return Err(ReadError::Failed("output too large".to_owned()));
    }
    Ok(Run {
        status,
        stdout,
        stderr,
    })
}

/// APT's own error lines (`E: ...`), at most a few, as one line of text.
fn errors_of(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(&stderr[..stderr.len().min(MAX_DIAGNOSTICS)]);
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("E:"))
        .take(4)
        .collect();
    let joined = if lines.is_empty() {
        text.lines().take(4).collect::<Vec<_>>().join(" | ")
    } else {
        lines.join(" | ")
    };
    joined
        .chars()
        .filter(|character| !character.is_control())
        .take(1024)
        .collect()
}

/// What APT will choose for `names` now.
pub fn read_policy(names: &[String]) -> Result<Vec<PackagePolicy>, ReadError> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let run = run_apt_cache(&["policy", "--"], names)?;
    if !run.status.success() {
        return Err(ReadError::Failed(format!(
            "{}: {}",
            run.status,
            errors_of(&run.stderr)
        )));
    }
    let text =
        String::from_utf8(run.stdout).map_err(|_| ReadError::Failed("not UTF-8".to_owned()))?;
    parse_policy(&text).map_err(ReadError::Parse)
}

/// Whether APT accepts its whole configuration now: `apt-cache policy`
/// with no names reads every sources and preferences file and fails on
/// any it rejects (for example two `Signed-By` values for one URI). The
/// error carries APT's own `E:` lines.
pub fn check_configuration() -> Result<(), ReadError> {
    let run = run_apt_cache(&["policy"], &[])?;
    if run.status.success() {
        Ok(())
    } else {
        Err(ReadError::Failed(format!(
            "{}: {}",
            run.status,
            errors_of(&run.stderr)
        )))
    }
}
