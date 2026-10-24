// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading APT's choice on this system: `apt-cache policy NAME...` without
//! a shell, with `LC_ALL=C`, an empty environment otherwise, a deadline,
//! and capped output.

use std::fmt;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::policy::{PackagePolicy, PolicyParseError, parse_policy};

const APT_CACHE: &str = "/usr/bin/apt-cache";
const TIMEOUT: Duration = Duration::from_secs(120);
const MAX_OUTPUT: usize = 16 * 1024 * 1024;

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

/// What APT will choose for `names` now.
pub fn read_policy(names: &[String]) -> Result<Vec<PackagePolicy>, ReadError> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = Command::new(APT_CACHE)
        .arg("policy")
        .arg("--")
        .args(names)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = (&mut stdout)
            .take(MAX_OUTPUT as u64 + 1)
            .read_to_end(&mut bytes);
        (read, bytes)
    });
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
    let (read, bytes) = reader
        .join()
        .map_err(|_| ReadError::Failed("reader panicked".to_owned()))?;
    read?;
    if bytes.len() > MAX_OUTPUT || !status.success() {
        return Err(ReadError::Failed(format!("{status}")));
    }
    let text = String::from_utf8(bytes).map_err(|_| ReadError::Failed("not UTF-8".to_owned()))?;
    parse_policy(&text).map_err(ReadError::Parse)
}
