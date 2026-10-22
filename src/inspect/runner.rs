// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs `dpkg-deb --ctrl-tarfile` for one package under the inspector limits.
//!
//! The child gets no shell, an empty environment apart from `PATH` and
//! `LC_ALL`, `/` as its working directory, and the package as its standard
//! input. `prlimit` applies `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE=0`
//! (the operation writes no file), `RLIMIT_CORE=0`, and `RLIMIT_NOFILE`
//! before it executes `dpkg-deb`, so the limits hold without `unsafe` code
//! in this process. The parent enforces the wall-clock timeout and the
//! output caps and kills the child when one is exceeded.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use super::InspectLimits;
use super::ar::read_layout;
use super::deb::{DebInspection, inspect_control_tar};
use super::error::InspectError;

/// Trusted locations only; `PATH` of the caller is never searched.
const DPKG_DEB_CANDIDATES: [&str; 2] = ["/usr/bin/dpkg-deb", "/bin/dpkg-deb"];
const PRLIMIT_CANDIDATES: [&str; 2] = ["/usr/bin/prlimit", "/bin/prlimit"];
const CHILD_PATH: &str = "/usr/bin:/bin";
/// `dpkg-deb` reopens the inherited descriptor, so it reads the very file
/// whose layout was checked, even if the path is replaced meanwhile.
const ARCHIVE_ON_STDIN: &str = "/proc/self/fd/0";
const POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Time to collect output after the child ends or is killed.
const COLLECT_GRACE: Duration = Duration::from_secs(1);

/// Absolute paths of the native tools.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolPaths {
    pub dpkg_deb: PathBuf,
    /// `None` runs `dpkg-deb` without kernel resource limits, which
    /// [`InspectorConfig::require_resource_limits`] forbids by default.
    pub prlimit: Option<PathBuf>,
}

impl ToolPaths {
    /// Looks for the tools in `/usr/bin` and `/bin` only.
    pub fn discover() -> Result<Self, InspectError> {
        let dpkg_deb = first_file(&DPKG_DEB_CANDIDATES)
            .ok_or(InspectError::ToolUnavailable { tool: "dpkg-deb" })?;
        Ok(Self {
            dpkg_deb,
            prlimit: first_file(&PRLIMIT_CANDIDATES),
        })
    }
}

fn first_file(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectorConfig {
    pub limits: InspectLimits,
    /// `None` discovers the tools at fixed system paths. An override must
    /// name files that only root can modify.
    pub tools: Option<ToolPaths>,
    /// Refuse to inspect when `prlimit` is unavailable (the default).
    pub require_resource_limits: bool,
    /// TEST ONLY: permit effective UID 0. A deployed inspector runs as an
    /// unprivileged user and leaves this `false`.
    pub allow_root: bool,
}

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            limits: InspectLimits::default(),
            tools: None,
            require_resource_limits: true,
            allow_root: false,
        }
    }
}

/// Reads DEB metadata without installing, unpacking, or running scripts.
#[derive(Debug)]
pub struct DebInspector {
    limits: InspectLimits,
    tools: ToolPaths,
    allow_root: bool,
}

impl DebInspector {
    pub fn new(config: InspectorConfig) -> Result<Self, InspectError> {
        refuse_root(config.allow_root)?;
        let tools = match config.tools {
            Some(tools) => tools,
            None => ToolPaths::discover()?,
        };
        if tools.prlimit.is_none() && config.require_resource_limits {
            return Err(InspectError::ToolUnavailable { tool: "prlimit" });
        }
        Ok(Self {
            limits: config.limits,
            tools,
            allow_root: config.allow_root,
        })
    }

    /// Inspects the package at `path`, which must be a regular file and not
    /// a symlink. Pass an immutable copy (a CAS object): the bytes are read
    /// twice, by this process and by `dpkg-deb`.
    pub fn inspect(&self, path: &Path) -> Result<DebInspection, InspectError> {
        refuse_root(self.allow_root)?;
        let mut file = open_package(path)?;
        let size = file
            .metadata()
            .map_err(|source| io_error("inspect the package file", source))?
            .len();
        if size > self.limits.max_package_bytes {
            return Err(InspectError::PackageTooLarge {
                size,
                limit: self.limits.max_package_bytes,
            });
        }

        let format = read_layout(&mut file, size, &self.limits)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| io_error("rewind the package", source))?;
        let control_tar = self.control_tar(file)?;
        inspect_control_tar(format, &control_tar, &self.limits)
    }

    fn control_tar(&self, archive: File) -> Result<Vec<u8>, InspectError> {
        let limits = &self.limits;
        let mut command = match &self.tools.prlimit {
            Some(prlimit) => {
                let mut command = Command::new(prlimit);
                command
                    .arg(format!("--cpu={}", limits.cpu_seconds))
                    .arg(format!("--as={}", limits.address_space_bytes))
                    .arg("--fsize=0")
                    .arg("--core=0")
                    .arg(format!("--nofile={}", limits.open_files))
                    .arg("--")
                    .arg(&self.tools.dpkg_deb);
                command
            }
            None => Command::new(&self.tools.dpkg_deb),
        };
        command
            .arg("--ctrl-tarfile")
            .arg(ARCHIVE_ON_STDIN)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::from(archive))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|source| io_error("start dpkg-deb", source))?;
        let outcome = supervise(&mut child, limits);
        if outcome.is_err() {
            kill(&mut child);
        }
        let run = outcome?;

        if run.stdout_over {
            return Err(InspectError::ControlArchiveTooLarge {
                limit: limits.max_control_tar_bytes,
            });
        }
        if run.stderr_over {
            return Err(InspectError::DiagnosticsTooLarge {
                limit: limits.max_stderr_bytes,
            });
        }
        if run.timed_out {
            return Err(InspectError::TimedOut {
                after: limits.timeout,
            });
        }
        match run.status {
            Some(status) if status.success() => Ok(run.stdout),
            Some(status) => Err(match status.signal() {
                Some(signal) => InspectError::ToolKilled { signal },
                None => InspectError::ToolFailed {
                    exit_code: status.code(),
                    stderr: String::from_utf8_lossy(&run.stderr).into_owned(),
                },
            }),
            None => Err(InspectError::TimedOut {
                after: limits.timeout,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Stream {
    Stdout,
    Stderr,
}

type Captured = (Stream, io::Result<Vec<u8>>);

struct Run {
    status: Option<ExitStatus>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_over: bool,
    stderr_over: bool,
}

/// Waits for `child` until it exits, a stream exceeds its cap, or the
/// deadline passes, killing it in the latter two cases.
fn supervise(child: &mut Child, limits: &InspectLimits) -> Result<Run, InspectError> {
    let deadline = Instant::now() + limits.timeout;
    let stdout_over = Arc::new(AtomicBool::new(false));
    let stderr_over = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io_error("capture dpkg-deb output", io::Error::other("no pipe")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io_error("capture dpkg-deb output", io::Error::other("no pipe")))?;
    spawn_reader(
        Stream::Stdout,
        stdout,
        limits.max_control_tar_bytes,
        Arc::clone(&stdout_over),
        sender.clone(),
    )?;
    spawn_reader(
        Stream::Stderr,
        stderr,
        u64::try_from(limits.max_stderr_bytes).unwrap_or(u64::MAX),
        Arc::clone(&stderr_over),
        sender,
    )?;

    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| io_error("wait for dpkg-deb", source))?
        {
            break Some(status);
        }
        if stdout_over.load(Ordering::Acquire) || stderr_over.load(Ordering::Acquire) {
            kill(child);
            break None;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill(child);
            break None;
        }
        thread::sleep(POLL_INTERVAL);
    };

    let (stdout, stderr) = collect(&receiver, deadline.max(Instant::now()) + COLLECT_GRACE);
    Ok(Run {
        status,
        // A process that leaves its output pipes open past the deadline
        // (for example, a forked decompressor) counts as timed out.
        timed_out: timed_out || stdout.is_none() || stderr.is_none(),
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
        stdout_over: stdout_over.load(Ordering::Acquire),
        stderr_over: stderr_over.load(Ordering::Acquire),
    })
}

/// Reads at most `limit + 1` bytes; the extra byte proves the cap was
/// exceeded. Dropping the pipe afterwards makes further writes fail.
fn spawn_reader<R: Read + Send + 'static>(
    stream: Stream,
    reader: R,
    limit: u64,
    over: Arc<AtomicBool>,
    sender: Sender<Captured>,
) -> Result<(), InspectError> {
    thread::Builder::new()
        .name("pakomichi-inspect-pipe".to_owned())
        .spawn(move || {
            let mut buffer = Vec::new();
            let result = reader
                .take(limit.saturating_add(1))
                .read_to_end(&mut buffer)
                .map(|_| buffer);
            if result
                .as_ref()
                .is_ok_and(|bytes| bytes.len() as u64 > limit)
            {
                over.store(true, Ordering::Release);
            }
            // The receiver may be gone after a timeout; nothing to report.
            let _ = sender.send((stream, result));
        })
        .map(|_| ())
        .map_err(|source| io_error("start an output reader", source))
}

fn collect(receiver: &Receiver<Captured>, deadline: Instant) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut stdout = None;
    let mut stderr = None;
    for _ in 0..2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok((Stream::Stdout, result)) => stdout = result.ok(),
            Ok((Stream::Stderr, result)) => stderr = result.ok(),
            Err(_) => break,
        }
    }
    (stdout, stderr)
}

fn kill(child: &mut Child) {
    // Both fail only when the child is already gone and reaped.
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn open_package(path: &Path) -> Result<File, InspectError> {
    // O_NONBLOCK keeps a FIFO from blocking the open; it does not affect
    // reads from a regular file.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|source| {
            if source.raw_os_error() == Some(libc::ELOOP) {
                InspectError::NotRegularFile
            } else {
                io_error("open the package", source)
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect the package file", source))?;
    if !metadata.is_file() {
        return Err(InspectError::NotRegularFile);
    }
    Ok(file)
}

pub(crate) fn refuse_root(allow_root: bool) -> Result<(), InspectError> {
    if !allow_root && effective_uid()? == 0 {
        return Err(InspectError::RunningAsRoot);
    }
    Ok(())
}

/// The effective UID from `/proc/self/status`, read without `unsafe`.
pub(crate) fn effective_uid() -> Result<u32, InspectError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|source| io_error("determine the effective user", source))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| {
            io_error(
                "determine the effective user",
                io::Error::other("no effective UID in /proc/self/status"),
            )
        })
}

const fn io_error(operation: &'static str, source: io::Error) -> InspectError {
    InspectError::Io { operation, source }
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;
