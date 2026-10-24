// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signing and checking local repository metadata (ADR-011, ADR-017
//! point 5).
//!
//! The metadata key is used only by `gpg` in its own child process, with
//! the signer's home directory; the publisher hands it the text to sign
//! and never reads the key. The check runs `gpgv` against the public
//! keyring that APT is configured with (`Signed-By`), so a signature that
//! passes here is one APT can verify with the same key.
//!
//! Both tools run without a shell, with an empty environment apart from
//! `PATH` and `LC_ALL`, `/` as the working directory, a deadline, and
//! capped output. Only absolute tool paths are used.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ipc::channels::{Refusal, SignRequest, SignResponse, SignText, Signed};
use crate::ipc::oneshot::call;

const GPG_CANDIDATES: [&str; 2] = ["/usr/bin/gpg", "/usr/bin/gpg2"];
const GPGV_CANDIDATES: [&str; 2] = ["/usr/bin/gpgv", "/usr/bin/gpgv2"];
const CHILD_PATH: &str = "/usr/bin:/bin";
const TOOL_TIMEOUT: Duration = Duration::from_secs(60);
/// Time to collect output after the tool exits.
const COLLECT_GRACE: Duration = Duration::from_secs(2);
/// Largest signed text and signature the tools may print.
const MAX_STDOUT: usize = 16 * 1024 * 1024;
const MAX_STDERR: usize = 64 * 1024;
const CLEARSIGN_HEADER: &[u8] = b"-----BEGIN PGP SIGNED MESSAGE-----\n";
const SIGNATURE_FOOTER: &[u8] = b"-----END PGP SIGNATURE-----\n";
/// OpenPGP hash algorithm IDs accepted in a signature: SHA-256, SHA-384,
/// SHA-512 (RFC 4880 9.4). APT on Debian 13 (`sqv`) refuses SHA-1.
const STRONG_HASHES: [&str; 3] = ["8", "9", "10"];

/// Why signing or checking failed.
#[derive(Debug)]
pub enum SignError {
    /// The tool is not installed in a trusted location.
    ToolUnavailable(&'static str),
    Io(io::Error),
    /// The tool did not finish in time and was killed.
    Timeout(&'static str),
    /// The tool printed more than the cap.
    OutputTooLarge(&'static str),
    /// `gpg` failed; the text is the start of its diagnostics.
    SigningFailed(String),
    /// `gpgv` did not accept the signature.
    BadSignature(String),
    /// A valid signature, but by another key, by more than one key, or with
    /// a weak hash.
    UnexpectedSignature(String),
    /// The output is not one clear-signed message.
    NotClearSigned,
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolUnavailable(tool) => write!(formatter, "{tool} is not installed"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Timeout(tool) => write!(formatter, "{tool} did not finish in time"),
            Self::OutputTooLarge(tool) => write!(formatter, "{tool} printed too much"),
            Self::SigningFailed(detail) => write!(formatter, "signing failed: {detail}"),
            Self::BadSignature(detail) => write!(formatter, "signature not accepted: {detail}"),
            Self::UnexpectedSignature(detail) => {
                write!(formatter, "unexpected signature: {detail}")
            }
            Self::NotClearSigned => formatter.write_str("not one clear-signed message"),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SignError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// An OpenPGP v4 or v5 primary key fingerprint, uppercase hex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn new(text: &str) -> Option<Self> {
        let valid = (text.len() == 40 || text.len() == 64)
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte));
        valid.then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Produces the clear-signed form of a text.
pub trait MetadataSigner {
    fn clearsign(&self, text: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// Checks a clear-signed message and returns the text its signature covers.
pub trait MetadataVerifier {
    fn verify_clearsigned(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

fn first_file(candidates: &[&'static str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

/// Signs with `gpg` and the key `key` from the signer's home directory.
#[derive(Clone, Debug)]
pub struct GpgSigner {
    gpg: PathBuf,
    homedir: PathBuf,
    key: Fingerprint,
}

impl GpgSigner {
    pub fn new(homedir: &Path, key: Fingerprint) -> Result<Self, SignError> {
        Ok(Self {
            gpg: first_file(&GPG_CANDIDATES).ok_or(SignError::ToolUnavailable("gpg"))?,
            homedir: homedir.to_owned(),
            key,
        })
    }
}

impl MetadataSigner for GpgSigner {
    fn clearsign(&self, text: &[u8]) -> Result<Vec<u8>, SignError> {
        let homedir = self.homedir.to_string_lossy().into_owned();
        let output = run(
            "gpg",
            &self.gpg,
            &[
                "--homedir",
                &homedir,
                "--batch",
                "--no-tty",
                "--no-options",
                "--quiet",
                "--pinentry-mode",
                "error",
                "--digest-algo",
                "SHA512",
                "--local-user",
                self.key.as_str(),
                "--clearsign",
            ],
            text,
        )?;
        if !output.status.success() {
            return Err(SignError::SigningFailed(output.diagnostics()));
        }
        check_shape(&output.stdout)?;
        Ok(output.stdout)
    }
}

/// Checks with `gpgv` against one public keyring and one expected key.
#[derive(Clone, Debug)]
pub struct GpgvVerifier {
    gpgv: PathBuf,
    keyring: PathBuf,
    key: Fingerprint,
}

impl GpgvVerifier {
    pub fn new(keyring: &Path, key: Fingerprint) -> Result<Self, SignError> {
        Ok(Self {
            gpgv: first_file(&GPGV_CANDIDATES).ok_or(SignError::ToolUnavailable("gpgv"))?,
            keyring: keyring.to_owned(),
            key,
        })
    }
}

impl MetadataVerifier for GpgvVerifier {
    fn verify_clearsigned(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        check_shape(message)?;
        let keyring = self.keyring.to_string_lossy().into_owned();
        let output = run(
            "gpgv",
            &self.gpgv,
            &["--keyring", &keyring, "--status-fd", "2", "--output", "-"],
            message,
        )?;
        let status = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<&str> = status
            .lines()
            .filter_map(|line| line.strip_prefix("[GNUPG:] "))
            .collect();
        if !output.status.success()
            || lines.iter().any(|line| {
                ["BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG", "EXPSIG"]
                    .iter()
                    .any(|tag| line.split(' ').next() == Some(tag))
            })
        {
            return Err(SignError::BadSignature(output.diagnostics()));
        }
        let valid: Vec<Vec<&str>> = lines
            .iter()
            .filter(|line| line.starts_with("VALIDSIG "))
            .map(|line| line.split(' ').collect())
            .collect();
        let [signature] = valid.as_slice() else {
            return Err(SignError::UnexpectedSignature(format!(
                "{} valid signatures",
                valid.len()
            )));
        };
        // VALIDSIG <fpr> <date> <ts> <expire> <version> <reserved>
        //          <pubkey-algo> <hash-algo> <class> <primary-fpr>
        let (Some(hash), Some(primary)) = (signature.get(8), signature.get(10)) else {
            return Err(SignError::UnexpectedSignature("short VALIDSIG".to_owned()));
        };
        if *primary != self.key.as_str() {
            return Err(SignError::UnexpectedSignature(format!(
                "signed by {primary}"
            )));
        }
        if !STRONG_HASHES.contains(hash) {
            return Err(SignError::UnexpectedSignature(format!(
                "hash algorithm {hash}"
            )));
        }
        Ok(output.stdout)
    }
}

/// One clear-signed message and nothing around it: APT reads the text
/// itself before it checks the signature.
fn check_shape(message: &[u8]) -> Result<(), SignError> {
    let begins = message
        .windows(CLEARSIGN_HEADER.len())
        .filter(|window| *window == CLEARSIGN_HEADER)
        .count();
    if !message.starts_with(CLEARSIGN_HEADER) || begins != 1 || !message.ends_with(SIGNATURE_FOOTER)
    {
        return Err(SignError::NotClearSigned);
    }
    Ok(())
}

struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Output {
    /// The start of the tool's diagnostics, without status lines.
    fn diagnostics(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.starts_with("[GNUPG:]"))
            .take(5)
            .collect();
        format!("{} ({})", lines.join("; "), self.status)
    }
}

/// Reads at most `cap + 1` bytes and drains the rest, so the child never
/// blocks on a full pipe; the result arrives on the returned channel.
fn read_capped<R: Read + Send + 'static>(
    mut source: R,
    cap: usize,
) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = (&mut source)
            .take(cap as u64 + 1)
            .read_to_end(&mut bytes)
            .and_then(|_| io::copy(&mut source, &mut io::sink()))
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    receiver
}

fn run(
    name: &'static str,
    program: &Path,
    args: &[&str],
    input: &[u8],
) -> Result<Output, SignError> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SignError::Io(io::Error::other("child pipes missing")));
    };
    let input = input.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&input));
    let stdout = read_capped(stdout, MAX_STDOUT);
    let stderr = read_capped(stderr, MAX_STDERR);
    let deadline = Instant::now() + TOOL_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SignError::Timeout(name));
        }
        thread::sleep(Duration::from_millis(5));
    };
    // A helper the tool leaves behind (such as `gpg-agent`) may keep a
    // pipe open; collection after the exit is bounded as well.
    let collect_until = Instant::now() + COLLECT_GRACE;
    let collected = |receiver: mpsc::Receiver<io::Result<Vec<u8>>>| {
        receiver
            .recv_timeout(collect_until.saturating_duration_since(Instant::now()))
            .map_err(|_| SignError::Timeout(name))?
            .map_err(SignError::Io)
    };
    let stdout = collected(stdout)?;
    let stderr = collected(stderr)?;
    // A child that exits without reading all input closes the pipe; that
    // is its own failure, reported through its status.
    drop(writer);
    if stdout.len() > MAX_STDOUT || stderr.len() > MAX_STDERR {
        return Err(SignError::OutputTooLarge(name));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// The state owner's side of `sign.sock`: one signer instance per call.
#[derive(Clone, Debug)]
pub struct SocketSigner {
    socket: std::path::PathBuf,
}

impl SocketSigner {
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_owned(),
        }
    }
}

impl MetadataSigner for SocketSigner {
    fn clearsign(&self, text: &[u8]) -> Result<Vec<u8>, SignError> {
        let text = String::from_utf8(text.to_vec())
            .map_err(|_| SignError::SigningFailed("the text is not UTF-8".to_owned()))?;
        let request = SignRequest::Clearsign(SignText { text });
        match call::<_, SignResponse>(&self.socket, &request, TOOL_TIMEOUT) {
            Ok(SignResponse::Signed(signed)) => {
                let message = signed.message.into_bytes();
                check_shape(&message)?;
                Ok(message)
            }
            Ok(SignResponse::Failed(refusal)) => Err(SignError::SigningFailed(refusal.message)),
            Ok(SignResponse::Error(body)) => Err(SignError::SigningFailed(body.message)),
            Err(error) => Err(SignError::SigningFailed(format!(
                "signer unavailable: {error}"
            ))),
        }
    }
}

/// The signer instance's answer to its one request.
pub fn answer_sign(signer: &dyn MetadataSigner, request: SignRequest) -> SignResponse {
    let SignRequest::Clearsign(SignText { text }) = request;
    match signer
        .clearsign(text.as_bytes())
        .and_then(|message| String::from_utf8(message).map_err(|_| SignError::NotClearSigned))
    {
        Ok(message) => SignResponse::Signed(Signed { message }),
        Err(error) => SignResponse::Failed(Refusal {
            message: error.to_string(),
        }),
    }
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod tests;
