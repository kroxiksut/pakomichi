// SPDX-License-Identifier: MIT OR Apache-2.0

//! TEST ONLY OpenPGP keys for the signer and index publisher tests: each
//! key lives in its own temporary GnuPG home, and its agent is stopped
//! when the key is dropped.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::sign::Fingerprint;
use crate::state::test_support::TempDir;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(crate) struct TestKey {
    dir: TempDir,
    pub(crate) fingerprint: Fingerprint,
}

fn gpg(homedir: &Path, args: &[&str]) -> TestResult<Vec<u8>> {
    let output = Command::new("/usr/bin/gpg")
        .arg("--homedir")
        .arg(homedir)
        .args(["--batch", "--no-tty", "--quiet"])
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(format!("gpg {args:?}: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(output.stdout)
}

impl TestKey {
    /// A new Ed25519 signing key without a passphrase.
    pub(crate) fn new(name: &str) -> TestResult<Self> {
        let dir = TempDir::new()?;
        let homedir = dir.join("gnupg");
        fs::create_dir(&homedir)?;
        fs::set_permissions(
            &homedir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        gpg(
            &homedir,
            &[
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-gen-key",
                &format!("Pakomichi {name} TEST ONLY <{name}@example.invalid>"),
                "ed25519",
                "sign",
                "never",
            ],
        )?;
        let listing = String::from_utf8(gpg(&homedir, &["--with-colons", "--list-secret-keys"])?)?;
        let fingerprint = listing
            .lines()
            .find_map(|line| line.strip_prefix("fpr:"))
            .and_then(|rest| rest.split(':').nth(8))
            .and_then(Fingerprint::new)
            .ok_or("no fingerprint in the key listing")?;
        let keyring = dir.join("keyring.gpg");
        let keyring_text = keyring.to_string_lossy().into_owned();
        gpg(
            &homedir,
            &["--output", &keyring_text, "--export", fingerprint.as_str()],
        )?;
        Ok(Self { dir, fingerprint })
    }

    pub(crate) fn homedir(&self) -> PathBuf {
        self.dir.join("gnupg")
    }

    /// The exported public key, as APT's `Signed-By` file.
    pub(crate) fn keyring(&self) -> PathBuf {
        self.dir.join("keyring.gpg")
    }

    /// Imports `other`'s secret key into this key's home, so one `gpg`
    /// run can sign with both; returns a keyring with both public keys.
    pub(crate) fn also_holding(&self, other: &TestKey) -> TestResult<PathBuf> {
        let secret = self.dir.join("other-secret.gpg");
        let secret_text = secret.to_string_lossy().into_owned();
        gpg(
            &other.homedir(),
            &[
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--output",
                &secret_text,
                "--export-secret-keys",
                other.fingerprint.as_str(),
            ],
        )?;
        gpg(&self.homedir(), &["--import", &secret_text])?;
        let both = self.dir.join("both.gpg");
        let mut bytes = fs::read(self.keyring())?;
        bytes.extend(fs::read(other.keyring())?);
        fs::write(&both, bytes)?;
        Ok(both)
    }

    /// Signs with explicit `gpg` options, bypassing the production signer.
    pub(crate) fn sign_with(&self, text: &[u8], options: &[&str]) -> TestResult<Vec<u8>> {
        let mut child = Command::new("/usr/bin/gpg")
            .arg("--homedir")
            .arg(self.homedir())
            .args(["--batch", "--no-tty", "--quiet", "--local-user"])
            .arg(self.fingerprint.as_str())
            .args(options)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            std::io::Write::write_all(&mut stdin, text)?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        Ok(output.stdout)
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/gpgconf")
            .arg("--homedir")
            .arg(self.homedir())
            .args(["--kill", "all"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
