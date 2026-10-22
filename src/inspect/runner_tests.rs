// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux tests against the real `dpkg-deb`. Each test skips with a message
//! when `dpkg-deb` is not installed; the TEST ONLY packages are generated
//! here, never committed.

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::*;
use crate::error::ReasonCode;
use crate::inspect::fixtures::{TarItem, ar, minimal_deb_members, tar};
use crate::inspect::{Compression, MaintainerScript};

type TestResult = Result<(), Box<dyn Error>>;

const DPKG_STATUS: &str = "/var/lib/dpkg/status";

const CONTROL: &str = "Package: pakomichi-probe\n\
    Version: 1.0.0-1\n\
    Architecture: amd64\n\
    Maintainer: Pakomichi test fixture <noreply@example.invalid>\n\
    Installed-Size: 8\n\
    Pre-Depends: dpkg (>= 1.19)\n\
    Depends: libc6 (>= 2.34),\n libprobe1 | libprobe0\n\
    Provides: probe-virtual\n\
    Conflicts: probe-old\n\
    Breaks: probe-plugin (<< 1.0)\n\
    Replaces: probe-old\n\
    Description: TEST ONLY P2-005 inspection fixture\n Never install this package.\n";

/// A unique directory under the system temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "pakomichi-inspect-test-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The real tools, or `None` with a message when `dpkg-deb` is missing.
fn tools() -> Option<ToolPaths> {
    match ToolPaths::discover() {
        Ok(tools) => Some(tools),
        Err(error) => {
            eprintln!("SKIP: {error}; this test needs dpkg-deb");
            None
        }
    }
}

fn config(limits: InspectLimits) -> InspectorConfig {
    InspectorConfig {
        limits,
        tools: None,
        require_resource_limits: true,
        // Tests also run as root in the disposable lab to prove that even a
        // root inspector leaves the dpkg database alone.
        allow_root: true,
    }
}

fn inspector() -> Result<DebInspector, InspectError> {
    DebInspector::new(config(InspectLimits::default()))
}

fn sha256_of(path: &str) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(format!("{:x}", Sha256::digest(&bytes)))
}

fn write_executable(path: &Path, text: &str) -> std::io::Result<()> {
    fs::write(path, text)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

/// Builds a package with the real `dpkg-deb --build`; `Ok(None)` when this
/// `dpkg-deb` does not support `compression`.
fn build_with_dpkg(
    tools: &ToolPaths,
    dir: &Path,
    control: &str,
    scripts: &[(&str, String)],
    extra: &[(&str, &[u8])],
    compression: &str,
) -> Result<Option<PathBuf>, Box<dyn Error>> {
    let tree = dir.join(format!("tree-{compression}"));
    let debian = tree.join("DEBIAN");
    let doc = tree.join("usr/share/doc/pakomichi-probe");
    fs::create_dir_all(&debian)?;
    fs::create_dir_all(&doc)?;
    for directory in [&tree, &debian] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    fs::write(debian.join("control"), control)?;
    for (name, body) in scripts {
        write_executable(&debian.join(name), body)?;
    }
    for (name, bytes) in extra {
        fs::write(debian.join(name), bytes)?;
    }
    fs::write(doc.join("README"), "TEST ONLY\n")?;

    let package = dir.join(format!("pakomichi-probe-{compression}.deb"));
    let output = Command::new(&tools.dpkg_deb)
        .arg("--root-owner-group")
        .arg(format!("-Z{compression}"))
        .arg("--build")
        .arg(&tree)
        .arg(&package)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if compression == "zstd" {
            eprintln!("SKIP: dpkg-deb cannot build zstd packages here: {stderr}");
            return Ok(None);
        }
        return Err(format!("dpkg-deb --build failed: {stderr}").into());
    }
    Ok(Some(package))
}

fn marker_scripts(dir: &Path) -> Vec<(&'static str, String)> {
    MaintainerScript::ALL
        .iter()
        .map(|script| {
            let marker = dir.join(format!("ran-{}", script.as_str()));
            (
                script.as_str(),
                format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
            )
        })
        .collect()
}

fn no_markers(dir: &Path) -> Result<bool, Box<dyn Error>> {
    Ok(!fs::read_dir(dir)?.any(|entry| {
        entry.is_ok_and(|entry| entry.file_name().to_string_lossy().starts_with("ran-"))
    }))
}

fn write_package(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = dir.join(name);
    fs::write(&path, bytes)?;
    Ok(path)
}

fn custom_deb(version: &[u8], control_tar: &[u8]) -> Vec<u8> {
    let data = tar(&[]);
    ar(&[
        ("debian-binary", version),
        ("control.tar", control_tar),
        ("data.tar", &data),
    ])
}

#[test]
fn inspects_a_built_package_without_running_scripts() -> TestResult {
    let Some(tools) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let status_before = sha256_of(DPKG_STATUS);
    let scripts = marker_scripts(dir.path());
    let package = build_with_dpkg(&tools, dir.path(), CONTROL, &scripts, &[], "xz")?
        .ok_or("xz build skipped")?;

    let inspection = inspector()?.inspect(&package)?;

    let control = inspection.control();
    assert_eq!(control.package(), "pakomichi-probe");
    assert_eq!(control.version(), "1.0.0-1");
    assert_eq!(control.architecture(), "amd64");
    assert_eq!(control.installed_size_kib(), Some(8));
    assert_eq!(control.pre_depends().as_deref(), Some("dpkg (>= 1.19)"));
    assert_eq!(
        control.depends().as_deref(),
        Some("libc6 (>= 2.34), libprobe1 | libprobe0")
    );
    assert_eq!(control.provides().as_deref(), Some("probe-virtual"));
    assert_eq!(control.conflicts().as_deref(), Some("probe-old"));
    assert_eq!(control.breaks().as_deref(), Some("probe-plugin (<< 1.0)"));
    assert_eq!(control.replaces().as_deref(), Some("probe-old"));
    assert_eq!(inspection.maintainer_scripts(), MaintainerScript::ALL);
    assert_eq!(inspection.format().version(), "2.0");
    assert_eq!(inspection.format().data_compression(), Compression::Xz);
    eprintln!(
        "format: {} control={} data={} members={:?}",
        inspection.format().version(),
        inspection.format().control_compression().as_str(),
        inspection.format().data_compression().as_str(),
        inspection.control_members()
    );

    assert!(no_markers(dir.path())?, "a maintainer script ran");
    assert_eq!(sha256_of(DPKG_STATUS), status_before, "dpkg status changed");
    Ok(())
}

#[test]
fn reads_every_supported_compression() -> TestResult {
    let Some(tools) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let inspector = inspector()?;
    for (name, expected) in [
        ("gzip", Compression::Gzip),
        ("xz", Compression::Xz),
        ("zstd", Compression::Zstd),
        ("none", Compression::None),
    ] {
        let Some(package) = build_with_dpkg(&tools, dir.path(), CONTROL, &[], &[], name)? else {
            continue;
        };
        let inspection = inspector.inspect(&package)?;
        let format = inspection.format();
        eprintln!(
            "-Z{name}: control member {} ({} bytes), data member {}",
            format.control_compression().as_str(),
            format.control_member_bytes(),
            format.data_compression().as_str()
        );
        assert_eq!(format.data_compression(), expected, "-Z{name}");
        assert_eq!(inspection.control().package(), "pakomichi-probe");
    }
    Ok(())
}

#[test]
fn rejects_truncated_and_corrupt_packages() -> TestResult {
    let Some(tools) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let package = build_with_dpkg(&tools, dir.path(), CONTROL, &[], &[], "gzip")?
        .ok_or("gzip build skipped")?;
    let bytes = fs::read(&package)?;
    let inspector = inspector()?;

    // The final byte may be the optional padding of an odd-sized data
    // member, so the last cut removes two bytes.
    for length in [0, 7, 48, 100, bytes.len() / 2, bytes.len() - 2] {
        let path = write_package(dir.path(), "truncated.deb", &bytes[..length])?;
        let result = inspector.inspect(&path);
        assert!(
            matches!(result, Err(InspectError::MalformedArchive { .. })),
            "length {length}: {result:?}"
        );
    }

    // Damage the gzip stream inside an intact container: only the native
    // decompressor can notice.
    let control_body = 8 + 60 + 4 + 60;
    let mut corrupt = bytes.clone();
    for byte in &mut corrupt[control_body + 20..control_body + 40] {
        *byte ^= 0x5a;
    }
    let path = write_package(dir.path(), "corrupt.deb", &corrupt)?;
    let error = inspector
        .inspect(&path)
        .err()
        .ok_or("a corrupt control stream was accepted")?;
    eprintln!("corrupt control member: {error}");
    assert!(matches!(
        error,
        InspectError::ToolFailed { .. } | InspectError::MalformedControlArchive { .. }
    ));
    assert_eq!(error.reason_code(), Some(ReasonCode::EArtifactMalformed));
    Ok(())
}

#[test]
fn checks_the_format_version_before_dpkg_deb() -> TestResult {
    let Some(_) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let (control_tar, _) = minimal_deb_members(CONTROL);
    let inspector = inspector()?;

    let path = write_package(dir.path(), "v3.deb", &custom_deb(b"3.0\n", &control_tar))?;
    assert!(matches!(
        inspector.inspect(&path),
        Err(InspectError::UnsupportedFormat { .. })
    ));

    // A newer minor version with an extra line is valid for both readers.
    let path = write_package(
        dir.path(),
        "v2-9.deb",
        &custom_deb(b"2.9\nfuture extension\n", &control_tar),
    )?;
    let inspection = inspector.inspect(&path)?;
    assert_eq!(inspection.format().version(), "2.9");
    Ok(())
}

#[test]
fn rejects_control_data_that_dpkg_deb_build_would_refuse() -> TestResult {
    let Some(_) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let inspector = inspector()?;

    let (control_tar, _) = minimal_deb_members("Package: pakomichi-probe\nArchitecture: all\n");
    let path = write_package(
        dir.path(),
        "no-version.deb",
        &custom_deb(b"2.0\n", &control_tar),
    )?;
    assert!(matches!(
        inspector.inspect(&path),
        Err(InspectError::MissingField { field: "Version" })
    ));

    let cases: [(&str, Vec<u8>); 3] = [
        (
            "duplicate-control.deb",
            tar(&[
                TarItem::file("./control", CONTROL.as_bytes()),
                TarItem::file(
                    "control",
                    b"Package: other\nVersion: 1\nArchitecture: all\n",
                ),
            ]),
        ),
        (
            "symlink-control.deb",
            tar(&[TarItem::symlink("./control", "/var/lib/dpkg/status")]),
        ),
        (
            "traversal.deb",
            tar(&[
                TarItem::file("./control", CONTROL.as_bytes()),
                TarItem::file("../../etc/cron.d/x", b""),
            ]),
        ),
    ];
    for (name, control_tar) in cases {
        let path = write_package(dir.path(), name, &custom_deb(b"2.0\n", &control_tar))?;
        let result = inspector.inspect(&path);
        assert!(
            matches!(result, Err(InspectError::MalformedControlArchive { .. })),
            "{name}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn accepts_many_and_long_fields_through_dpkg_deb() -> TestResult {
    let Some(_) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let mut text = String::from(CONTROL);
    for index in 0..300 {
        text.push_str(&format!("X-Probe-{index}: {}\n", "v".repeat(200)));
    }
    let (control_tar, _) = minimal_deb_members(&text);
    let path = write_package(dir.path(), "many.deb", &custom_deb(b"2.0\n", &control_tar))?;
    let inspection = inspector()?.inspect(&path)?;
    assert_eq!(inspection.control().fields().len(), 312);

    let limits = InspectLimits {
        max_fields: 100,
        ..InspectLimits::default()
    };
    let result = DebInspector::new(config(limits))?.inspect(&path);
    assert!(matches!(result, Err(InspectError::MalformedControl(_))));
    Ok(())
}

#[test]
fn rejects_an_oversized_control_member_without_running_dpkg_deb() -> TestResult {
    let Some(real) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let marker = dir.path().join("tool-ran");
    let fake = dir.path().join("fake-dpkg-deb");
    write_executable(
        &fake,
        &format!("#!/bin/sh\n: > '{}'\nexit 0\n", marker.display()),
    )?;

    let padding = vec![b'p'; 256 * 1024];
    let control_tar = tar(&[
        TarItem::file("./control", CONTROL.as_bytes()),
        TarItem::file("./padding", &padding),
    ]);
    let path = write_package(dir.path(), "big.deb", &custom_deb(b"2.0\n", &control_tar))?;
    let limits = InspectLimits {
        max_control_member_bytes: 64 * 1024,
        ..InspectLimits::default()
    };
    let inspector = DebInspector::new(InspectorConfig {
        tools: Some(ToolPaths {
            dpkg_deb: fake,
            prlimit: real.prlimit,
        }),
        ..config(limits)
    })?;
    assert!(matches!(
        inspector.inspect(&path),
        Err(InspectError::ControlMemberTooLarge { .. })
    ));
    assert!(!marker.exists(), "dpkg-deb ran for an oversized member");
    Ok(())
}

#[test]
fn stops_a_decompression_bomb() -> TestResult {
    let Some(tools) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    // A highly compressible control member: 16 MiB of zeros next to control.
    let zeros = vec![0_u8; 16 * 1024 * 1024];
    let path = build_with_dpkg(&tools, dir.path(), CONTROL, &[], &[("zeros", &zeros)], "xz")?
        .ok_or("xz build skipped")?;
    let compressed = fs::metadata(&path)?.len();

    let limits = InspectLimits {
        max_control_tar_bytes: 1024 * 1024,
        ..InspectLimits::default()
    };
    let result = DebInspector::new(config(limits))?.inspect(&path);
    eprintln!("bomb: {compressed} bytes on disk -> {result:?}");
    assert!(matches!(
        result,
        Err(InspectError::ControlArchiveTooLarge { limit: 1_048_576 })
    ));
    Ok(())
}

/// A package that passes the container checks, for fake-tool tests.
fn valid_package(dir: &Path) -> std::io::Result<PathBuf> {
    let (control_tar, _) = minimal_deb_members(CONTROL);
    write_package(dir, "valid.deb", &custom_deb(b"2.0\n", &control_tar))
}

fn with_fake_tool(
    dir: &Path,
    script: &str,
    limits: InspectLimits,
) -> Result<Option<DebInspector>, Box<dyn Error>> {
    let Some(real) = tools() else { return Ok(None) };
    let Some(prlimit) = real.prlimit else {
        eprintln!("SKIP: prlimit is not installed");
        return Ok(None);
    };
    let fake = dir.join("fake-dpkg-deb");
    write_executable(&fake, script)?;
    Ok(Some(DebInspector::new(InspectorConfig {
        tools: Some(ToolPaths {
            dpkg_deb: fake,
            prlimit: Some(prlimit),
        }),
        ..config(limits)
    })?))
}

#[test]
fn runs_the_tool_with_a_fixed_environment_and_the_package_on_stdin() -> TestResult {
    let dir = TempDir::new()?;
    let script = "#!/bin/sh\nenv >&2\nprintf 'ARGS=%s|%s\\n' \"$1\" \"$2\" >&2\nprintf 'CWD=%s\\n' \"$(pwd)\" >&2\nhead -c 8 \"$2\" >&2\nexit 3\n";
    let Some(inspector) = with_fake_tool(dir.path(), script, InspectLimits::default())? else {
        return Ok(());
    };
    let error = inspector
        .inspect(&valid_package(dir.path())?)
        .err()
        .ok_or("the fake tool succeeded")?;
    let InspectError::ToolFailed {
        exit_code: Some(3),
        stderr,
    } = error
    else {
        return Err(format!("unexpected result: {error:?}").into());
    };
    eprintln!("child view:\n{stderr}");
    assert!(stderr.contains("PATH=/usr/bin:/bin\n"));
    assert!(stderr.contains("LC_ALL=C\n"));
    assert!(stderr.contains("ARGS=--ctrl-tarfile|/proc/self/fd/0\n"));
    assert!(stderr.contains("CWD=/\n"));
    assert!(stderr.ends_with("!<arch>\n"));
    for leaked in ["HOME=", "TMPDIR=", "CARGO", "RUST", "USER="] {
        assert!(!stderr.contains(leaked), "{leaked} leaked into the child");
    }
    Ok(())
}

#[test]
fn a_compression_the_system_dpkg_cannot_read_is_a_platform_limit() -> TestResult {
    let dir = TempDir::new()?;
    // The diagnostic of a dpkg without zstd support for `control.tar.zst`.
    let script = "#!/bin/sh\necho \"dpkg-deb: error: archive '$2' uses unknown compression for member 'control.tar.zst', giving up\" >&2\nexit 2\n";
    let Some(inspector) = with_fake_tool(dir.path(), script, InspectLimits::default())? else {
        return Ok(());
    };
    let error = inspector
        .inspect(&valid_package(dir.path())?)
        .err()
        .ok_or("the fake tool succeeded")?;
    assert!(
        matches!(error, InspectError::ToolFailed { .. }),
        "{error:?}"
    );
    assert_eq!(error.reason_code(), Some(ReasonCode::EPlatformUnsupported));
    Ok(())
}

#[test]
fn kills_a_tool_that_exceeds_the_timeout() -> TestResult {
    let dir = TempDir::new()?;
    let limits = InspectLimits {
        timeout: Duration::from_millis(300),
        ..InspectLimits::default()
    };
    let Some(inspector) = with_fake_tool(dir.path(), "#!/bin/sh\nexec sleep 30\n", limits)? else {
        return Ok(());
    };
    let started = std::time::Instant::now();
    let result = inspector.inspect(&valid_package(dir.path())?);
    assert!(
        matches!(result, Err(InspectError::TimedOut { .. })),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    Ok(())
}

#[test]
fn caps_output_of_a_runaway_tool() -> TestResult {
    let dir = TempDir::new()?;
    let limits = InspectLimits {
        max_control_tar_bytes: 64 * 1024,
        max_stderr_bytes: 1024,
        ..InspectLimits::default()
    };
    let Some(inspector) = with_fake_tool(dir.path(), "#!/bin/sh\nexec cat /dev/zero\n", limits)?
    else {
        return Ok(());
    };
    let result = inspector.inspect(&valid_package(dir.path())?);
    assert!(
        matches!(
            result,
            Err(InspectError::ControlArchiveTooLarge { limit: 65_536 })
        ),
        "{result:?}"
    );

    let Some(inspector) =
        with_fake_tool(dir.path(), "#!/bin/sh\nexec cat /dev/zero >&2\n", limits)?
    else {
        return Ok(());
    };
    let result = inspector.inspect(&valid_package(dir.path())?);
    assert!(
        matches!(
            result,
            Err(InspectError::DiagnosticsTooLarge { limit: 1024 })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn applies_file_size_and_cpu_limits() -> TestResult {
    let dir = TempDir::new()?;
    let probe = dir.path().join("fsize-probe");
    let script = format!(
        "#!/bin/sh\nhead -c 4096 /dev/zero > '{}'\nexit 0\n",
        probe.display()
    );
    let Some(inspector) = with_fake_tool(dir.path(), &script, InspectLimits::default())? else {
        return Ok(());
    };
    // The tool printed no tar stream, so the inspection fails either way;
    // the point is that RLIMIT_FSIZE=0 stopped the write.
    assert!(inspector.inspect(&valid_package(dir.path())?).is_err());
    assert_eq!(
        fs::metadata(&probe)
            .map(|metadata| metadata.len())
            .unwrap_or(0),
        0
    );

    let limits = InspectLimits {
        cpu_seconds: 1,
        timeout: Duration::from_secs(30),
        ..InspectLimits::default()
    };
    let Some(inspector) = with_fake_tool(dir.path(), "#!/bin/sh\nwhile :; do :; done\n", limits)?
    else {
        return Ok(());
    };
    let result = inspector.inspect(&valid_package(dir.path())?);
    eprintln!("cpu limit: {result:?}");
    // SIGXCPU at the soft limit; SIGKILL if the hard limit is reached.
    assert!(
        matches!(result, Err(InspectError::ToolKilled { signal: 24 | 9 })),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn refuses_to_run_as_root_without_the_test_override() -> TestResult {
    let Some(_) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let result = DebInspector::new(InspectorConfig::default());
    if effective_uid()? == 0 {
        assert!(matches!(result, Err(InspectError::RunningAsRoot)));
        eprintln!("running as root: the inspector refused");
    } else {
        let inspection = result?.inspect(&valid_package(dir.path())?)?;
        assert_eq!(inspection.control().package(), "pakomichi-probe");
        eprintln!("running as uid {}: the inspector worked", effective_uid()?);
    }
    Ok(())
}

#[test]
fn opens_only_regular_files() -> TestResult {
    let Some(_) = tools() else { return Ok(()) };
    let dir = TempDir::new()?;
    let inspector = inspector()?;
    let package = valid_package(dir.path())?;

    let link = dir.path().join("link.deb");
    symlink(&package, &link)?;
    assert!(matches!(
        inspector.inspect(&link),
        Err(InspectError::NotRegularFile)
    ));
    assert!(matches!(
        inspector.inspect(dir.path()),
        Err(InspectError::NotRegularFile)
    ));

    let fifo = dir.path().join("fifo.deb");
    if Command::new("mkfifo").arg(&fifo).status()?.success() {
        assert!(matches!(
            inspector.inspect(&fifo),
            Err(InspectError::NotRegularFile)
        ));
    } else {
        eprintln!("SKIP: mkfifo failed; FIFO case not checked");
    }

    let limits = InspectLimits {
        max_package_bytes: 100,
        ..InspectLimits::default()
    };
    assert!(matches!(
        DebInspector::new(config(limits))?.inspect(&package),
        Err(InspectError::PackageTooLarge { limit: 100, .. })
    ));
    Ok(())
}
