// SPDX-License-Identifier: MIT OR Apache-2.0

use std::os::unix::net::UnixListener;

use super::*;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn a_key_directory_others_can_enter_or_another_user_owns_is_refused() -> TestResult {
    let dir = TempDir::new()?;
    let keys = dir.join("keys");
    fs::create_dir(&keys)?;
    let uid = effective_uid()?;
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700))?;
    require_private_dir(&keys, uid)?;
    for mode in [0o750, 0o705, 0o770] {
        fs::set_permissions(&keys, fs::Permissions::from_mode(mode))?;
        assert!(
            matches!(require_private_dir(&keys, uid), Err(StartError::Unsafe(_))),
            "{mode:o}"
        );
    }
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700))?;
    assert!(matches!(
        require_private_dir(&keys, uid.wrapping_add(1)),
        Err(StartError::Unsafe(_))
    ));
    // A regular file with the right owner and mode is not a directory:
    // the signer would take a file anyone can replace for its key home.
    let file = dir.join("file");
    fs::write(&file, b"")?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(
        require_private_dir(&file, uid),
        Err(StartError::Unsafe(_))
    ));
    // A symlink to a private directory is not the directory.
    let link = dir.join("link");
    std::os::unix::fs::symlink(&keys, &link)?;
    assert!(matches!(
        require_private_dir(&link, uid),
        Err(StartError::Unsafe(_))
    ));
    Ok(())
}

#[test]
fn the_admitted_peer_is_the_owner_of_a_real_socket_file() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.join("fetch.sock");
    let _listener = UnixListener::bind(&path)?;
    assert_eq!(socket_owner(&path)?, effective_uid()?);
    // A regular file or a symlink at the socket's path is refused.
    let file = dir.join("file");
    fs::write(&file, b"")?;
    assert!(matches!(socket_owner(&file), Err(StartError::Unsafe(_))));
    let link = dir.join("link.sock");
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(matches!(socket_owner(&link), Err(StartError::Unsafe(_))));
    Ok(())
}

#[test]
fn an_unprivileged_role_refuses_root_and_the_applier_requires_it() -> TestResult {
    let uid = effective_uid()?;
    if uid == 0 {
        assert!(matches!(require_unprivileged(), Err(StartError::Root)));
        require_root()?;
    } else {
        assert_eq!(require_unprivileged()?, uid);
        assert!(matches!(require_root(), Err(StartError::NotRoot { .. })));
    }
    Ok(())
}

#[test]
fn every_role_check_answers_both_ways_whoever_runs_the_tests() {
    // The builder runs the tests as root, so the live check never takes the
    // other branch; the mapping from uid to answer is checked directly.
    assert!(matches!(unprivileged_role(0), Err(StartError::Root)));
    assert!(matches!(unprivileged_role(996), Ok(996)));
    assert!(root_role(0).is_ok());
    assert!(matches!(
        root_role(996),
        Err(StartError::NotRoot { uid: 996 })
    ));
}

/// Set in the child process of
/// `every_named_socket_is_inherited_not_only_the_first`.
const CHILD: &str = "PAKOMICHI_TEST_INHERITED_CHILD";

#[test]
fn every_named_socket_is_inherited_not_only_the_first() -> TestResult {
    // systemd passes the state owner three listeners at once. Taking the
    // first must not lose the others (`listenfd` clears `LISTEN_FDS` on
    // every read of the environment).
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use std::os::fd::AsRawFd;
    let dir = TempDir::new()?;
    // Two listeners on consecutive descriptors, as systemd numbers them.
    let mut kept = Vec::new();
    let (first, second) = loop {
        let first = UnixListener::bind(dir.join(&format!("a{}.sock", kept.len())))?;
        let second = UnixListener::bind(dir.join(&format!("b{}.sock", kept.len())))?;
        if second.as_raw_fd() == first.as_raw_fd() + 1 {
            break (first, second);
        }
        kept.push((first, second));
        if kept.len() > 20 {
            return Err("no consecutive descriptors".into());
        }
    };
    for listener in [&first, &second] {
        fcntl(listener, FcntlArg::F_SETFD(FdFlag::empty()))?;
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "process::tests::child_takes_both_named_sockets",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("LISTEN_FDS", "2")
        .env("LISTEN_FDS_FIRST_FD", first.as_raw_fd().to_string())
        .env("LISTEN_FDNAMES", "fetch:status")
        .env_remove("LISTEN_PID")
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("1 passed"), "{text}");
    Ok(())
}

/// Runs only as the child of the test above.
#[test]
fn child_takes_both_named_sockets() -> TestResult {
    if std::env::var_os(CHILD).is_none() {
        return Ok(());
    }
    let fetch = inherited_unix_listener("fetch")?;
    let status = inherited_unix_listener("status")?;
    assert_ne!(
        fetch.local_addr()?.as_pathname(),
        status.local_addr()?.as_pathname()
    );
    // Each socket is taken once.
    assert!(inherited_unix_listener("status").is_err());
    Ok(())
}
