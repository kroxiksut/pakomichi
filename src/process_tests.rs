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
