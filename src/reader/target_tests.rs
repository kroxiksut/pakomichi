// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

fn parsed(target: &str) -> Option<(String, String)> {
    parse_target(target)
        .ok()
        .map(|(repo, path)| (repo.as_str().to_owned(), path.as_str().to_owned()))
}

#[test]
fn origin_form_targets_split_into_repository_and_path() {
    assert_eq!(
        parsed("/src-1-apt-strict/dists/stable/InRelease"),
        Some(("src-1-apt-strict".into(), "dists/stable/InRelease".into()))
    );
    // APT escapes `+` and `~` in file names; they decode to the manifest's
    // own alphabet.
    assert_eq!(
        parsed("/src-1-apt-strict/pool/ab/libstdc%2B%2B6_1%7e1_amd64.deb"),
        Some((
            "src-1-apt-strict".into(),
            "pool/ab/libstdc++6_1~1_amd64.deb".into()
        ))
    );
}

#[test]
fn traversal_and_separators_are_refused_in_any_spelling() {
    // N-018: `..`, encoded dots, encoded separators, backslash and NUL.
    for (target, error) in [
        (
            "/src-1-apt-strict/../etc/passwd",
            TargetError::UnsafeSegment,
        ),
        (
            "/src-1-apt-strict/%2e%2e/etc/passwd",
            TargetError::UnsafeSegment,
        ),
        (
            "/src-1-apt-strict/%2E%2E/etc/passwd",
            TargetError::UnsafeSegment,
        ),
        ("/src-1-apt-strict/./InRelease", TargetError::UnsafeSegment),
        ("/src-1-apt-strict/a%2fb", TargetError::UnsafeSegment),
        ("/src-1-apt-strict/a%2Fb", TargetError::UnsafeSegment),
        ("/src-1-apt-strict/a%5cb", TargetError::UnsafeSegment),
        ("/src-1-apt-strict/a%00b", TargetError::UnsafeSegment),
        ("/src-1-apt-strict//InRelease", TargetError::UnsafeSegment),
        ("/src-1-apt-strict/InRelease/", TargetError::UnsafeSegment),
        (
            "/%2e%2e/src-1-apt-strict/InRelease",
            TargetError::UnsafeSegment,
        ),
    ] {
        assert_eq!(parse_target(target).err(), Some(error), "{target}");
    }
}

#[test]
fn malformed_targets_are_refused() {
    for (target, error) in [
        ("src-1-apt-strict/InRelease", TargetError::NotOriginForm),
        (
            "http://127.0.0.1/src-1-apt-strict/InRelease",
            TargetError::NotOriginForm,
        ),
        ("*", TargetError::NotOriginForm),
        (
            "/src-1-apt-strict/InRelease?x=1",
            TargetError::NotOriginForm,
        ),
        ("/src-1-apt-strict/InRelease#x", TargetError::NotOriginForm),
        ("/src-1-apt-strict/a%zz", TargetError::BadEscape),
        ("/src-1-apt-strict/a%2", TargetError::BadEscape),
        ("/src-1-apt-strict/a%ff", TargetError::BadEscape),
        ("/src-1-apt-strict", TargetError::NoPath),
        ("/", TargetError::UnsafeSegment),
        ("/Src-1/InRelease", TargetError::InvalidRepo),
        ("/src-1-apt-strict/a%20b", TargetError::InvalidPath),
        ("/src-1-apt-strict/a:b", TargetError::InvalidPath),
    ] {
        assert_eq!(parse_target(target).err(), Some(error), "{target}");
    }
    let long = format!("/src-1-apt-strict/{}", "a".repeat(MAX_TARGET_BYTES));
    assert_eq!(parse_target(&long).err(), Some(TargetError::TooLong));
}

#[test]
fn only_the_loopback_endpoint_is_an_accepted_host() {
    for host in [
        "127.0.0.1:8080",
        "localhost:8080",
        "LOCALHOST:8080",
        "[::1]:8080",
    ] {
        assert!(host_allowed(host, 8080), "{host}");
    }
    for host in [
        "127.0.0.1",
        "127.0.0.1:8081",
        "127.0.0.1:08080",
        "127.0.0.1:",
        "evil.example:8080",
        "localhost.evil.example:8080",
        "user@127.0.0.1:8080",
        "127.0.0.2:8080",
        "[::1]",
        "::1:8080",
        "",
    ] {
        assert!(!host_allowed(host, 8080), "{host}");
    }
    assert!(host_allowed("127.0.0.1", 80));
    assert!(host_allowed("[::1]", 80));
    assert!(!host_allowed("127.0.0.1:81", 80));
}
