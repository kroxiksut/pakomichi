// SPDX-License-Identifier: MIT OR Apache-2.0

//! Request targets and `Host` values of the repository reader.
//!
//! A target is `/<repo>/<path>` in origin form. Every segment is
//! percent-decoded on its own, and a decoded segment that could change the
//! structure of the path (empty, `.`, `..`, or containing `/`, `\` or NUL)
//! rejects the whole target, so `%2e%2e` and `%2f` are refused like `..`
//! and `/` (N-018). The decoded repository name and path must then pass the
//! same validation as the manifest ([`RepoName`], [`RepoPath`]), so nothing
//! outside a manifest's own alphabet can be looked up.

use crate::publish::{RepoName, RepoPath};

/// Longest request target accepted, in bytes.
pub const MAX_TARGET_BYTES: usize = 2048;

/// Why a request target was refused. Every variant is answered as "not
/// found": the reader does not explain which rule a path broke.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    TooLong,
    /// Not origin form: no leading `/`, a query, or a fragment.
    NotOriginForm,
    /// A percent escape that is not two hexadecimal digits, or a segment
    /// that is not UTF-8 after decoding.
    BadEscape,
    /// A decoded segment that is empty, `.`, `..`, or contains `/`, `\` or
    /// NUL.
    UnsafeSegment,
    /// Fewer than two segments: no path inside a repository.
    NoPath,
    InvalidRepo,
    InvalidPath,
}

/// Splits and decodes `/<repo>/<path>`.
pub fn parse_target(target: &str) -> Result<(RepoName, RepoPath), TargetError> {
    if target.len() > MAX_TARGET_BYTES {
        return Err(TargetError::TooLong);
    }
    let Some(rest) = target.strip_prefix('/') else {
        return Err(TargetError::NotOriginForm);
    };
    if rest.contains(['?', '#']) {
        return Err(TargetError::NotOriginForm);
    }
    let segments = rest
        .split('/')
        .map(decode_segment)
        .collect::<Result<Vec<_>, _>>()?;
    let Some((repo, path)) = segments.split_first() else {
        return Err(TargetError::NoPath);
    };
    if path.is_empty() {
        return Err(TargetError::NoPath);
    }
    let repo = RepoName::new(repo).map_err(|_| TargetError::InvalidRepo)?;
    let path = RepoPath::new(&path.join("/")).map_err(|_| TargetError::InvalidPath)?;
    Ok((repo, path))
}

fn decode_segment(segment: &str) -> Result<String, TargetError> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let digits = bytes
                .get(index + 1..index + 3)
                .ok_or(TargetError::BadEscape)?;
            let high = hex_digit(digits[0]).ok_or(TargetError::BadEscape)?;
            let low = hex_digit(digits[1]).ok_or(TargetError::BadEscape)?;
            decoded.push(high << 4 | low);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    let text = String::from_utf8(decoded).map_err(|_| TargetError::BadEscape)?;
    if text.is_empty() || text == "." || text == ".." || text.contains(['/', '\\', '\0']) {
        return Err(TargetError::UnsafeSegment);
    }
    Ok(text)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Whether `host` names the loopback endpoint the reader listens on:
/// `127.0.0.1`, `localhost` or `[::1]` with the listening port, compared
/// without regard to letter case. The port may be omitted only when it is
/// 80. Any other value (another name, another port, userinfo) is refused,
/// which stops DNS-rebinding pages from reading the repositories.
pub fn host_allowed(host: &str, port: u16) -> bool {
    let (name, given_port) = match host.rsplit_once(':') {
        Some((name, digits)) if !name.is_empty() && name != "[" && !digits.contains(']') => {
            match digits.parse::<u16>() {
                Ok(given) if given.to_string() == digits => (name, Some(given)),
                _ => return false,
            }
        }
        _ => (host, None),
    };
    let port_matches = match given_port {
        Some(given) => given == port,
        None => port == 80,
    };
    port_matches
        && ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(name))
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod tests;
