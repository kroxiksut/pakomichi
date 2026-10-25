// SPDX-License-Identifier: MIT OR Apache-2.0

//! The repository address a user gives to `pchi source add` (and, later,
//! to `preview`, ADR-033 point 3).
//!
//! Only `https://github.com/<owner>/<name>` is accepted, with an optional
//! `.git` and one trailing slash. Everything that could make the address
//! mean something else is refused before any request: another scheme or
//! host, userinfo (`user@`, a token in the URL), a port, a query or
//! fragment, more path segments, percent-encoding, and names GitHub would
//! not issue. The address only finds the repository once; the source is
//! then pinned by its numeric IDs (ADR-005).

use std::fmt;

use super::identity::{OwnerLogin, RepositoryName};

const PREFIX: &str = "https://github.com/";
/// Longer than any GitHub owner and repository name together.
const MAX_ADDRESS_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressError(&'static str);

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "not a GitHub repository address: {}", self.0)
    }
}

impl std::error::Error for AddressError {}

/// The owner and the repository name of a GitHub address.
pub fn parse_repository_address(
    address: &str,
) -> Result<(OwnerLogin, RepositoryName), AddressError> {
    if address.len() > MAX_ADDRESS_BYTES {
        return Err(AddressError("too long"));
    }
    if address.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return Err(AddressError("a space or a non-ASCII character"));
    }
    let rest = address
        .strip_prefix(PREFIX)
        .ok_or(AddressError("only https://github.com/<owner>/<name>"))?;
    if rest.contains(['?', '#', '%', '@', ':', '\\']) {
        return Err(AddressError("a query, fragment, escape, userinfo or port"));
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut segments = rest.split('/');
    let (Some(owner), Some(name), None) = (segments.next(), segments.next(), segments.next())
    else {
        return Err(AddressError("exactly an owner and a repository name"));
    };
    let name = name.strip_suffix(".git").unwrap_or(name);
    let owner = OwnerLogin::new(owner).map_err(|_| AddressError("the owner name"))?;
    let name = RepositoryName::new(name).map_err(|_| AddressError("the repository name"))?;
    Ok((owner, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_plain_github_repository_address_is_accepted() {
        for good in [
            "https://github.com/kroxiksut/pchi-test",
            "https://github.com/kroxiksut/pchi-test/",
            "https://github.com/kroxiksut/pchi-test.git",
            "https://github.com/pchi-test-org/pchi.test_2",
        ] {
            assert!(parse_repository_address(good).is_ok(), "{good}");
        }
        let (owner, name) = parse_repository_address("https://github.com/kroxiksut/pchi-test.git")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(format!("{owner}/{name}"), "kroxiksut/pchi-test");
    }

    #[test]
    fn an_address_that_could_mean_something_else_is_refused() {
        for bad in [
            "http://github.com/o/r",
            "https://github.com.evil.example/o/r",
            "https://evil.example/github.com/o/r",
            "https://token@github.com/o/r",
            "https://github.com:8443/o/r",
            "https://github.com/o/r?tab=readme",
            "https://github.com/o/r#x",
            "https://github.com/o/r/releases",
            "https://github.com/o",
            "https://github.com//r",
            "https://github.com/o/%72",
            "https://github.com/o/r\n",
            "https://github.com/o/r x",
            "https://github.com/o/../r",
            "HTTPS://GITHUB.COM/o/r",
            "https://github.com/o/r//",
        ] {
            assert!(parse_repository_address(bad).is_err(), "{bad:?}");
        }
        assert!(
            parse_repository_address(&format!("https://github.com/o/{}", "r".repeat(300))).is_err()
        );
    }
}
