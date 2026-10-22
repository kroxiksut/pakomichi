// SPDX-License-Identifier: MIT OR Apache-2.0

//! GitHub REST responses: dedicated wire types and validated conversion.
//!
//! ADR-019 point 3: GitHub owns this format, so unknown fields are tolerated
//! (no `deny_unknown_fields`), only used fields are deserialized, a missing or
//! mistyped required field is an error, identities and sizes are integers
//! (a JSON float such as `1.0` is refused), and the input size is bounded
//! before parsing. Fields that GitHub may omit (`digest`, `immutable`) are
//! `Option` and are never invented.

use std::fmt;

use serde::Deserialize;

use super::identity::{
    AssetId, IdentityError, OwnerId, OwnerLogin, ReleaseId, RepositoryId, RepositoryIdentity,
    RepositoryName,
};
use crate::cas::Sha256Digest;

/// Largest response body accepted by the parsers and the default client
/// limit. A page of 100 releases with long notes stays well below it.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Largest number of releases accepted in one page.
pub const MAX_RELEASES_PER_PAGE: usize = 100;

/// Largest number of assets accepted for one release.
pub const MAX_ASSETS_PER_RELEASE: usize = 1000;

/// Longest tag, commitish, or asset name accepted.
const MAX_TEXT_BYTES: usize = 255;

/// Longest download URL accepted.
const MAX_URL_BYTES: usize = 2048;

/// A response that does not satisfy the contract. Messages never quote the
/// response, so untrusted text does not reach logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    Oversized {
        length: usize,
        limit: usize,
    },
    /// Not JSON, or a required field is missing or has the wrong type.
    Json {
        category: &'static str,
        line: usize,
        column: usize,
    },
    Invalid {
        field: &'static str,
        problem: &'static str,
    },
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversized { length, limit } => {
                write!(
                    formatter,
                    "response is {length} bytes; the limit is {limit}"
                )
            }
            Self::Json {
                category,
                line,
                column,
            } => write!(formatter, "{category} error at line {line} column {column}"),
            Self::Invalid { field, problem } => write!(formatter, "field {field}: {problem}"),
        }
    }
}

impl std::error::Error for WireError {}

fn decode<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, WireError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(WireError::Oversized {
            length: body.len(),
            limit: MAX_RESPONSE_BYTES,
        });
    }
    serde_json::from_slice(body).map_err(|error| WireError::Json {
        category: match error.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        },
        line: error.line(),
        column: error.column(),
    })
}

fn invalid(field: &'static str) -> impl Fn(IdentityError) -> WireError {
    move |error| WireError::Invalid {
        field,
        problem: match error {
            IdentityError::ZeroId => "zero identifier",
            IdentityError::EmptyName => "empty",
            IdentityError::NameTooLong { .. } => "too long",
            IdentityError::InvalidNameCharacter => "disallowed character",
            IdentityError::ReservedName => "reserved name",
        },
    }
}

#[derive(Deserialize)]
struct RepositoryWire {
    id: u64,
    name: String,
    full_name: String,
    owner: OwnerWire,
}

#[derive(Deserialize)]
struct OwnerWire {
    id: u64,
    login: String,
}

/// Parses `GET /repos/{owner}/{repo}` or `GET /repositories/{id}`.
pub fn parse_repository(body: &[u8]) -> Result<RepositoryIdentity, WireError> {
    let wire: RepositoryWire = decode(body)?;
    let identity = RepositoryIdentity::new(
        RepositoryId::new(wire.id).map_err(invalid("id"))?,
        OwnerId::new(wire.owner.id).map_err(invalid("owner.id"))?,
        OwnerLogin::new(wire.owner.login).map_err(invalid("owner.login"))?,
        RepositoryName::new(wire.name).map_err(invalid("name"))?,
    );
    // The three name fields must agree; a disagreement means the response
    // is not the object it claims to be.
    if wire.full_name != identity.full_name() {
        return Err(WireError::Invalid {
            field: "full_name",
            problem: "does not match owner.login/name",
        });
    }
    Ok(identity)
}

#[derive(Deserialize)]
struct ReleaseWire {
    id: u64,
    tag_name: String,
    target_commitish: String,
    draft: bool,
    prerelease: bool,
    #[serde(default)]
    immutable: Option<bool>,
    #[serde(default)]
    published_at: Option<String>,
    assets: Vec<AssetWire>,
}

#[derive(Deserialize)]
struct AssetWire {
    id: u64,
    name: String,
    size: u64,
    #[serde(default)]
    digest: Option<String>,
    state: String,
    browser_download_url: String,
}

/// A validated release. Every flag here is a provider claim: `prerelease`
/// is mutable and `immutable` is not evidence by itself (specification
/// items 3 and 6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    pub id: ReleaseId,
    pub tag: String,
    /// A branch name or SHA as entered by the publisher; not a verified commit.
    pub target_commitish: String,
    pub draft: bool,
    pub prerelease: bool,
    /// `None` when the API omitted the field.
    pub immutable: Option<bool>,
    /// `YYYY-MM-DDTHH:MM:SSZ`; `None` for drafts.
    pub published_at: Option<String>,
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseAsset {
    pub id: AssetId,
    pub name: String,
    pub size: u64,
    /// The API's SHA-256 claim. `None` when the API omitted it (R-005: 23%
    /// of latest releases) or used another algorithm. It is reconciled with
    /// the downloaded bytes later and is never a signature.
    pub api_digest: Option<Sha256Digest>,
    /// `state == "uploaded"`; other states are incomplete uploads.
    pub uploaded: bool,
    /// HTTPS download URL as reported; the download task vets every hop.
    pub download_url: String,
}

/// Parses `GET .../releases/latest` or `GET .../releases/tags/{tag}`.
pub fn parse_release(body: &[u8]) -> Result<Release, WireError> {
    let wire: ReleaseWire = decode(body)?;
    convert_release(wire)
}

/// Parses one page of `GET .../releases`.
pub fn parse_release_page(body: &[u8]) -> Result<Vec<Release>, WireError> {
    let wire: Vec<ReleaseWire> = decode(body)?;
    if wire.len() > MAX_RELEASES_PER_PAGE {
        return Err(WireError::Invalid {
            field: "releases",
            problem: "too many entries in one page",
        });
    }
    wire.into_iter().map(convert_release).collect()
}

fn convert_release(wire: ReleaseWire) -> Result<Release, WireError> {
    if wire.assets.len() > MAX_ASSETS_PER_RELEASE {
        return Err(WireError::Invalid {
            field: "assets",
            problem: "too many assets",
        });
    }
    let published_at = match wire.published_at {
        Some(timestamp) if is_utc_timestamp(&timestamp) => Some(timestamp),
        Some(_) => {
            return Err(WireError::Invalid {
                field: "published_at",
                problem: "not a UTC timestamp",
            });
        }
        None => None,
    };
    Ok(Release {
        id: ReleaseId::new(wire.id).map_err(invalid("id"))?,
        tag: checked_text("tag_name", wire.tag_name)?,
        target_commitish: checked_text("target_commitish", wire.target_commitish)?,
        draft: wire.draft,
        prerelease: wire.prerelease,
        immutable: wire.immutable,
        published_at,
        assets: wire
            .assets
            .into_iter()
            .map(convert_asset)
            .collect::<Result<_, _>>()?,
    })
}

fn convert_asset(wire: AssetWire) -> Result<ReleaseAsset, WireError> {
    let name = checked_text("assets.name", wire.name)?;
    if name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(WireError::Invalid {
            field: "assets.name",
            problem: "not a plain file name",
        });
    }
    Ok(ReleaseAsset {
        id: AssetId::new(wire.id).map_err(invalid("assets.id"))?,
        name,
        size: wire.size,
        api_digest: parse_digest(wire.digest)?,
        uploaded: wire.state == "uploaded",
        download_url: checked_url(wire.browser_download_url)?,
    })
}

/// `sha256:<64 lowercase hex>` → digest; absent, `null`, or another
/// algorithm → `None`; a malformed SHA-256 value → error.
fn parse_digest(digest: Option<String>) -> Result<Option<Sha256Digest>, WireError> {
    let Some(digest) = digest else {
        return Ok(None);
    };
    match digest.strip_prefix("sha256:") {
        Some(hex) => Sha256Digest::from_hex(hex)
            .map(Some)
            .map_err(|_| WireError::Invalid {
                field: "assets.digest",
                problem: "malformed sha256 value",
            }),
        None => Ok(None),
    }
}

fn checked_text(field: &'static str, value: String) -> Result<String, WireError> {
    if value.is_empty() {
        return Err(WireError::Invalid {
            field,
            problem: "empty",
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(WireError::Invalid {
            field,
            problem: "too long",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(WireError::Invalid {
            field,
            problem: "control character",
        });
    }
    Ok(value)
}

fn checked_url(value: String) -> Result<String, WireError> {
    let problem = if value.len() > MAX_URL_BYTES {
        Some("too long")
    } else if !value.starts_with("https://") {
        Some("not an HTTPS URL")
    } else if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Some("disallowed character")
    } else if value["https://".len()..]
        .split(['/', '?', '#'])
        .next()
        .is_none_or(|authority| authority.is_empty() || authority.contains('@'))
    {
        Some("missing host or user information present")
    } else {
        None
    };
    match problem {
        Some(problem) => Err(WireError::Invalid {
            field: "assets.browser_download_url",
            problem,
        }),
        None => Ok(value),
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the form GitHub uses.
fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// The `message` of an error body, used only to recognise a secondary rate
/// limit on a 403 without rate-limit headers.
pub(crate) fn error_message(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorWire {
        message: String,
    }
    decode::<ErrorWire>(body).ok().map(|wire| wire.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_have_one_shape() {
        assert!(is_utc_timestamp("2026-10-20T10:44:17Z"));
        assert!(!is_utc_timestamp("2026-10-20T10:44:17+00:00"));
        assert!(!is_utc_timestamp("2026-10-20 10:44:17Z"));
    }

    #[test]
    fn download_urls_must_be_plain_https() {
        assert!(
            checked_url("https://github.com/a/b/releases/download/v1/x.deb".to_owned()).is_ok()
        );
        for url in [
            "http://github.com/x",
            "https://user@github.com/x",
            "https:///x",
            "https://github.com/a b",
        ] {
            assert!(checked_url(url.to_owned()).is_err(), "{url}");
        }
    }

    #[test]
    fn digests_are_optional_but_never_malformed() -> Result<(), WireError> {
        assert_eq!(parse_digest(None)?, None);
        assert_eq!(parse_digest(Some("sha512:abcd".to_owned()))?, None);
        assert!(parse_digest(Some(format!("sha256:{}", "0".repeat(64))))?.is_some());
        assert!(parse_digest(Some(format!("sha256:{}", "A".repeat(64)))).is_err());
        assert!(parse_digest(Some("sha256:".to_owned())).is_err());
        Ok(())
    }
}
