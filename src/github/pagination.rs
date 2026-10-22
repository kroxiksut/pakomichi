// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Link` header pagination with a strict next-page rule.
//!
//! The next URL must be on the API origin, on the same path as the first
//! page, with the same `per_page` and exactly the following page number. The
//! request for it is rebuilt from those validated parts, never copied, so a
//! hostile or broken header cannot send the client elsewhere, skip pages,
//! or loop.

use super::transport::API_ORIGIN;

/// Longest `Link` header parsed.
const MAX_LINK_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaginationError {
    Malformed,
    /// The next link leaves the origin or the path, or changes the page size.
    ForeignLink,
    /// The next link does not point to the following page.
    UnexpectedPage,
}

impl std::fmt::Display for PaginationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed Link header",
            Self::ForeignLink => "next link leaves the expected endpoint",
            Self::UnexpectedPage => "next link does not point to the following page",
        })
    }
}

impl std::error::Error for PaginationError {}

/// The path and query of page `page` (1-based).
pub fn page_path(path: &str, per_page: u32, page: u32) -> String {
    if page <= 1 {
        format!("{path}?per_page={per_page}")
    } else {
        format!("{path}?per_page={per_page}&page={page}")
    }
}

/// Returns the validated next page number, or `None` on the last page.
pub fn next_page(
    link: Option<&str>,
    path: &str,
    per_page: u32,
    current_page: u32,
) -> Result<Option<u32>, PaginationError> {
    let Some(link) = link else {
        return Ok(None);
    };
    let Some(target) = find_next(link)? else {
        return Ok(None);
    };
    let relative = target
        .strip_prefix(API_ORIGIN)
        .filter(|rest| rest.starts_with('/'))
        .ok_or(PaginationError::ForeignLink)?;
    let (target_path, query) = relative
        .split_once('?')
        .ok_or(PaginationError::ForeignLink)?;
    if target_path != path {
        return Err(PaginationError::ForeignLink);
    }
    let mut size = None;
    let mut page = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').ok_or(PaginationError::Malformed)?;
        let slot = match key {
            "per_page" => &mut size,
            "page" => &mut page,
            _ => return Err(PaginationError::ForeignLink),
        };
        if slot.replace(parse_number(value)?).is_some() {
            return Err(PaginationError::Malformed);
        }
    }
    if size != Some(per_page) {
        return Err(PaginationError::ForeignLink);
    }
    match page {
        Some(page) if Some(page) == current_page.checked_add(1) => Ok(Some(page)),
        _ => Err(PaginationError::UnexpectedPage),
    }
}

fn parse_number(value: &str) -> Result<u32, PaginationError> {
    if value.is_empty() || value.len() > 9 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PaginationError::Malformed);
    }
    value.parse().map_err(|_| PaginationError::Malformed)
}

/// Finds the target of the `rel="next"` link (RFC 8288 subset used by
/// GitHub: `<url>; rel="next", <url>; rel="last"`).
fn find_next(header: &str) -> Result<Option<&str>, PaginationError> {
    if header.len() > MAX_LINK_BYTES {
        return Err(PaginationError::Malformed);
    }
    let mut next = None;
    let mut rest = header.trim_start();
    while !rest.is_empty() {
        let after_open = rest.strip_prefix('<').ok_or(PaginationError::Malformed)?;
        let (target, after_target) = after_open
            .split_once('>')
            .ok_or(PaginationError::Malformed)?;
        let (parameters, remainder) = match after_target.split_once(',') {
            Some((parameters, remainder)) => (parameters, remainder),
            None => (after_target, ""),
        };
        let is_next = parameters.split(';').any(|parameter| {
            let parameter = parameter.trim();
            parameter
                .strip_prefix("rel=")
                .map(|value| value.trim_matches('"'))
                .is_some_and(|value| value.split_ascii_whitespace().any(|rel| rel == "next"))
        });
        if is_next {
            if next.is_some() {
                return Err(PaginationError::Malformed);
            }
            next = Some(target);
        }
        rest = remainder.trim_start();
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/repositories/7/releases";

    fn link(next: &str) -> String {
        format!(
            "<{next}>; rel=\"next\", <https://api.github.com/repositories/7/releases?per_page=100&page=9>; rel=\"last\""
        )
    }

    #[test]
    fn github_style_links_are_followed_one_page_at_a_time() {
        let header = link("https://api.github.com/repositories/7/releases?per_page=100&page=2");
        assert_eq!(next_page(Some(&header), PATH, 100, 1), Ok(Some(2)));
        assert_eq!(next_page(None, PATH, 100, 1), Ok(None));
        let last_only =
            "<https://api.github.com/repositories/7/releases?per_page=100&page=1>; rel=\"first\"";
        assert_eq!(next_page(Some(last_only), PATH, 100, 2), Ok(None));
    }

    #[test]
    fn foreign_or_skipping_links_are_refused() {
        for (next, expected) in [
            (
                "https://evil.example/repositories/7/releases?per_page=100&page=2",
                PaginationError::ForeignLink,
            ),
            (
                "https://api.github.com.evil.example/repositories/7/releases?per_page=100&page=2",
                PaginationError::ForeignLink,
            ),
            (
                "http://api.github.com/repositories/7/releases?per_page=100&page=2",
                PaginationError::ForeignLink,
            ),
            (
                "https://api.github.com/repositories/8/releases?per_page=100&page=2",
                PaginationError::ForeignLink,
            ),
            (
                "https://api.github.com/repositories/7/releases?per_page=100&page=2&after=x",
                PaginationError::ForeignLink,
            ),
            (
                "https://api.github.com/repositories/7/releases?per_page=1&page=2",
                PaginationError::ForeignLink,
            ),
            (
                "https://api.github.com/repositories/7/releases?per_page=100&page=3",
                PaginationError::UnexpectedPage,
            ),
            (
                "https://api.github.com/repositories/7/releases?per_page=100&page=1",
                PaginationError::UnexpectedPage,
            ),
            (
                "https://api.github.com/repositories/7/releases?per_page=100&page=2&page=3",
                PaginationError::Malformed,
            ),
        ] {
            assert_eq!(
                next_page(Some(&link(next)), PATH, 100, 1),
                Err(expected),
                "{next}"
            );
        }
        assert_eq!(
            next_page(Some("garbage"), PATH, 100, 1),
            Err(PaginationError::Malformed)
        );
    }

    #[test]
    fn page_paths_are_rebuilt() {
        assert_eq!(
            page_path(PATH, 100, 1),
            "/repositories/7/releases?per_page=100"
        );
        assert_eq!(
            page_path(PATH, 100, 3),
            "/repositories/7/releases?per_page=100&page=3"
        );
    }
}
