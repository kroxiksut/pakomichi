// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SQLite floor of ADR-020: the oldest library the state owner accepts
//! and the SQL features newer than it that Pakomichi must not use.
//!
//! This part has no SQLite dependency, so it is checked on every target,
//! including the Windows development host.

/// SQLite 3.34.1, the oldest version the schema and its tests run on
/// (AlmaLinux 9) and the floor of `rusqlite 0.40.2`, in the form of
/// `sqlite3_libversion_number()`.
pub const MIN_SQLITE_VERSION: i32 = 3_034_001;

/// Formats a `sqlite3_libversion_number()` value as `3.34.1`.
pub fn format_version(number: i32) -> String {
    format!(
        "{}.{}.{}",
        number / 1_000_000,
        number / 1_000 % 1_000,
        number % 1_000
    )
}

/// SQL that needs a newer SQLite than the floor (ADR-020 point 3), with
/// the version that introduced it. Matched case-insensitively outside
/// comments and string literals.
pub const NEWER_THAN_FLOOR: [(&str, &str); 7] = [
    ("RETURNING", "3.35.0"),
    ("DROP COLUMN", "3.35.0"),
    ("STRICT", "3.37.0"),
    ("UNIXEPOCH", "3.38.0"),
    ("->>", "3.38.0"),
    ("->", "3.38.0"),
    ("OCTET_LENGTH", "3.43.0"),
];

/// JSON functions are built in only from 3.38.0; before that a
/// distribution may compile them out (ADR-020 point 3), so a call of
/// `json(...)` or `json_*(...)` is reported as this name.
pub const JSON_FUNCTION: &str = "JSON function";

/// The features from [`NEWER_THAN_FLOOR`], and [`JSON_FUNCTION`], that
/// `sql` uses.
pub fn newer_features(sql: &str) -> Vec<&'static str> {
    let code = strip_comments_and_strings(sql).to_ascii_uppercase();
    let mut found: Vec<&'static str> = NEWER_THAN_FLOOR
        .iter()
        .filter(|(feature, _)| contains_token(&code, feature))
        .map(|(feature, _)| *feature)
        .collect();
    if calls_json_function(&code) {
        found.push(JSON_FUNCTION);
    }
    found
}

/// A `JSON` or `JSON_<name>` identifier followed by `(`.
fn calls_json_function(code: &str) -> bool {
    let bytes = code.as_bytes();
    let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut from = 0;
    while let Some(offset) = code.get(from..).and_then(|rest| rest.find("JSON")) {
        let start = from + offset;
        from = start + 1;
        if start > 0 && is_ident(bytes[start - 1]) {
            continue;
        }
        let mut end = start + 4;
        if bytes.get(end) == Some(&b'_') {
            while bytes.get(end).is_some_and(|byte| is_ident(*byte)) {
                end += 1;
            }
        } else if bytes.get(end).is_some_and(|byte| is_ident(*byte)) {
            continue;
        }
        while bytes.get(end).is_some_and(u8::is_ascii_whitespace) {
            end += 1;
        }
        if bytes.get(end) == Some(&b'(') {
            return true;
        }
    }
    false
}

/// Whether `feature` occurs in `code` as a token: a word must not be part
/// of a longer identifier, so `STRICT` does not match `RESTRICT`.
fn contains_token(code: &str, feature: &str) -> bool {
    let word_like = feature
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic());
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(offset) = code.get(from..).and_then(|rest| rest.find(feature)) {
        let start = from + offset;
        let end = start + feature.len();
        from = start + 1;
        if !word_like {
            return true;
        }
        let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_ident(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Replaces `--` and `/* */` comments and `'...'` string literals with
/// spaces, so that prose and data never count as SQL.
fn strip_comments_and_strings(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '-' if chars.peek() == Some(&'-') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous = ' ';
                for next in chars.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    previous = next;
                }
                out.push(' ');
            }
            '\'' => {
                // `''` inside a literal is an escaped quote.
                while let Some(next) = chars.next() {
                    if next == '\'' {
                        if chars.peek() == Some(&'\'') {
                            chars.next();
                            continue;
                        }
                        break;
                    }
                }
                out.push_str("''");
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_format_as_dotted_text() {
        assert_eq!(format_version(MIN_SQLITE_VERSION), "3.34.1");
        assert_eq!(format_version(3_051_002), "3.51.2");
    }

    #[test]
    fn newer_features_are_found_outside_comments_and_strings() {
        assert_eq!(
            newer_features("INSERT INTO t(a) VALUES (1) RETURNING a;"),
            vec!["RETURNING"]
        );
        assert_eq!(
            newer_features("CREATE TABLE t (a TEXT) STRICT;"),
            vec!["STRICT"]
        );
        assert_eq!(
            newer_features("ALTER TABLE t DROP COLUMN a;"),
            vec!["DROP COLUMN"]
        );
        assert_eq!(newer_features("SELECT unixepoch();"), vec!["UNIXEPOCH"]);
        assert_eq!(
            newer_features("SELECT doc ->> '$.a' FROM t;"),
            vec!["->>", "->"]
        );
        assert_eq!(
            newer_features("SELECT json_extract(doc, '$.a');"),
            vec![JSON_FUNCTION]
        );
        assert_eq!(newer_features("SELECT JSON ('[]');"), vec![JSON_FUNCTION]);
        // Prose, data, and longer identifiers do not count.
        assert!(newer_features("-- STRICT tables are not used\nSELECT 1;").is_empty());
        assert!(newer_features("/* RETURNING */ SELECT 1;").is_empty());
        assert!(newer_features("SELECT 'uses -> and RETURNING';").is_empty());
        assert!(newer_features("SELECT 'it''s RETURNING';").is_empty());
        assert!(newer_features("FOREIGN KEY (a) REFERENCES b(a) ON DELETE RESTRICT").is_empty());
        assert!(
            newer_features("SELECT returning_count, json_text, record_json FROM t;").is_empty()
        );
        assert!(newer_features("SELECT iif(a, 1, 2) FROM t;").is_empty());
    }

    #[test]
    fn the_shipped_migrations_stay_on_the_floor() {
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut checked = 0;
        for entry in std::fs::read_dir(&migrations)
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "sql") {
                let sql = std::fs::read_to_string(&path).unwrap_or_default();
                assert!(!sql.is_empty(), "{}", path.display());
                assert_eq!(
                    newer_features(&sql),
                    Vec::<&str>::new(),
                    "{}",
                    path.display()
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "no migration found");
    }
}
