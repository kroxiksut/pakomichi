// SPDX-License-Identifier: MIT OR Apache-2.0

//! A strict parser of the single deb822 paragraph in a binary `control` file.
//!
//! Field names compare case-insensitively. A continuation line keeps its
//! leading whitespace and is joined with `\n`, as `dpkg-deb --field` prints
//! it. Duplicate fields, a second paragraph, control characters, invalid
//! UTF-8, and oversized values are errors, never silently resolved.

use std::collections::HashSet;
use std::fmt;

use super::InspectLimits;

const MAX_FIELD_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlProblem {
    InvalidUtf8,
    ControlCharacter,
    ContinuationWithoutField,
    MissingColon,
    InvalidFieldName,
    DuplicateField,
    FieldTooLong,
    TooManyFields,
    MultipleParagraphs,
    Empty,
}

impl ControlProblem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "not valid UTF-8",
            Self::ControlCharacter => "contains a control character",
            Self::ContinuationWithoutField => "continuation line without a field",
            Self::MissingColon => "line has no field separator",
            Self::InvalidFieldName => "invalid field name",
            Self::DuplicateField => "duplicate field",
            Self::FieldTooLong => "field value exceeds the limit",
            Self::TooManyFields => "too many fields",
            Self::MultipleParagraphs => "more than one paragraph",
            Self::Empty => "no fields",
        }
    }
}

/// A syntax error and the 1-based line where it was found (0 for the whole
/// file).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlError {
    line: usize,
    problem: ControlProblem,
}

impl ControlError {
    pub(crate) const fn new(line: usize, problem: ControlProblem) -> Self {
        Self { line, problem }
    }

    pub const fn line(&self) -> usize {
        self.line
    }

    pub const fn problem(&self) -> ControlProblem {
        self.problem
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.problem.as_str())
    }
}

impl std::error::Error for ControlError {}

/// One field as written: its name, and its value with continuation lines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) value: String,
}

/// Parses `bytes` into the fields of one paragraph, in file order.
pub(crate) fn parse_paragraph(
    bytes: &[u8],
    limits: &InspectLimits,
) -> Result<Vec<Field>, ControlError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        let line = bytes[..error.valid_up_to()]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            + 1;
        ControlError::new(line, ControlProblem::InvalidUtf8)
    })?;

    let mut fields: Vec<Field> = Vec::new();
    let mut names = HashSet::new();
    let mut paragraph_ended = false;

    for (index, line) in text.split('\n').enumerate() {
        let number = index + 1;
        let error = |problem| ControlError::new(number, problem);

        if line
            .chars()
            .any(|character| character.is_control() && character != '\t')
        {
            return Err(error(ControlProblem::ControlCharacter));
        }
        if line.trim().is_empty() {
            // A blank line ends the paragraph; leading blank lines are skipped.
            paragraph_ended = !fields.is_empty();
            continue;
        }
        // deb822(5): comment lines start at column 0 and are ignored.
        if line.starts_with('#') {
            continue;
        }
        if paragraph_ended {
            return Err(error(ControlProblem::MultipleParagraphs));
        }

        if line.starts_with([' ', '\t']) {
            let field = fields
                .last_mut()
                .ok_or(error(ControlProblem::ContinuationWithoutField))?;
            field.value.push('\n');
            field.value.push_str(line.trim_end());
            if field.value.len() > limits.max_field_bytes {
                return Err(error(ControlProblem::FieldTooLong));
            }
            continue;
        }

        let (name, value) = line
            .split_once(':')
            .ok_or(error(ControlProblem::MissingColon))?;
        if !is_field_name(name) {
            return Err(error(ControlProblem::InvalidFieldName));
        }
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(error(ControlProblem::DuplicateField));
        }
        if fields.len() >= limits.max_fields {
            return Err(error(ControlProblem::TooManyFields));
        }
        let value = value.trim();
        if value.len() > limits.max_field_bytes {
            return Err(error(ControlProblem::FieldTooLong));
        }
        fields.push(Field {
            name: name.to_owned(),
            value: value.to_owned(),
        });
    }

    if fields.is_empty() {
        return Err(ControlError::new(0, ControlProblem::Empty));
    }
    Ok(fields)
}

/// deb822(5): printable US-ASCII without `:` or whitespace, not starting
/// with `#` or `-`.
fn is_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FIELD_NAME_BYTES
        && !name.starts_with(['#', '-'])
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Vec<Field>, ControlError> {
        parse_paragraph(text.as_bytes(), &InspectLimits::default())
    }

    fn problem(text: &[u8]) -> Option<ControlProblem> {
        parse_paragraph(text, &InspectLimits::default())
            .err()
            .map(|error| error.problem())
    }

    #[test]
    fn parses_fields_and_continuations() -> Result<(), ControlError> {
        let fields = parse(
            "\nPackage: probe\nDepends: libc6 (>= 2.36),\n libssl3\nDescription: short\n long text\n .\n more\n\n\n",
        )?;
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[1].value, "libc6 (>= 2.36),\n libssl3");
        assert_eq!(fields[2].value, "short\n long text\n .\n more");
        Ok(())
    }

    #[test]
    fn ignores_comment_lines() -> Result<(), ControlError> {
        let fields = parse("# generated\nPackage: probe\n# note\nVersion: 1\n")?;
        assert_eq!(fields.len(), 2);
        Ok(())
    }

    #[test]
    fn rejects_duplicates_case_insensitively() {
        assert_eq!(
            problem(b"Package: a\npackage: b\n"),
            Some(ControlProblem::DuplicateField)
        );
    }

    #[test]
    fn rejects_malformed_lines() {
        assert_eq!(
            problem(b" continuation first\n"),
            Some(ControlProblem::ContinuationWithoutField)
        );
        assert_eq!(
            problem(b"Package probe\n"),
            Some(ControlProblem::MissingColon)
        );
        assert_eq!(
            problem(b"-Package: probe\n"),
            Some(ControlProblem::InvalidFieldName)
        );
        assert_eq!(
            problem(b"Pack age: probe\n"),
            Some(ControlProblem::InvalidFieldName)
        );
        assert_eq!(
            problem(b"Package: a\n\nPackage: b\n"),
            Some(ControlProblem::MultipleParagraphs)
        );
        assert_eq!(problem(b"\n\n"), Some(ControlProblem::Empty));
    }

    #[test]
    fn rejects_bad_encoding_and_control_characters() -> Result<(), String> {
        let error = parse_paragraph(b"Package: a\nVersion: \xff\n", &InspectLimits::default())
            .err()
            .ok_or("invalid UTF-8 was accepted")?;
        assert_eq!(error.problem(), ControlProblem::InvalidUtf8);
        assert_eq!(error.line(), 2);
        for text in [
            &b"Package: a\r\n"[..],
            b"Package: a\0\n",
            b"Package: \x1b[31m\n",
        ] {
            assert_eq!(problem(text), Some(ControlProblem::ControlCharacter));
        }
        // UTF-8 text in a value is fine.
        assert!(parse("Maintainer: Jürgen <j@example.invalid>\n").is_ok());
        Ok(())
    }

    #[test]
    fn enforces_field_limits() {
        let limits = InspectLimits {
            max_field_bytes: 8,
            max_fields: 2,
            ..InspectLimits::default()
        };
        let parse_limited = |text: &str| {
            parse_paragraph(text.as_bytes(), &limits)
                .err()
                .map(|error| error.problem())
        };
        assert_eq!(
            parse_limited("A: 123456789\n"),
            Some(ControlProblem::FieldTooLong)
        );
        assert_eq!(
            parse_limited("A: 1234\n 5678\n"),
            Some(ControlProblem::FieldTooLong)
        );
        assert_eq!(
            parse_limited("A: 1\nB: 2\nC: 3\n"),
            Some(ControlProblem::TooManyFields)
        );
        assert_eq!(parse_limited("A: 12345678\nB: 2\n"), None);
    }
}
