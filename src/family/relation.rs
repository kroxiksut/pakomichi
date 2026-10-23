// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native relationship fields reduced to a common model.
//!
//! DEB fields are parsed with dpkg's rules for binary packages: entries are
//! comma-separated, `|` separates alternatives only in `Depends` and
//! `Pre-Depends`, a version constraint is one of `<<`, `<=`, `=`, `>=`,
//! `>>` (the obsolete `<` and `>` mean `<=` and `>=`), `Provides` accepts
//! only `=`, and build-profile or architecture restrictions (`[…]`, `<…>`)
//! do not occur in a binary package. RPM entries come from the header with
//! their `RPMSENSE_*` flags; rich (boolean) dependencies are kept as text.

use std::fmt;

use super::version::{DebVersion, Op, RpmEvr, VersionError};
use crate::inspect::RpmDependency;

/// One package name with an optional version constraint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Atom {
    pub name: String,
    pub constraint: Option<(Op, String)>,
}

impl fmt::Display for Atom {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.constraint {
            Some((op, version)) => write!(formatter, "{} ({} {version})", self.name, op.deb()),
            None => formatter.write_str(&self.name),
        }
    }
}

/// One dependency entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Clause {
    /// Satisfied by any one alternative (a single atom for RPM).
    Any(Vec<Atom>),
    /// An RPM rich dependency such as `(foo >= 1 if bar)`, not evaluated.
    Rich(String),
}

impl fmt::Display for Clause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any(atoms) => {
                for (index, atom) in atoms.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(" | ")?;
                    }
                    write!(formatter, "{atom}")?;
                }
                Ok(())
            }
            Self::Rich(text) => formatter.write_str(text),
        }
    }
}

/// Why a relationship field is malformed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationError {
    pub field: &'static str,
    pub entry: String,
    pub problem: RelationProblem,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelationProblem {
    EmptyEntry,
    BadName,
    BadArchQualifier,
    BadOperator,
    /// A `[…]` or `<…>` restriction, only valid in source packages.
    Restriction,
    /// `|` in a field without alternatives.
    Alternatives,
    /// An operator other than `=` in `Provides`.
    ProvidesOperator,
    Version(VersionError),
    Trailing,
}

impl fmt::Display for RelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "malformed {} entry {:?}: ",
            self.field, self.entry
        )?;
        match &self.problem {
            RelationProblem::EmptyEntry => formatter.write_str("empty entry"),
            RelationProblem::BadName => formatter.write_str("not a package name"),
            RelationProblem::BadArchQualifier => formatter.write_str("bad architecture qualifier"),
            RelationProblem::BadOperator => formatter.write_str("unknown operator"),
            RelationProblem::Restriction => {
                formatter.write_str("restriction list in a binary package")
            }
            RelationProblem::Alternatives => formatter.write_str("alternatives are not allowed"),
            RelationProblem::ProvidesOperator => formatter.write_str("Provides allows only ="),
            RelationProblem::Version(error) => write!(formatter, "{error}"),
            RelationProblem::Trailing => formatter.write_str("unexpected text after the entry"),
        }
    }
}

impl std::error::Error for RelationError {}

/// Which DEB field is parsed; it decides what the field may contain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebField {
    Depends,
    PreDepends,
    Provides,
    Conflicts,
    Breaks,
    Replaces,
}

impl DebField {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Depends => "Depends",
            Self::PreDepends => "Pre-Depends",
            Self::Provides => "Provides",
            Self::Conflicts => "Conflicts",
            Self::Breaks => "Breaks",
            Self::Replaces => "Replaces",
        }
    }

    const fn allows_alternatives(self) -> bool {
        matches!(self, Self::Depends | Self::PreDepends)
    }
}

/// Parses one DEB relationship field. A missing or blank field is empty.
pub fn parse_deb_field(field: DebField, value: Option<&str>) -> Result<Vec<Clause>, RelationError> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(|entry| {
            let error = |problem| RelationError {
                field: field.name(),
                entry: entry.trim().to_owned(),
                problem,
            };
            let alternatives: Vec<&str> = entry.split('|').collect();
            if alternatives.len() > 1 && !field.allows_alternatives() {
                return Err(error(RelationProblem::Alternatives));
            }
            alternatives
                .into_iter()
                .map(|text| parse_deb_atom(field, text).map_err(error))
                .collect::<Result<Vec<_>, _>>()
                .map(Clause::Any)
        })
        .collect()
}

fn parse_deb_atom(field: DebField, text: &str) -> Result<Atom, RelationProblem> {
    let text = text.trim();
    if text.is_empty() {
        return Err(RelationProblem::EmptyEntry);
    }
    // `<` inside the parentheses is an operator; outside them, and `[`
    // anywhere, it opens a restriction list.
    let outside = match (text.find('('), text.rfind(')')) {
        (Some(open), Some(close)) if open < close => [&text[..open], &text[close + 1..]],
        (Some(open), _) => [&text[..open], ""],
        (None, _) => [text, ""],
    };
    if text.contains(['[', ']']) || outside.iter().any(|part| part.contains(['<', '>'])) {
        return Err(RelationProblem::Restriction);
    }
    let name_end = text
        .find(|character: char| character.is_whitespace() || character == '(' || character == ':')
        .unwrap_or(text.len());
    let name = &text[..name_end];
    if !is_deb_name(name) {
        return Err(RelationProblem::BadName);
    }
    let mut rest = &text[name_end..];
    if let Some(after) = rest.strip_prefix(':') {
        let end = after
            .find(|character: char| character.is_whitespace() || character == '(')
            .unwrap_or(after.len());
        let arch = &after[..end];
        if arch.is_empty()
            || !arch
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(RelationProblem::BadArchQualifier);
        }
        rest = &after[end..];
    }
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Ok(Atom {
            name: name.to_owned(),
            constraint: None,
        });
    }
    let inner = rest
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .ok_or(RelationProblem::Trailing)?;
    if inner.contains(['(', ')']) {
        return Err(RelationProblem::Trailing);
    }
    let inner = inner.trim();
    let (op, version) = [
        ("<<", Op::Less),
        ("<=", Op::LessEqual),
        (">=", Op::GreaterEqual),
        (">>", Op::Greater),
        ("=", Op::Equal),
        ("<", Op::LessEqual),
        (">", Op::GreaterEqual),
    ]
    .into_iter()
    .find_map(|(spelling, op)| {
        inner
            .strip_prefix(spelling)
            .map(|version| (op, version.trim()))
    })
    .ok_or(RelationProblem::BadOperator)?;
    if field == DebField::Provides && op != Op::Equal {
        return Err(RelationProblem::ProvidesOperator);
    }
    DebVersion::parse(version).map_err(RelationProblem::Version)?;
    Ok(Atom {
        name: name.to_owned(),
        constraint: Some((op, version.to_owned())),
    })
}

/// A dpkg package name: lowercase alphanumerics and `+-.`, starting with an
/// alphanumeric.
pub fn is_deb_name(name: &str) -> bool {
    name.starts_with(|character: char| character.is_ascii_lowercase() || character.is_ascii_digit())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+-.".contains(&byte)
        })
}

/// The kind of an RPM dependency for the family model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpmEntry {
    /// A package name or a named capability.
    Named(Atom),
    /// A file path (`/usr/bin/foo`), resolved from file lists by the
    /// native manager.
    File(String),
    /// An `rpmlib(…)` feature of librpm itself.
    Rpmlib,
    Rich(String),
}

/// Reduces one RPM header entry.
pub fn rpm_entry(field: &'static str, entry: &RpmDependency) -> Result<RpmEntry, RelationError> {
    let error = |problem| RelationError {
        field,
        entry: entry.to_string(),
        problem,
    };
    let name = entry.name();
    if entry.is_rpmlib() || name.starts_with("rpmlib(") {
        return Ok(RpmEntry::Rpmlib);
    }
    if name.starts_with('(') {
        return Ok(RpmEntry::Rich(name.to_owned()));
    }
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        return Err(error(RelationProblem::BadName));
    }
    if name.starts_with('/') {
        return Ok(RpmEntry::File(name.to_owned()));
    }
    let constraint = match (entry.operator(), entry.version()) {
        (_, "") => None,
        (None, _) => return Err(error(RelationProblem::BadOperator)),
        (Some(spelling), version) => {
            let op = match spelling {
                "<" => Op::Less,
                "<=" => Op::LessEqual,
                "=" => Op::Equal,
                ">=" => Op::GreaterEqual,
                _ => Op::Greater,
            };
            RpmEvr::parse(version).map_err(|problem| error(RelationProblem::Version(problem)))?;
            Some((op, version.to_owned()))
        }
    };
    Ok(RpmEntry::Named(Atom {
        name: name.to_owned(),
        constraint,
    }))
}

#[cfg(test)]
#[path = "relation_tests.rs"]
mod tests;
