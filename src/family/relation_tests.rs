// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

fn atom(name: &str, constraint: Option<(Op, &str)>) -> Atom {
    Atom {
        name: name.to_owned(),
        constraint: constraint.map(|(op, version)| (op, version.to_owned())),
    }
}

fn problem(field: DebField, value: &str) -> RelationProblem {
    match parse_deb_field(field, Some(value)) {
        Err(error) => error.problem,
        Ok(clauses) => panic!("{value:?} parsed as {clauses:?}"),
    }
}

#[test]
fn deb_depends_with_alternatives_and_qualifiers() -> Result<(), RelationError> {
    let clauses = parse_deb_field(
        DebField::Depends,
        Some(
            "app-common (= 1:0.6-1), libc6 (>= 2.36), python3:any, mail-transport-agent | exim4 (>> 4)",
        ),
    )?;
    assert_eq!(
        clauses,
        vec![
            Clause::Any(vec![atom("app-common", Some((Op::Equal, "1:0.6-1")))]),
            Clause::Any(vec![atom("libc6", Some((Op::GreaterEqual, "2.36")))]),
            Clause::Any(vec![atom("python3", None)]),
            Clause::Any(vec![
                atom("mail-transport-agent", None),
                atom("exim4", Some((Op::Greater, "4"))),
            ]),
        ]
    );
    Ok(())
}

#[test]
fn deb_operators_and_spacing() -> Result<(), RelationError> {
    for (text, op) in [
        ("a (<< 1)", Op::Less),
        ("a(<=1)", Op::LessEqual),
        ("a ( = 1 )", Op::Equal),
        ("a (>=1)", Op::GreaterEqual),
        ("a (>> 1)", Op::Greater),
        // Obsolete dpkg spellings: `<` is `<=` and `>` is `>=`.
        ("a (< 1)", Op::LessEqual),
        ("a (> 1)", Op::GreaterEqual),
    ] {
        assert_eq!(
            parse_deb_field(DebField::Depends, Some(text))?,
            vec![Clause::Any(vec![atom("a", Some((op, "1")))])],
            "{text}"
        );
    }
    assert!(parse_deb_field(DebField::Depends, None)?.is_empty());
    assert!(parse_deb_field(DebField::Depends, Some("  "))?.is_empty());
    Ok(())
}

#[test]
fn deb_malformed_entries_are_refused() {
    assert_eq!(
        problem(DebField::Depends, "a, , b"),
        RelationProblem::EmptyEntry
    );
    assert_eq!(
        problem(DebField::Depends, "a,"),
        RelationProblem::EmptyEntry
    );
    assert_eq!(problem(DebField::Depends, "App"), RelationProblem::BadName);
    assert_eq!(problem(DebField::Depends, "-a"), RelationProblem::BadName);
    assert_eq!(
        problem(DebField::Depends, "a:"),
        RelationProblem::BadArchQualifier
    );
    assert_eq!(
        problem(DebField::Depends, "a:AMD64"),
        RelationProblem::BadArchQualifier
    );
    assert_eq!(
        problem(DebField::Depends, "a (~ 1)"),
        RelationProblem::BadOperator
    );
    assert_eq!(
        problem(DebField::Depends, "a [amd64]"),
        RelationProblem::Restriction
    );
    assert_eq!(
        problem(DebField::Depends, "a <!nocheck>"),
        RelationProblem::Restriction
    );
    assert_eq!(
        problem(DebField::Depends, "a (>= 1) <stage1>"),
        RelationProblem::Restriction
    );
    assert_eq!(
        problem(DebField::Depends, "a (>= 1"),
        RelationProblem::Trailing
    );
    assert_eq!(
        problem(DebField::Depends, "a (>= 1) b"),
        RelationProblem::Trailing
    );
    assert_eq!(
        problem(DebField::Depends, "a ((>= 1))"),
        RelationProblem::Trailing
    );
    assert_eq!(problem(DebField::Depends, "a b"), RelationProblem::Trailing);
    assert!(matches!(
        problem(DebField::Depends, "a (>= 1.0-)"),
        RelationProblem::Version(_)
    ));
    assert!(matches!(
        problem(DebField::Depends, "a (>=)"),
        RelationProblem::Version(_)
    ));
}

#[test]
fn deb_fields_follow_their_own_rules() -> Result<(), RelationError> {
    // `|` is only for Depends and Pre-Depends.
    assert!(parse_deb_field(DebField::PreDepends, Some("a | b")).is_ok());
    for field in [
        DebField::Provides,
        DebField::Conflicts,
        DebField::Breaks,
        DebField::Replaces,
    ] {
        assert_eq!(
            problem(field, "a | b"),
            RelationProblem::Alternatives,
            "{field:?}"
        );
    }
    // Provides takes only `=`.
    assert_eq!(
        parse_deb_field(DebField::Provides, Some("app-api (= 2)"))?,
        vec![Clause::Any(vec![atom("app-api", Some((Op::Equal, "2")))])]
    );
    assert_eq!(
        problem(DebField::Provides, "app-api (>= 2)"),
        RelationProblem::ProvidesOperator
    );
    // Breaks and Replaces take any operator.
    assert!(parse_deb_field(DebField::Breaks, Some("app (<< 0.6)")).is_ok());
    let error = parse_deb_field(DebField::Replaces, Some("a | b"));
    assert_eq!(error.map_err(|error| error.field), Err("Replaces"));
    Ok(())
}

#[test]
fn deb_names_follow_dpkg() {
    for name in ["a", "0ad", "libfoo1.2", "g++", "app-cli", "x.y+z-1"] {
        assert!(is_deb_name(name), "{name}");
    }
    for name in ["", "A", "app_cli", ".a", "+a", "app cli", "приложение"] {
        assert!(!is_deb_name(name), "{name}");
    }
}
