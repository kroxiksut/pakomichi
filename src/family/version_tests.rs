// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

/// The vectors that `scripts/check-native-versions.py` checks against
/// `dpkg --compare-versions` and python3-rpm.
const VECTORS: &str = include_str!("../../tests/data/native-versions.tsv");

fn vectors() -> impl Iterator<Item = (usize, [&'static str; 4])> {
    VECTORS
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(index, line)| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "line {}", index + 1);
            (index + 1, [fields[0], fields[1], fields[2], fields[3]])
        })
}

fn sign(ordering: Ordering) -> &'static str {
    match ordering {
        Ordering::Less => "<",
        Ordering::Equal => "=",
        Ordering::Greater => ">",
    }
}

fn op(spelling: &str) -> Op {
    match spelling {
        "<" => Op::Less,
        "<=" => Op::LessEqual,
        "=" => Op::Equal,
        ">=" => Op::GreaterEqual,
        ">" => Op::Greater,
        other => panic!("unknown operator {other}"),
    }
}

fn range(text: &str) -> (Op, RpmEvr) {
    let (spelling, evr) = text
        .split_once(' ')
        .unwrap_or_else(|| panic!("bad range {text}"));
    (
        op(spelling),
        RpmEvr::parse(evr).unwrap_or_else(|error| panic!("{text}: {error}")),
    )
}

#[test]
fn every_vector_matches_the_native_tools() {
    let mut checked = 0;
    for (line, [kind, left, right, expected]) in vectors() {
        let actual = match kind {
            "deb" => {
                let parse = |text| {
                    DebVersion::parse(text)
                        .unwrap_or_else(|error| panic!("line {line}: {text}: {error}"))
                };
                sign(parse(left).cmp(&parse(right))).to_owned()
            }
            "deb-invalid" | "deb-strict" => if DebVersion::parse(left).is_err() {
                "error"
            } else {
                "accepted"
            }
            .to_owned(),
            "rpm" => sign(rpmvercmp(left, right)).to_owned(),
            "rpm-evr" => {
                let parse = |text| {
                    RpmEvr::parse(text)
                        .unwrap_or_else(|error| panic!("line {line}: {text}: {error}"))
                };
                sign(parse(left).compare(&parse(right))).to_owned()
            }
            "rpm-overlap" => {
                let ((provide_op, provide), (require_op, require)) = (range(left), range(right));
                let overlap = rpm_ranges_overlap(&provide, provide_op, &require, require_op);
                // The relation is symmetric.
                assert_eq!(
                    overlap,
                    rpm_ranges_overlap(&require, require_op, &provide, provide_op),
                    "line {line}"
                );
                if overlap { "1" } else { "0" }.to_owned()
            }
            other => panic!("line {line}: unknown kind {other}"),
        };
        assert_eq!(actual, expected, "line {line}: {kind} {left} {right}");
        checked += 1;
    }
    assert!(checked >= 90, "only {checked} vectors");
}

#[test]
fn orderings_are_antisymmetric() {
    for (line, [kind, left, right, _]) in vectors() {
        match kind {
            "deb" => {
                let (a, b) = (DebVersion::parse(left), DebVersion::parse(right));
                if let (Ok(a), Ok(b)) = (a, b) {
                    assert_eq!(a.cmp(&b), b.cmp(&a).reverse(), "line {line}");
                }
            }
            "rpm" => assert_eq!(
                rpmvercmp(left, right),
                rpmvercmp(right, left).reverse(),
                "line {line}"
            ),
            _ => {}
        }
    }
}

#[test]
fn dpkg_parts_are_split_like_dpkg() -> Result<(), VersionError> {
    let version = DebVersion::parse("2:1.0-rc1-3+deb12u1")?;
    assert_eq!(version.epoch(), 2);
    assert_eq!(version.upstream(), "1.0-rc1");
    assert_eq!(version.revision(), "3+deb12u1");
    let plain = DebVersion::parse("1.0")?;
    assert_eq!(
        (plain.epoch(), plain.upstream(), plain.revision()),
        (0, "1.0", "")
    );
    assert_eq!(DebVersion::parse(""), Err(VersionError::Empty));
    assert_eq!(
        DebVersion::parse("99999999999:1"),
        Err(VersionError::BadEpoch)
    );
    assert_eq!(
        DebVersion::parse("2147483648:1"),
        Err(VersionError::BadEpoch)
    );
    assert!(DebVersion::parse("2147483647:1").is_ok());
    Ok(())
}

#[test]
fn rpm_parts_are_split_like_rpmver_parse() -> Result<(), VersionError> {
    let evr = RpmEvr::parse("3:1.2.3-4.el9")?;
    assert_eq!(
        (evr.epoch(), evr.version(), evr.release()),
        (Some("3"), "1.2.3", Some("4.el9"))
    );
    let bare = RpmEvr::parse("1.0")?;
    assert_eq!((bare.epoch(), bare.release()), (None, None));
    assert_eq!(RpmEvr::parse(":1.0")?.epoch(), Some("0"));
    assert_eq!(RpmEvr::parse("1.0-"), Err(VersionError::EmptyRevision));
    assert_eq!(
        RpmEvr::parse("1-2-3"),
        Err(VersionError::InvalidCharacter { part: "version" })
    );
    assert_eq!(RpmEvr::parse("1.0 -1"), Err(VersionError::Whitespace));
    Ok(())
}

#[test]
fn deb_operators_accept_the_right_orderings() {
    use Ordering::{Equal, Greater, Less};
    let table = [
        (Op::Less, [true, false, false]),
        (Op::LessEqual, [true, true, false]),
        (Op::Equal, [false, true, false]),
        (Op::GreaterEqual, [false, true, true]),
        (Op::Greater, [false, false, true]),
    ];
    for (op, expected) in table {
        assert_eq!(
            [op.accepts(Less), op.accepts(Equal), op.accepts(Greater)],
            expected,
            "{op:?}"
        );
    }
}
