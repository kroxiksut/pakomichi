// SPDX-License-Identifier: MIT OR Apache-2.0

//! The answer of an inspector instance is read back, not trusted (ADR-035).

use super::*;
use crate::inspect::fixtures::{TarItem, ar, deb_inspection, tar};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CONTROL: &str = "Package: netwatch\nVersion: 0.35.4\nArchitecture: amd64\n\
    Maintainer: Fixture <fixture@example.invalid>\nDepends: libc6 (>= 2.36)\n\
    Description: fixture\n long text\n .\n more\n";

fn with_postinst() -> Result<DebInspection, InspectError> {
    let control_tar = tar(&[
        TarItem::dir("./"),
        TarItem::file("./control", CONTROL.as_bytes()),
        TarItem::file("./postinst", b"#!/bin/sh\nexit 0\n"),
    ]);
    let data_tar = tar(&[]);
    let package = ar(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &control_tar),
        ("data.tar", &data_tar),
    ]);
    let limits = InspectLimits::default();
    let format = super::super::ar::read_layout(
        &mut std::io::Cursor::new(&package),
        package.len() as u64,
        &limits,
    )?;
    inspect_control_tar(format, &control_tar, &limits)
}

#[test]
fn an_inspection_comes_back_unchanged() -> TestResult {
    for inspection in [deb_inspection(CONTROL)?, with_postinst()?] {
        assert_eq!(DebInspection::from_wire(inspection.to_wire())?, inspection);
    }
    Ok(())
}

#[test]
fn an_answer_that_smuggles_a_field_into_the_paragraph_is_refused() -> TestResult {
    // A value with a bare line break would become a field of its own in
    // the Packages index this paragraph is copied into.
    let mut wire = deb_inspection(CONTROL)?.to_wire();
    if let Some((_, value)) = wire
        .fields
        .iter_mut()
        .find(|(name, _)| name == "Description")
    {
        value.push_str("\nFilename: pool/0000/other.deb");
    }
    assert!(DebInspection::from_wire(wire).is_err());
    // A trailing space, a duplicate field, an empty name.
    for change in [
        |fields: &mut Vec<(String, String)>| fields[1].1.push(' '),
        |fields: &mut Vec<(String, String)>| {
            fields.push(("package".to_owned(), "other".to_owned()))
        },
        |fields: &mut Vec<(String, String)>| fields.push((String::new(), "x".to_owned())),
    ] {
        let mut wire = deb_inspection(CONTROL)?.to_wire();
        change(&mut wire.fields);
        assert!(DebInspection::from_wire(wire).is_err());
    }
    Ok(())
}

#[test]
fn an_answer_that_hides_a_maintainer_script_is_refused() -> TestResult {
    let mut wire = with_postinst()?.to_wire();
    assert_eq!(wire.maintainer_scripts, ["postinst"]);
    wire.maintainer_scripts.clear();
    assert!(DebInspection::from_wire(wire).is_err());
    // The reverse: a script listed that the members do not have.
    let mut wire = deb_inspection(CONTROL)?.to_wire();
    wire.maintainer_scripts.push("preinst".to_owned());
    assert!(DebInspection::from_wire(wire).is_err());
    Ok(())
}
