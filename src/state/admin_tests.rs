// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::state::test_support::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: &str = "2026-10-24T12:00:00Z";
const ID: &str = "0123456789abcdef0123456789abcdef";

fn digests(path: &str, byte: u8) -> Digests {
    [(path.to_owned(), Sha256Digest::of(&[byte]))]
        .into_iter()
        .collect()
}

#[test]
fn an_operation_finishes_once_and_never_back_to_planned() -> TestResult {
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let keyring = "/etc/apt/keyrings/pakomichi.gpg";
    owner.begin_apt_operation(
        ID,
        &Desired::empty(18080),
        &Desired::empty(18080),
        &Digests::new(),
        &digests(keyring, 1),
        AT,
    )?;
    assert!(matches!(
        owner.finish_apt_operation(ID, OperationStatus::Planned, &Digests::new(), AT),
        Err(StateError::OperationNotPlanned)
    ));
    owner.finish_apt_operation(ID, OperationStatus::Verified, &digests(keyring, 2), AT)?;
    // A second finish could overwrite what the first one recorded.
    assert!(matches!(
        owner.finish_apt_operation(ID, OperationStatus::Failed, &Digests::new(), AT),
        Err(StateError::OperationNotPlanned)
    ));
    assert_eq!(owner.apt_state()?.known, digests(keyring, 2));
    Ok(())
}

#[test]
fn a_tampered_row_is_refused_instead_of_trusted() -> TestResult {
    // The applier acts on these digests as root; a row naming a system file
    // must not come back as "ours".
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    owner.begin_apt_operation(
        ID,
        &Desired::empty(18080),
        &Desired::empty(18080),
        &Digests::new(),
        &Digests::new(),
        AT,
    )?;
    let sha = "00".repeat(32);
    owner.connection().execute(
        "UPDATE admin_operation SET previous_hashes_json = ?1",
        [format!(r#"[{{"path":"/etc/passwd","sha256":"{sha}"}}]"#)],
    )?;
    assert!(matches!(
        owner.unfinished_apt_operations(),
        Err(StateError::CorruptRow { .. })
    ));
    Ok(())
}

#[test]
fn a_second_intent_is_refused_while_one_is_open() -> TestResult {
    // Two open operations could each restore a different "previous".
    let dir = TempDir::new()?;
    let mut owner = StateOwner::open(&dir.join("state.db"))?;
    let begin = |owner: &mut StateOwner, id: &str| {
        owner.begin_apt_operation(
            id,
            &Desired::empty(18080),
            &Desired::empty(18080),
            &Digests::new(),
            &Digests::new(),
            AT,
        )
    };
    begin(&mut owner, ID)?;
    assert!(matches!(
        begin(&mut owner, "ffffffffffffffffffffffffffffffff"),
        Err(StateError::OperationUnfinished)
    ));
    assert!(matches!(
        owner.apt_state(),
        Err(StateError::OperationUnfinished)
    ));
    assert_eq!(owner.unfinished_apt_operations()?.len(), 1);
    Ok(())
}
