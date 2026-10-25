// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::publish::test_keys::{TestKey, TestResult};

const RELEASE: &[u8] = b"Origin: Pakomichi\nLabel: pakomichi-netwatch-strict\n\
Suite: pakomichi-netwatch-strict\nValid-Until: Fri, 30 Oct 2026 10:00:00 UTC\n\
SHA256:\n 8fcda58d824b4fea8f98e036083f398f497941af4b8c15de5dac02dd900576fd 14 main/binary-amd64/Packages\n";

fn pair(key: &TestKey) -> TestResult<(GpgSigner, GpgvVerifier)> {
    Ok((
        GpgSigner::new(&key.homedir(), key.fingerprint.clone())?,
        GpgvVerifier::new(&key.keyring(), key.fingerprint.clone())?,
    ))
}

#[test]
fn the_signed_text_is_exactly_the_release_that_was_given() -> TestResult {
    let key = TestKey::new("signer")?;
    let (signer, verifier) = pair(&key)?;
    let message = signer.clearsign(RELEASE)?;
    assert!(message.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n"));
    assert_eq!(verifier.verify_clearsigned(&message)?, RELEASE);
    Ok(())
}

#[test]
fn n012_a_changed_byte_in_the_signed_text_is_refused() -> TestResult {
    let key = TestKey::new("signer")?;
    let (signer, verifier) = pair(&key)?;
    let message = signer.clearsign(RELEASE)?;
    // Push the validity forward by one day without signing again.
    let forged = String::from_utf8(message)?.replace("30 Oct 2026", "31 Oct 2026");
    assert!(matches!(
        verifier.verify_clearsigned(forged.as_bytes()),
        Err(SignError::BadSignature(_))
    ));
    Ok(())
}

#[test]
fn a_signature_by_another_key_is_refused_even_if_it_is_valid() -> TestResult {
    // R-004 G9: the metadata key was lost and something signed with
    // another key; the keyring APT trusts holds only the original key.
    let original = TestKey::new("original")?;
    let other = TestKey::new("other")?;
    let message =
        GpgSigner::new(&other.homedir(), other.fingerprint.clone())?.clearsign(RELEASE)?;
    let strict = GpgvVerifier::new(&original.keyring(), original.fingerprint.clone())?;
    assert!(matches!(
        strict.verify_clearsigned(&message),
        Err(SignError::BadSignature(_))
    ));
    // The other key in the keyring, but not the expected fingerprint.
    let confused = GpgvVerifier::new(&other.keyring(), original.fingerprint.clone())?;
    assert!(matches!(
        confused.verify_clearsigned(&message),
        Err(SignError::UnexpectedSignature(_))
    ));
    Ok(())
}

#[test]
fn a_second_signature_next_to_the_expected_one_is_refused() -> TestResult {
    // Exactly one signature, by the expected key: a message that also
    // carries another key's signature is not the message the signer made,
    // whichever of the two gpgv reports first.
    let original = TestKey::new("original")?;
    let other = TestKey::new("other")?;
    let both = original.also_holding(&other)?;
    let message = original.sign_with(
        RELEASE,
        &["--local-user", other.fingerprint.as_str(), "--clearsign"],
    )?;
    let verifier = GpgvVerifier::new(&both, original.fingerprint.clone())?;
    let result = verifier.verify_clearsigned(&message);
    assert!(
        matches!(&result, Err(SignError::UnexpectedSignature(text)) if text == "2 valid signatures"),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn a_sha1_signature_is_refused() -> TestResult {
    // APT on Debian 13 verifies with sqv, which refuses SHA-1; gpgv still
    // accepts it, so the check has to.
    let key = TestKey::new("signer")?;
    let message = key.sign_with(RELEASE, &["--digest-algo", "SHA1", "--clearsign"])?;
    let verifier = GpgvVerifier::new(&key.keyring(), key.fingerprint.clone())?;
    assert!(matches!(
        verifier.verify_clearsigned(&message),
        Err(SignError::UnexpectedSignature(_))
    ));
    Ok(())
}

#[test]
fn text_outside_the_signed_message_is_refused() -> TestResult {
    let key = TestKey::new("signer")?;
    let (signer, verifier) = pair(&key)?;
    let message = signer.clearsign(RELEASE)?;
    let mut trailing = message.clone();
    trailing.extend_from_slice(b"Valid-Until: Fri, 30 Oct 2099 10:00:00 UTC\n");
    let mut leading = b"Valid-Until: Fri, 30 Oct 2099 10:00:00 UTC\n".to_vec();
    leading.extend_from_slice(&message);
    let mut twice = message.clone();
    twice.extend_from_slice(&message);
    for forged in [trailing, leading, twice] {
        assert!(matches!(
            verifier.verify_clearsigned(&forged),
            Err(SignError::NotClearSigned)
        ));
    }
    Ok(())
}

#[test]
fn a_signer_without_its_key_fails_and_signs_nothing() -> TestResult {
    let key = TestKey::new("signer")?;
    let other = TestKey::new("other")?;
    // The signer's home holds another key: the metadata key is gone.
    let lost = GpgSigner::new(&other.homedir(), key.fingerprint.clone())?;
    assert!(matches!(
        lost.clearsign(RELEASE),
        Err(SignError::SigningFailed(_))
    ));
    Ok(())
}

#[test]
fn the_state_owner_gets_a_signature_it_can_verify_over_the_sign_channel() -> TestResult {
    use crate::ipc::oneshot::{FETCH_LIMITS, serve_channel};
    use crate::ipc::server::PeerRule;
    use crate::state::test_support::TempDir;
    let key = TestKey::new("signer")?;
    let (signer, verifier) = pair(&key)?;
    let dir = TempDir::new()?;
    let path = dir.join("sign.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    serve_channel(
        listener,
        PeerRule::AnyUser,
        FETCH_LIMITS,
        move |request, _uid| answer_sign(&signer, request),
    )?;
    let message = SocketSigner::new(&path).clearsign(RELEASE)?;
    assert_eq!(verifier.verify_clearsigned(&message)?, RELEASE);
    // A signer without its key answers a refusal, never a signature.
    let other = TestKey::new("other")?;
    let lost = GpgSigner::new(&other.homedir(), key.fingerprint.clone())?;
    let path = dir.join("lost.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    serve_channel(
        listener,
        PeerRule::AnyUser,
        FETCH_LIMITS,
        move |request, _uid| answer_sign(&lost, request),
    )?;
    assert!(matches!(
        SocketSigner::new(&path).clearsign(RELEASE),
        Err(SignError::SigningFailed(_))
    ));
    Ok(())
}
