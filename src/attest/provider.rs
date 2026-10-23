// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification-only `sigstore-crypto` provider on `ring` (ADR-030 point 2).
//!
//! Without the `aws-lc-rs` feature, `sigstore-crypto` panics on its first
//! operation if no provider is installed, so [`ensure_crypto_provider`] runs
//! at process start and its failure stops the process. `ring` cannot verify
//! from a prehashed digest and has no ML-DSA; both fail closed.

use ring::digest;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use sigstore_crypto::error::{Error, Result};
use sigstore_crypto::{CryptoProvider, HashContext, SigningScheme};
use sigstore_types::HashAlgorithm;

#[derive(Debug)]
struct RingProvider;

static RING_PROVIDER: RingProvider = RingProvider;

struct RingHash(digest::Context);

impl HashContext for RingHash {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }
}

fn algorithm(scheme: SigningScheme) -> Result<&'static dyn VerificationAlgorithm> {
    Ok(match scheme {
        SigningScheme::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
        SigningScheme::EcdsaP256Sha384 => &signature::ECDSA_P256_SHA384_ASN1,
        SigningScheme::EcdsaP384Sha256 => &signature::ECDSA_P384_SHA256_ASN1,
        SigningScheme::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        SigningScheme::Ed25519 => &signature::ED25519,
        SigningScheme::RsaPkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        SigningScheme::RsaPkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        SigningScheme::RsaPkcs1Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        SigningScheme::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
        SigningScheme::RsaPssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
        SigningScheme::RsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
        other => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "{} is not available in the ring provider",
                other.name()
            )));
        }
    })
}

impl CryptoProvider for RingProvider {
    fn hash(&self, algorithm: HashAlgorithm) -> Result<Box<dyn HashContext>> {
        let algorithm = match algorithm {
            HashAlgorithm::Sha2256 => &digest::SHA256,
            HashAlgorithm::Sha2384 => &digest::SHA384,
            HashAlgorithm::Sha2512 => &digest::SHA512,
            other => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "hash {other:?} is not available in the ring provider"
                )));
            }
        };
        Ok(Box::new(RingHash(digest::Context::new(algorithm))))
    }

    fn verify_raw(
        &self,
        scheme: SigningScheme,
        spki_pubkey_bytes: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        // `sigstore-crypto` passes the raw subjectPublicKey bytes (an
        // uncompressed SEC1 point, a raw Ed25519 key or a PKCS#1
        // RSAPublicKey), which is what `ring` expects for each algorithm.
        UnparsedPublicKey::new(algorithm(scheme)?, spki_pubkey_bytes)
            .verify(data, signature)
            .map_err(|_| Error::Verification(format!("{} signature is invalid", scheme.name())))
    }

    fn verify_prehashed(
        &self,
        scheme: SigningScheme,
        _spki_pubkey_bytes: &[u8],
        _digest: &[u8],
        _signature: &[u8],
    ) -> Result<()> {
        Err(Error::UnsupportedAlgorithm(format!(
            "{} from a prehashed digest is not available in the ring provider",
            scheme.name()
        )))
    }
}

/// The process-wide provider could not be installed: another, foreign
/// provider was installed first.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProviderConflict;

impl std::fmt::Display for ProviderConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("another sigstore-crypto provider is already installed")
    }
}

impl std::error::Error for ProviderConflict {}

/// Installs the `ring` provider once for the process. Calling it again is
/// harmless; a provider installed by someone else is an error, because
/// Pakomichi verifies only with its own.
pub fn ensure_crypto_provider() -> std::result::Result<(), ProviderConflict> {
    let ours: &'static dyn CryptoProvider = &RING_PROVIDER;
    if sigstore_crypto::install_default_provider(ours).is_ok() {
        return Ok(());
    }
    // `install_default_provider` hands back the rejected argument, so ask
    // which provider is actually installed.
    match sigstore_crypto::try_default_provider() {
        Some(installed) if std::ptr::addr_eq(installed, ours) => Ok(()),
        _ => Err(ProviderConflict),
    }
}
