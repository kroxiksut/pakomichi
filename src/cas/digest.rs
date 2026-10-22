// SPDX-License-Identifier: MIT OR Apache-2.0

//! SHA-256 object identity.

use std::fmt;
use std::io::{self, Read};

use sha2::{Digest as _, Sha256};

use crate::error::{ObjectKind, ObjectReference, SafeIdentifier, SafeValueError};

/// Buffer size for streaming reads; large enough to amortise syscalls
/// without holding a package in memory.
pub(crate) const COPY_BUFFER_BYTES: usize = 128 * 1024;

/// A SHA-256 digest. Its canonical text form is 64 lowercase hex digits,
/// which is also the object's file name in the store.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

/// The text is not a canonical lowercase SHA-256 hex digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDigest;

impl fmt::Display for InvalidDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected 64 lowercase hexadecimal digits")
    }
}

impl std::error::Error for InvalidDigest {}

impl Sha256Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses the canonical form only: uppercase digits are refused so that
    /// one object can never have two file names.
    pub fn from_hex(text: &str) -> Result<Self, InvalidDigest> {
        let text = text.as_bytes();
        if text.len() != 64 {
            return Err(InvalidDigest);
        }
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
            *byte = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(64);
        for byte in self.0 {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        text
    }

    /// Digest of an in-memory value.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Reference for a reason event about this cache object. The hex form
    /// always satisfies the identifier rules; the `Result` only keeps the
    /// conversion panic-free.
    pub fn cache_reference(&self) -> Result<ObjectReference, SafeValueError> {
        SafeIdentifier::new(self.to_hex()).map(|id| ObjectReference::new(ObjectKind::Cache, id))
    }
}

fn hex_value(digit: u8) -> Result<u8, InvalidDigest> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(InvalidDigest),
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sha256Digest({})", self.to_hex())
    }
}

impl std::str::FromStr for Sha256Digest {
    type Err = InvalidDigest;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_hex(text)
    }
}

/// The identity a caller has accepted for an object: the pinned digest and
/// the exact size, both from verified evidence rather than from the bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExpectedObject {
    pub sha256: Sha256Digest,
    pub size: u64,
}

impl ExpectedObject {
    pub const fn new(sha256: Sha256Digest, size: u64) -> Self {
        Self { sha256, size }
    }
}

/// Incremental SHA-256 with a byte counter.
#[derive(Clone, Default)]
pub(crate) struct Hasher {
    state: Sha256,
    length: u64,
}

impl Hasher {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
        // usize always fits in u64 on supported targets.
        self.length = self.length.saturating_add(bytes.len() as u64);
    }

    pub(crate) fn length(&self) -> u64 {
        self.length
    }

    pub(crate) fn finish(self) -> (Sha256Digest, u64) {
        (Sha256Digest(self.state.finalize().into()), self.length)
    }
}

/// Hashes a reader to its end.
pub(crate) fn hash_reader<R: Read>(mut reader: R) -> io::Result<(Sha256Digest, u64)> {
    let mut hasher = Hasher::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(hasher.finish()),
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn known_vectors() -> Result<(), InvalidDigest> {
        assert_eq!(Sha256Digest::of(b"").to_hex(), EMPTY);
        assert_eq!(Sha256Digest::of(b"abc"), Sha256Digest::from_hex(ABC)?);
        Ok(())
    }

    #[test]
    fn hex_round_trip() -> Result<(), InvalidDigest> {
        let digest = Sha256Digest::from_hex(ABC)?;
        assert_eq!(digest.to_hex(), ABC);
        assert_eq!(digest.to_string(), ABC);
        assert_eq!(ABC.parse::<Sha256Digest>()?, digest);
        Ok(())
    }

    #[test]
    fn non_canonical_text_is_refused() {
        let upper = ABC.to_ascii_uppercase();
        for text in [
            "",
            &ABC[..63],
            &format!("{ABC}0"),
            upper.as_str(),
            &format!("g{}", &ABC[1..]),
            &format!(" {}", &ABC[1..]),
            "../../../../../../../../../../../../../../../../../../../etc/passw",
        ] {
            assert_eq!(Sha256Digest::from_hex(text), Err(InvalidDigest), "{text:?}");
        }
    }

    #[test]
    fn streaming_hash_matches_one_shot() -> io::Result<()> {
        let data: Vec<u8> = (0..(COPY_BUFFER_BYTES * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect();
        let (digest, length) = hash_reader(data.as_slice())?;
        assert_eq!(digest, Sha256Digest::of(&data));
        assert_eq!(length, data.len() as u64);
        Ok(())
    }

    #[test]
    fn cache_reference_uses_the_hex_digest() -> Result<(), Box<dyn std::error::Error>> {
        let reference = Sha256Digest::from_hex(ABC)?.cache_reference()?;
        assert_eq!(reference.kind(), ObjectKind::Cache);
        assert_eq!(reference.id().as_str(), ABC);
        Ok(())
    }
}
