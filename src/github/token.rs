// SPDX-License-Identifier: MIT OR Apache-2.0

//! An optional GitHub token and the credential identity derived from it.
//!
//! The caller decides where the token comes from (a file or an environment
//! variable). The value never appears in `Debug`, errors, request paths, or
//! cache keys; the cache key uses a one-way fingerprint.

use std::fmt;
use std::io::Read as _;
use std::path::Path;

use crate::cas::Sha256Digest;

/// Longest token accepted; current GitHub tokens are well below this.
pub const MAX_TOKEN_BYTES: usize = 1024;

/// Longest token file read; anything larger is not a token file.
const MAX_TOKEN_FILE_BYTES: u64 = 4096;

/// Why a token was refused. Never contains any part of the value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    Empty,
    TooLong,
    InvalidCharacter,
    NotUnicode,
    Unreadable(std::io::ErrorKind),
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("token is empty"),
            Self::TooLong => write!(formatter, "token exceeds {MAX_TOKEN_BYTES} bytes"),
            Self::InvalidCharacter => {
                formatter.write_str("token contains whitespace or a non-ASCII character")
            }
            Self::NotUnicode => formatter.write_str("token is not valid UTF-8"),
            Self::Unreadable(kind) => write!(formatter, "token source is unreadable: {kind}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// A GitHub token. `Debug` is redacted, and there is no `Display`.
#[derive(Clone, Eq, PartialEq)]
pub struct Token(String);

impl Token {
    pub fn new(value: String) -> Result<Self, TokenError> {
        if value.is_empty() {
            return Err(TokenError::Empty);
        }
        if value.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::TooLong);
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(TokenError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Reads a token file. One trailing line ending is allowed; any other
    /// whitespace is refused rather than silently trimmed.
    pub fn from_file(path: &Path) -> Result<Self, TokenError> {
        let file =
            std::fs::File::open(path).map_err(|error| TokenError::Unreadable(error.kind()))?;
        let mut bytes = Vec::new();
        file.take(MAX_TOKEN_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| TokenError::Unreadable(error.kind()))?;
        if bytes.len() as u64 > MAX_TOKEN_FILE_BYTES {
            return Err(TokenError::TooLong);
        }
        let mut text = String::from_utf8(bytes).map_err(|_| TokenError::NotUnicode)?;
        if text.ends_with('\n') {
            text.pop();
            if text.ends_with('\r') {
                text.pop();
            }
        }
        Self::new(text)
    }

    /// Reads a token from the named environment variable; `Ok(None)` when it
    /// is not set.
    pub fn from_env(name: &str) -> Result<Option<Self>, TokenError> {
        match std::env::var(name) {
            Ok(value) => Self::new(value).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(TokenError::NotUnicode),
        }
    }

    /// The secret itself, for the `Authorization` header only.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn credential_id(&self) -> CredentialId {
        let mut input = b"pakomichi-github-credential-v1\0".to_vec();
        input.extend_from_slice(self.0.as_bytes());
        CredentialId::Token(Sha256Digest::of(&input))
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Token(<redacted>)")
    }
}

/// Which credential a conditional-request entry belongs to (R-004
/// conclusion 14: an ETag is valid only for the same URL and credentials).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CredentialId {
    Anonymous,
    /// Domain-separated SHA-256 of the token; never the token itself.
    Token(Sha256Digest),
}

impl CredentialId {
    pub fn of(token: Option<&Token>) -> Self {
        token.map_or(Self::Anonymous, Token::credential_id)
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => formatter.write_str("Anonymous"),
            Self::Token(_) => formatter.write_str("Token(<fingerprint>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "sample-credential-value-for-tests";

    #[test]
    fn debug_never_shows_the_value() -> Result<(), TokenError> {
        let token = Token::new(SAMPLE.to_owned())?;
        assert_eq!(format!("{token:?}"), "Token(<redacted>)");
        let credential = format!("{:?}", token.credential_id());
        assert!(!credential.contains(SAMPLE));
        Ok(())
    }

    #[test]
    fn malformed_tokens_are_refused_without_echo() {
        assert_eq!(Token::new(String::new()), Err(TokenError::Empty));
        assert_eq!(
            Token::new("a b".to_owned()),
            Err(TokenError::InvalidCharacter)
        );
        assert_eq!(
            Token::new("a\n".to_owned()),
            Err(TokenError::InvalidCharacter)
        );
        assert_eq!(
            Token::new("x".repeat(MAX_TOKEN_BYTES + 1)),
            Err(TokenError::TooLong)
        );
    }

    #[test]
    fn credentials_differ_per_token_and_from_anonymous() -> Result<(), TokenError> {
        let first = Token::new(SAMPLE.to_owned())?;
        let second = Token::new(format!("{SAMPLE}-2"))?;
        assert_ne!(first.credential_id(), second.credential_id());
        assert_ne!(CredentialId::of(Some(&first)), CredentialId::Anonymous);
        assert_eq!(CredentialId::of(None), CredentialId::Anonymous);
        Ok(())
    }
}
