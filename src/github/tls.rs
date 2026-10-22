// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS for the API origin: rustls with the `ring` provider over Tokio.
//!
//! [`RustlsConnector`] implements the [`SecureConnector`] seam. It opens a
//! TCP connection to exactly the address the transport vetted, sends SNI
//! for the fixed host name, verifies the chain and the name against the
//! operating system CA store, and offers only HTTP/1.1 through ALPN.
//! TLS 1.2 and 1.3 are enabled; nothing older exists in rustls.
//!
//! Certificate verification cannot be switched off. Production code builds
//! the connector only from the system store
//! ([`RustlsConnector::with_native_roots`]); the loopback tests pass a
//! throwaway TEST ONLY root through a constructor that exists only in
//! `cfg(test)` builds.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::http::SecureConnector;
use super::transport::TransportError;

/// The only application protocol offered through ALPN.
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// Why the TLS client configuration could not be built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsSetupError {
    /// The operating system CA store yielded no usable root certificate.
    /// `load_errors` counts files or stores that could not be read;
    /// `unparsable` counts certificates rustls could not use as roots.
    NoRootCertificates {
        load_errors: usize,
        unparsable: usize,
    },
    /// The crypto provider refused the protocol versions.
    Provider,
}

impl fmt::Display for TlsSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRootCertificates {
                load_errors,
                unparsable,
            } => write!(
                formatter,
                "no usable root certificate in the system CA store \
                 ({load_errors} load errors, {unparsable} unusable certificates)"
            ),
            Self::Provider => formatter.write_str("the TLS provider refused the configuration"),
        }
    }
}

impl std::error::Error for TlsSetupError {}

/// TLS connector with mandatory certificate verification.
#[derive(Clone)]
pub struct RustlsConnector {
    tls: TlsConnector,
}

impl fmt::Debug for RustlsConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsConnector")
            .finish_non_exhaustive()
    }
}

impl RustlsConnector {
    /// Trusts the operating system CA store as read by
    /// `rustls-native-certs`: on Linux the bundle and directory found by
    /// `openssl-probe`, on Windows the current user's `ROOT` store. When
    /// `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, only those locations are
    /// read; the service unit controls this environment.
    ///
    /// Loading is expensive (it parses the whole store); build the
    /// connector once per process.
    pub fn with_native_roots() -> Result<Self, TlsSetupError> {
        let loaded = rustls_native_certs::load_native_certs();
        let roots = root_store(loaded.certs, loaded.errors.len())?;
        Self::with_roots(roots)
    }

    /// TEST ONLY: trusts exactly `roots`. Compiled only into unit tests.
    #[cfg(test)]
    pub(crate) fn with_test_only_roots(roots: RootCertStore) -> Result<Self, TlsSetupError> {
        Self::with_roots(roots)
    }

    fn with_roots(roots: RootCertStore) -> Result<Self, TlsSetupError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| TlsSetupError::Provider)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
        // SNI stays on (the default); no key log, no early data.
        config.enable_sni = true;
        config.enable_early_data = false;
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
        })
    }
}

/// Builds the root store; an empty result is an error rather than a client
/// that can never verify anything.
fn root_store(
    certificates: Vec<CertificateDer<'static>>,
    load_errors: usize,
) -> Result<RootCertStore, TlsSetupError> {
    let mut roots = RootCertStore::empty();
    let (added, unparsable) = roots.add_parsable_certificates(certificates);
    if added == 0 {
        return Err(TlsSetupError::NoRootCertificates {
            load_errors,
            unparsable,
        });
    }
    Ok(roots)
}

impl SecureConnector for RustlsConnector {
    type Stream = TlsStream<TcpStream>;

    async fn connect(
        &self,
        host: &'static str,
        address: SocketAddr,
    ) -> Result<Self::Stream, TransportError> {
        let name = ServerName::try_from(host).map_err(|_| TransportError::Tls)?;
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|_| TransportError::Connect)?;
        // Only latency; a failure here does not affect correctness.
        let _ = tcp.set_nodelay(true);
        let stream = self
            .tls
            .connect(name, tcp)
            .await
            .map_err(|error| handshake_error(&error))?;
        // rustls already refuses a protocol we did not offer; an absent
        // ALPN answer means the server did not use ALPN, so HTTP/1.1.
        match stream.get_ref().1.alpn_protocol() {
            None | Some(ALPN_HTTP_1_1) => Ok(stream),
            Some(_) => Err(TransportError::Tls),
        }
    }
}

/// Separates a certificate failure (an untrusted chain, a wrong name, an
/// expired certificate) from other handshake failures.
fn handshake_error(error: &std::io::Error) -> TransportError {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(_)) => TransportError::Certificate,
        _ => TransportError::Tls,
    }
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
