#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

/// Contains the Windows-specific implementation details.
#[cfg(any(windows, feature = "docs-only"))]
pub mod windows;

use thiserror::Error;

/// A specialized `Result` type for this crate's operations.
pub type Result<T> = std::result::Result<T, PrimerError>;

/// Represents errors that can occur while priming the certificate store.
#[derive(Error, Debug)]
pub enum PrimerError {
    /// The underlying `native-tls` connector could not be built.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("failed to build TLS connector")]
    TlsConnector(#[from] native_tls::Error),

    /// A DNS lookup for a given domain failed.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("DNS lookup failed for domain '{domain}'")]
    DnsLookup {
        domain: String,
        #[source]
        source: std::io::Error,
    },

    /// No IP addresses were found for a given domain.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("no IP addresses found for domain '{0}'")]
    NoAddressesFound(String),

    /// A TCP connection to a remote address failed.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("TCP connect to {addr} failed")]
    TcpConnect {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// The TLS handshake with the remote server failed.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("TLS handshake to {domain} ({addr}) failed")]
    TlsHandshake {
        domain: String,
        addr: std::net::SocketAddr,
        #[source]
        source: native_tls::Error,
    },

    /// An I/O error occurred during the TLS priming operation.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("I/O error during TLS operation")]
    TlsIo(#[from] std::io::Error),

    /// All provided priming endpoints failed to connect and trigger trust installation.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("all priming endpoints failed")]
    AllPrimingEndpointsFailed(#[source] Box<PrimerError>),

    /// No domains were provided to attempt priming.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("no priming endpoints were provided")]
    NoPrimingEndpoints,

    /// An error occurred while interacting with the Windows Certificate Store.
    #[cfg(any(windows, feature = "docs-only"))]
    #[error("failed to query certificate store")]
    CertStore(#[source] std::io::Error),
}

/// The SHA-1 fingerprint for the Let's Encrypt ISRG Root X1 certificate.
///
/// # Security Warning
///
/// This value is provided for convenience. You **should** verify this fingerprint
/// against the official value published by Let's Encrypt before using it in a
/// production environment. Security identifiers can change or be compromised.
/// Official source: <https://letsencrypt.org/certs/isrgrootx1.pem>
pub const UNSAFE_LETS_ENCRYPT_ISRG_ROOT_X1_FINGERPRINT: &str =
    "CABD2A79A1076A31F21D253635CB039D4329A5E8";

/// The SHA-1 fingerprint for the Let's Encrypt ISRG Root X2 certificate.
///
/// # Security Warning
///
/// This value is provided for convenience. You **should** verify this fingerprint
/// against the official value published by Let's Encrypt before using it in a
/// production environment. Security identifiers can change or be compromised.
/// Official source: <https://letsencrypt.org/certs/isrg-root-x2.pem>
pub const UNSAFE_LETS_ENCRYPT_ISRG_ROOT_X2_FINGERPRINT: &str =
    "BDB1B93CD5978D45C6261455F8DB95C75AD153AF";

/// On non-Windows platforms, this is a no-op that always returns `Ok(())`.
#[cfg(not(any(windows, feature = "docs-only")))]
pub const fn prime_cert(_fingerprints: &[&str], _touch_domains: &[&str]) -> Result<()> {
    Ok(())
}

/// Checks if a root certificate is trusted locally and, if not, attempts to
/// trigger Windows's automatic root certificate installation mechanism.
///
/// This function first checks the Windows certificate store to see if any of the
/// provided certificate `fingerprints` are already present and trusted.
///
/// If not, it will attempt to make a TLS connection using `schannel` (the native
/// Windows TLS library) to one of the `touch_domains`. This action prompts Windows
/// to fetch and install any missing intermediate or root certificates needed to
/// validate the domain's certificate chain. The first successful connection is
/// sufficient to prime the trust store.
///
/// # Parameters
/// - `fingerprints`: A slice of hex-encoded SHA-1 certificate fingerprints to check for.
/// - `touch_domains`: A slice of domain names to connect to. The domains should be
///   served by certificates that chain up to one of the target root CAs.
///
/// # Errors
///
/// Returns an [`Error`] if checking the local trust store fails or if all attempts
/// to connect to the `touch_domains` fail.
///
/// # Example
/// ```no_run
/// use tls_root_primer::{prime_cert, UNSAFE_LETS_ENCRYPT_ISRG_ROOT_X1_FINGERPRINT};
///
/// fn main() -> tls_root_primer::Result<()> {
///     prime_cert(
///         &[UNSAFE_LETS_ENCRYPT_ISRG_ROOT_X1_FINGERPRINT],
///         &["valid-isrgrootx1.letsencrypt.org"],
///     )?;
///     Ok(())
/// }
/// ```
#[cfg(any(windows, feature = "docs-only"))]
pub fn prime_cert(fingerprints: &[&str], touch_domains: &[&str]) -> Result<()> {
    if !windows::is_cert_trusted_locally(fingerprints)? {
        tracing::warn!(
            "None of the provided cert fingerprints were trusted locally; attempting to prime the root store."
        );
        let res = windows::try_prime_trust(touch_domains);
        if let Err(e) = &res {
            tracing::error!("Failed to prime any trust anchors: {e}");
        }
        res
    } else {
        tracing::info!(
            "One or more of the provided cert fingerprints are already trusted locally; no need to prime."
        );
        Ok(())
    }
}
