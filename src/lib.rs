#![doc = include_str!("../README.md")]

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
    if !windows_impl::is_cert_trusted_locally(fingerprints)? {
        tracing::warn!(
            "None of the provided cert fingerprints were trusted locally; attempting to prime the root store."
        );
        let res = windows_impl::try_prime_trust(touch_domains);
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

/// Contains the Windows-specific implementation details.
#[cfg(any(windows, feature = "docs-only"))]
mod windows_impl {
    use super::{PrimerError, Result};
    use native_tls::{HandshakeError, Protocol, TlsConnector};

    #[cfg(windows)]
    use schannel::{cert_context::HashAlgorithm, cert_store::CertStore};
    use std::{
        io::{Read, Write},
        net::{TcpStream, ToSocketAddrs},
        time::Duration,
    };

    /// Attempts to establish a TLS connection to trigger root installation.
    pub(super) fn try_prime_trust(touch_domains: &[&str]) -> Result<()> {
        let connector = TlsConnector::builder()
            .min_protocol_version(Some(Protocol::Tlsv12))
            .build()?;

        let mut last_err: Option<PrimerError> = None;

        if touch_domains.is_empty() {
            return Err(PrimerError::NoPrimingEndpoints);
        }

        for &domain in touch_domains {
            let addrs = match (domain, 443).to_socket_addrs() {
                Ok(addrs) => addrs.collect::<Vec<_>>(),
                Err(e) => {
                    last_err = Some(PrimerError::DnsLookup {
                        domain: domain.to_string(),
                        source: e,
                    });
                    continue;
                }
            };

            if addrs.is_empty() {
                last_err = Some(PrimerError::NoAddressesFound(domain.to_string()));
                continue;
            }

            for addr in addrs {
                match try_connect(domain, addr, &connector) {
                    Ok(()) => {
                        tracing::info!("Successfully primed trust via {domain} ({addr})");
                        return Ok(()); // First success wins.
                    }
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                }
            }
        }

        Err(PrimerError::AllPrimingEndpointsFailed(Box::new(
            last_err.unwrap_or(PrimerError::NoPrimingEndpoints),
        )))
    }

    /// Performs a single connection and TLS handshake attempt.
    fn try_connect(
        domain: &str,
        addr: std::net::SocketAddr,
        connector: &TlsConnector,
    ) -> Result<()> {
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
            .map_err(|e| PrimerError::TcpConnect { addr, source: e })?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))?;

        let mut tls = match connector.connect(domain, tcp) {
            Ok(stream) => stream,
            Err(e) => {
                let err = match e {
                    // This is the expected error path for handshake failures.
                    HandshakeError::Failure(tls_error) => PrimerError::TlsHandshake {
                        domain: domain.to_string(),
                        addr,
                        source: tls_error,
                    },
                    // This should not happen with a blocking stream, but we handle it defensively.
                    HandshakeError::WouldBlock(_) => PrimerError::TlsIo(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unexpected WouldBlock during TLS handshake with a blocking stream",
                    )),
                };
                return Err(err);
            }
        };

        // Nudge the channel to ensure the handshake completes. This is harmless.
        write!(
            tls,
            "HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
        )?;
        let _ = tls.read(&mut [0u8; 1]);

        Ok(())
    }

    /// Checks local machine and current user certificate stores for the given fingerprints.
    #[cfg(windows)]
    pub(super) fn is_cert_trusted_locally(fingerprints: &[&str]) -> Result<bool> {
        let decoded_fps: Vec<Vec<u8>> = fingerprints.iter().map(|s| decode_hex(s)).collect();
        let fps_slices: Vec<&[u8]> = decoded_fps.iter().map(Vec::as_slice).collect();

        // Helper to check if any certificate in a store matches one of our fingerprints.
        let has_fingerprint = |store: &CertStore| -> Result<bool> {
            for cert in store.certs() {
                let fp = cert
                    .fingerprint(HashAlgorithm::sha1())
                    .map_err(PrimerError::CertStore)?;
                if fps_slices.iter().any(|f| *f == fp.as_slice()) {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        // If a cert is in a "Disallowed" store, it is explicitly distrusted.
        // We treat this as "not trusted" and should not attempt to prime it.
        // We use `.ok()` to ignore errors if a store cannot be opened (e.g., permissions),
        // which is a safe default (assume not present if un-checkable).
        if let Some(store) = CertStore::open_local_machine("Disallowed").ok() {
            if has_fingerprint(&store)? {
                return Ok(false);
            }
        }
        if let Some(store) = CertStore::open_current_user("Disallowed").ok() {
            if has_fingerprint(&store)? {
                return Ok(false);
            }
        }

        // Now check the trusted "ROOT" stores.
        if let Some(store) = CertStore::open_local_machine("ROOT").ok() {
            if has_fingerprint(&store)? {
                return Ok(true);
            }
        }
        if let Some(store) = CertStore::open_current_user("ROOT").ok() {
            if has_fingerprint(&store)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Decodes a hexadecimal string into a byte vector, ignoring non-hex characters.
    fn decode_hex(s: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(s.len() / 2);
        let mut chars = s.chars().filter_map(|c| c.to_digit(16));
        while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
            bytes.push((h as u8) << 4 | (l as u8));
        }
        bytes
    }
}
