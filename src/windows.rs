use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use native_tls::{HandshakeError, Protocol, TlsConnector};

#[cfg(windows)]
use schannel::{cert_context::HashAlgorithm, cert_store::CertStore};

use super::{PrimerError, Result};

/// Attempts to establish a TLS connection to trigger root installation.
pub(super) fn try_prime_trust(touch_domains: &[&str]) -> Result<()> {
    let connector = TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build()?;

    let mut last_err: Option<PrimerError> = None;

    if touch_domains.is_empty() {
        tracing::warn!("no priming endpoints provided; cannot trigger Windows root install");
        return Err(PrimerError::NoPrimingEndpoints);
    }

    for &domain in touch_domains {
        let mut addrs = match (domain, 443).to_socket_addrs() {
            Ok(addrs) => addrs.collect::<Vec<_>>(),
            Err(e) => {
                last_err = Some(PrimerError::DnsLookup {
                    domain: domain.to_string(),
                    source: e,
                });
                continue;
            }
        };

        // Prefer IPv4 first; avoids long timeouts on some dual-stack hosts.
        addrs.sort_by_key(|a| a.is_ipv6());

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
fn try_connect(domain: &str, addr: std::net::SocketAddr, connector: &TlsConnector) -> Result<()> {
    const CONNECT_TIMEOUT_SECS: u64 = 10;
    const IO_TIMEOUT_SECS: u64 = 10;

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .map_err(|e| PrimerError::TcpConnect { addr, source: e })?;
    tcp.set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))?;

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

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn parses_plain_hex() {
        let v = decode_hex("CABD2A79A1076A31F21D253635CB039D4329A5E8");
        assert_eq!(v.len(), 20);
    }

    #[test]
    fn parses_colon_separated() {
        let v = decode_hex("CA:BD:2A:79:A1:07:6A:31:F2:1D:25:36:35:CB:03:9D:43:29:A5:E8");
        assert_eq!(v.len(), 20);
    }

    #[test]
    fn case_insensitive() {
        let a = decode_hex("abcd".repeat(10).as_str());
        let b = decode_hex("ABCD".repeat(10).as_str());
        assert_eq!(a, b);
    }

    #[test]
    fn parses_with_spaces_and_dashes() {
        let v = decode_hex("CA BD-2A 79 A1 07 6A 31 F2 1D 25 36 35 CB 03 9D 43 29 A5 E8");
        assert_eq!(v.len(), 20);
    }

    #[test]
    fn odd_nibble_is_ignored() {
        // 3 nibbles -> 1 byte (0x0A), last nibble ignored.
        let v = decode_hex("A:B:C");
        assert_eq!(v, vec![0xAB]);
    }
}
