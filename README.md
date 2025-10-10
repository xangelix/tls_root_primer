# TLS Root Primer

A small, single-purpose utility to help prime the Windows root certificate store for Rust applications, particularly those using `rustls`.

## The Problem

On clean installations, Windows (especially Server editions) may not ship with a full set of root Certificate Authorities (CAs). Instead, it uses a mechanism called CAPI2 to automatically download and install trusted root certificates on demand when an application performs a TLS handshake using the native TLS library (`schannel`).

However, many Rust applications use `rustls`, which is a cross-platform TLS implementation that does **not** use `schannel` and therefore **does not trigger** this automatic trust installation. This can lead to TLS connection failures with errors like `invalid certificate: UnknownIssuer` when connecting to services that use newer CAs, such as Let's Encrypt's `ISRG Root X1`.

## The Solution

This crate solves the problem by providing a single function, `prime_cert`, that performs a brief TLS handshake to a known domain using `schannel` (via the `native-tls` crate). This simple act is enough to trigger Windows's auto-update mechanism, which fetches and installs the necessary root certificate into the system's trust store.

Once primed, the root certificate is available system-wide, and subsequent TLS connections made by `rustls` (or any other TLS library) will succeed.

### Is This Safe?

**Yes.** This crate is much safer than the common alternative of bundling a `.pem` file inside your binary.

* **No certificates are bundled.** We do not embed any CA certificates in the code.
* **We don't manually install anything.** The crate leverages a secure, built-in Windows feature. It simply provides the "nudge" needed to make Windows do its job.
* **Trust is managed by the OS.** The decision to trust and install a root certificate is still made entirely by the Windows operating system, respecting any existing group policies or security configurations.

## Usage

Add `tls_root_primer` to your `Cargo.toml`:

```toml
[dependencies]
tls_root_primer = "0.1.0"
```

Then, early in your application's startup, call `prime_cert` with the SHA-1 fingerprints of the root certificates you need and a list of domains that use them.

```rust
fn main() {
    // A connection to the remote service to fetch the cert is only made if
    // NONE of the provided fingerprints are found in Windows's cert store.
    let result = tls_root_primer::prime_cert(
        &[
            // ISRG Root X1 (provided, but you should find this yourself)
            tls_root_primer::UNSAFE_LETS_ENCRYPT_ISRG_ROOT_X1_FINGERPRINT,
            // ISRG Root X2 (provided, but you should find this yourself)
            tls_root_primer::UNSAFE_LETS_ENCRYPT_ISRG_ROOT_X2_FINGERPRINT,
        ],
        // A list of domains that are signed by the target CA.
        // The first one that successfully connects will trigger the priming.
        &["google.com", "letsencrypt.org"],
    );

    if let Err(e) = result {
        eprintln!("Failed to prime TLS root certificates: {e}");
        // Decide how to handle the error
    }

    // ... rest of your application startup ...
}
```

### Important Note on Fingerprints

This crate provides constants for the Let's Encrypt ISRG root CAs for convenience. However, these are marked `UNSAFE_` because hardcoded security values can become outdated or compromised. For production use, you **should** verify these fingerprints against the official sources provided by the Certificate Authority yourself.

## Non-Windows Platforms

On non-Windows platforms, `prime_cert` is a compile-time no-op. It costs nothing at runtime or in binary size and always returns `Ok(())`.

If you encounter similar lazy-loading trust issues on other platforms, please open an issue\! We would be happy to consider adding support.
