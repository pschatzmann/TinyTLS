# Security

## Status

| Area | Status |
|------|--------|
| TLS 1.3 client handshake (RFC 8446) | Implemented; tested against OpenSSL 3.5 |
| Cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256` |
| Key exchange | X25519 (no HelloRetryRequest) |
| Record layer, alerts, close_notify, KeyUpdate | Implemented |
| Server certificate validation | Implemented (see below) |
| Client certificates, PSK, 0-RTT, session resumption | Not implemented |
| Revocation (CRL, OCSP), name constraints | Not implemented |

## Certificate validation

The server chain is checked against a trust store that you provide:

- **Signatures:** ECDSA on P-256, and RSA (PKCS#1 v1.5 and PSS, SHA-256). The
  CertificateVerify message is checked with the leaf key, so the peer must
  possess its private key.
- **Chain:** each certificate must be issued by the next, which must be a CA.
  The last certificate must be a trust anchor, or be issued by one.
- **Host name:** matched against subjectAltName dNSName entries (one-label
  wildcards are allowed). The common name is not used.
- **Validity:** checked when a time source is configured.

## Verification modes

| Mode | Behaviour |
|------|-----------|
| `VerifyMode::Required` (default) | Fails closed: without a trust store, or without a time source, the handshake is refused. |
| `VerifyMode::Optional` | Continues after a failure and reports it through `verifyResult()`. |
| `VerifyMode::None` | Encrypts the connection but does not authenticate the server. This allows man-in-the-middle attacks. Use it only for testing. |

## Robustness

The DER and PEM parsers, the certificate chain logic and the TLS record and
handshake parsers are exercised by a mutation fuzzer under AddressSanitizer and
UBSan. The fuzzer and its results are described in [Testing](testing.md).

## Known limits

- The common name is not used for host matching.
- No revocation checking (CRL or OCSP), no name constraints, and no path length checks.
- ECDSA is P-256 only, and RSA keys are limited to the size set by
  `TINYTLS_MPI_MAX_LIMBS` (2048 bits by default).
- The bignum and AES code is not constant-time. That is acceptable for verifying
  public data, but not for operations that use a private key.
