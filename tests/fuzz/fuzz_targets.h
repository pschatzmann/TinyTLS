/**
 * @file fuzz_targets.h
 * Entry points for fuzzing the parsers and verifiers of TinyTLS.
 *
 * Each function takes arbitrary bytes and must never crash, hang or trigger a
 * sanitizer report, whatever the input. They are called by fuzz_main.cpp and
 * can be used with libFuzzer as well.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace fuzz {

/** Certificate::parse and the accessors of a parsed certificate. */
void fuzzCertificate(const uint8_t *data, size_t size);

/** PublicKey::parse (SubjectPublicKeyInfo content) and signature verification with it. */
void fuzzPublicKey(const uint8_t *data, size_t size);

/** CertificateStore::add (PEM or DER) followed by chain verification. */
void fuzzCertificateStore(const uint8_t *data, size_t size);

/** Base64 decoding. */
void fuzzBase64(const uint8_t *data, size_t size);

/** DerReader iteration over arbitrary bytes. */
void fuzzDerReader(const uint8_t *data, size_t size);

/** RSA PKCS#1 v1.5 and PSS verification with a fuzzed modulus, exponent and signature. */
void fuzzRsa(const uint8_t *data, size_t size);

/** ECDSA P-256 verification with fuzzed key, digest and signature. */
void fuzzEcdsa(const uint8_t *data, size_t size);

}  // namespace fuzz

namespace fuzz {

/**
 * Drives a real TLS 1.3 client session against a scripted server. The fuzz input
 * chooses the cipher suite, the certificate chain (real test certificates with
 * mutations, or raw bytes), the CertificateVerify fields and the verification
 * mode. The server flight is encrypted with keys derived in the harness, so the
 * client parses the mutated messages and then the post-handshake code.
 */
void fuzzTlsHandshake(const uint8_t *data, size_t size);

/** Number of inputs that got past the ClientHello and reached the server flight. */
unsigned long handshakeFlights();

/** Number of inputs that completed the handshake (client Finished verified). */
unsigned long handshakeCompletions();

}  // namespace fuzz
