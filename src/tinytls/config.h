/**
 * @file config.h
 * Configuration macros, error codes and verification flags of the TinyTLS library.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/** Library version. */
#define TINYTLS_VERSION_MAJOR 0
/** Library version. */
#define TINYTLS_VERSION_MINOR 2
/** Library version. */
#define TINYTLS_VERSION_PATCH 0
/** Library version as a string. */
#define TINYTLS_VERSION_STRING "0.2.0"

/**
 * Largest plaintext fragment accepted or produced, in bytes (RFC 8446 section 5.1).
 * Lower it on memory-constrained boards.
 */
#ifndef TINYTLS_MAX_FRAGMENT_LENGTH
#define TINYTLS_MAX_FRAGMENT_LENGTH 16384
#endif

/** Largest handshake message (header included) that is buffered, in bytes. */
#ifndef TINYTLS_MAX_HANDSHAKE_MESSAGE
#define TINYTLS_MAX_HANDSHAKE_MESSAGE 16384
#endif

/** Longest server name sent in SNI and checked against certificates, in bytes. */
#ifndef TINYTLS_MAX_HOSTNAME_LENGTH
#define TINYTLS_MAX_HOSTNAME_LENGTH 128
#endif

/** Maximum number of certificates in a trust store. */
#ifndef TINYTLS_X509_MAX_CERTS
#define TINYTLS_X509_MAX_CERTS 4
#endif

/** Largest DER certificate stored in a trust store, in bytes. */
#ifndef TINYTLS_X509_MAX_CERT_SIZE
#define TINYTLS_X509_MAX_CERT_SIZE 3072
#endif

/** Maximum number of certificates accepted in a server Certificate message. */
#ifndef TINYTLS_X509_MAX_CHAIN
#define TINYTLS_X509_MAX_CHAIN 6
#endif

/**
 * Maximum limbs per big integer. The default of 72 limbs (2304 bits) covers
 * RSA-2048. Define a larger value for RSA-3072 (96 limbs) or RSA-4096 (130 limbs);
 * this also raises the heap use of the signature code.
 */
#ifndef TINYTLS_MPI_MAX_LIMBS
#define TINYTLS_MPI_MAX_LIMBS 72
#endif

/**
 * Use PSRAM for large, rarely accessed buffers when the platform has it.
 * Defaults to 1 on ESP32 (Arduino or ESP-IDF); set 0 to keep everything in RAM.
 * If no PSRAM is present at run time, the allocation falls back to RAM.
 */
#ifndef TINYTLS_USE_PSRAM
#if defined(ESP_PLATFORM) || defined(ESP32)
#define TINYTLS_USE_PSRAM 1
#else
#define TINYTLS_USE_PSRAM 0
#endif
#endif

namespace tinytls {

/** Result codes returned by the library. Negative values are errors. */
enum class Error : int32_t {
  Ok = 0,                       ///< Success.
  WantRead = -0x6900,           ///< No data yet; retry when the transport is readable.
  WantWrite = -0x6880,          ///< Transport not writable yet; retry.
  ConnectionClosed = -0x7280,   ///< The transport closed or timed out.
  PeerCloseNotify = -0x7880,    ///< The peer sent close_notify.
  InvalidRecord = -0x7200,      ///< A record is malformed or failed authentication.
  UnexpectedMessage = -0x7300,  ///< A message arrived out of order.
  ProtocolVersion = -0x7400,    ///< The peer does not support TLS 1.3.
  BadServerHello = -0x7500,     ///< The ServerHello is malformed or uses unsupported parameters.
  BadFinished = -0x7600,        ///< The server Finished did not verify.
  BadCertificate = -0x7700,     ///< The Certificate message is malformed.
  AlertReceived = -0x7A00,      ///< The peer sent a fatal alert.
  MessageTooLarge = -0x7F20,    ///< A handshake message exceeds TINYTLS_MAX_HANDSHAKE_MESSAGE.
  Unsupported = -0x7080,        ///< The requested feature is not implemented.
  BadInput = -0x7180,           ///< An argument is invalid.
  Internal = -0x7FFF,           ///< Internal inconsistency; should not happen.
  CertificateVerifyFailed = -0x7E00,  ///< Certificate validation failed; see the verify flags.
  EntropyFailed = -0x003C,      ///< All entropy sources failed.
  AuthenticationFailed = -0x0012,  ///< AEAD tag verification failed.
  X509BadCertificate = -0x0081,    ///< Certificate DER or PEM is malformed.
  X509Unsupported = -0x0083,       ///< Certificate uses an unsupported algorithm.
  X509BadSignature = -0x0085,      ///< A signature does not verify.
  X509Full = -0x0089,              ///< Trust store or certificate storage is full.
  X509CertVerifyFailed = -0x0087,  ///< Chain validation failed; see the verify flags.
  EcdsaBadInput = -0x0071,         ///< ECDSA public key or signature is malformed.
  EcdsaVerifyFailed = -0x0073,     ///< ECDSA signature does not verify.
  RsaVerifyFailed = -0x0075,       ///< RSA signature does not verify.
  X25519LowOrder = -0x0061         ///< X25519 produced an all-zero result (low-order input).
};

/** Returns true if the result is Error::Ok. */
inline bool ok(Error e) { return e == Error::Ok; }

/** Returns the numeric value of an error (used by functions that return a byte count or an error). */
inline int code(Error e) { return static_cast<int>(e); }

/** Returns a short human-readable description of an error. */
inline const char *errorString(Error e) {
  switch (e) {
    case Error::Ok: return "success";
    case Error::WantRead: return "want read";
    case Error::WantWrite: return "want write";
    case Error::ConnectionClosed: return "connection closed by transport or timed out";
    case Error::PeerCloseNotify: return "peer sent close_notify";
    case Error::InvalidRecord: return "invalid record";
    case Error::UnexpectedMessage: return "unexpected message";
    case Error::ProtocolVersion: return "peer does not support TLS 1.3";
    case Error::BadServerHello: return "bad ServerHello";
    case Error::BadFinished: return "bad Finished message";
    case Error::BadCertificate: return "bad Certificate message";
    case Error::AlertReceived: return "fatal alert received";
    case Error::MessageTooLarge: return "handshake message too large";
    case Error::Unsupported: return "feature not supported";
    case Error::BadInput: return "bad input or missing setup";
    case Error::Internal: return "internal error";
    case Error::CertificateVerifyFailed: return "certificate verification failed (see verifyResult)";
    case Error::EntropyFailed: return "entropy source failed";
    case Error::AuthenticationFailed: return "authentication tag mismatch";
    case Error::X509BadCertificate: return "malformed certificate";
    case Error::X509Unsupported: return "unsupported certificate algorithm";
    case Error::X509BadSignature: return "signature does not verify";
    case Error::X509Full: return "trust store is full";
    case Error::X509CertVerifyFailed: return "certificate chain not trusted";
    case Error::EcdsaBadInput: return "malformed ECDSA key or signature";
    case Error::EcdsaVerifyFailed: return "ECDSA signature does not verify";
    case Error::RsaVerifyFailed: return "RSA signature does not verify";
    case Error::X25519LowOrder: return "X25519 low-order point";
  }
  return "unknown error";
}

/**
 * Certificate verification flags reported by TinyTLS::verifyResult(). They
 * describe why the peer was not fully authenticated.
 */
enum VerifyFlag : uint32_t {
  VerifyNotVerified = 0x0001,     ///< Chain not checked (VerifyMode::Optional).
  VerifySkipped = 0x0002,         ///< Verification disabled (VerifyMode::None).
  VerifyExpired = 0x0004,         ///< A certificate is past its notAfter time.
  VerifyFuture = 0x0008,          ///< A certificate is not yet valid.
  VerifyNameMismatch = 0x0010,    ///< No subjectAltName matches the host name.
  VerifyNotTrusted = 0x0020,      ///< The chain does not lead to a trust anchor.
  VerifyBadSignature = 0x0040,    ///< A certificate or CertificateVerify signature is invalid.
  VerifyBadCertificate = 0x0080,  ///< A certificate is malformed or uses an unsupported algorithm.
  VerifyTimeUnchecked = 0x0100    ///< No time source configured; validity not checked.
};

/** Certificate verification mode of a TLS client. */
enum class VerifyMode : int {
  None = 0,      ///< Do not verify the server (encryption only).
  Optional = 1,  ///< Verify, but continue on failure (see verifyResult()).
  Required = 2   ///< Verify and fail the handshake on failure (default).
};

/** Current Unix time in seconds, or a negative value if unknown. */
using TimeFn = int64_t (*)();

}  // namespace tinytls
