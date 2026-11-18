/**
 * @file session.h
 * TLS 1.3 client session (RFC 8446): handshake, record layer and application data.
 *
 * The session is resumable. Every operation that would block returns
 * Error::WantRead or Error::WantWrite, and the next call continues where the
 * previous one stopped.
 *
 * Scope: client only; cipher suites TLS_AES_128_GCM_SHA256 and
 * TLS_CHACHA20_POLY1305_SHA256; X25519 key exchange; no HelloRetryRequest,
 * client certificates, PSK, 0-RTT or resumption.
 */
#pragma once

#include <string.h>
#include "bignum.h"
#include "chachapoly.h"
#include "config.h"
#include "drbg.h"
#include "gcm.h"
#include "heap.h"
#include "hkdf.h"
#include "sha256.h"
#include "transport.h"
#include "x25519.h"
#include "x509.h"

namespace tinytls {

/**
 * @brief AEAD keys for one direction of the TLS 1.3 record layer.
 *
 * install() derives the key and IV from a traffic secret and starts a fresh record
 * sequence. seal() and open() protect records in place; the nonce is the IV XORed
 * with the 64-bit sequence number. The class is internal to the session.
 *
 * The current secret is kept so that KeyUpdate can derive the next one. The key
 * material is wiped on reset() and on destruction.
 */
class TrafficKeys {
 public:
  /** TLS_AES_128_GCM_SHA256 cipher suite code point. */
  static constexpr uint16_t CipherAes128GcmSha256 = 0x1301;
  /** TLS_CHACHA20_POLY1305_SHA256 cipher suite code point. */
  static constexpr uint16_t CipherChaCha20Poly1305Sha256 = 0x1303;

  /** Creates inactive keys. */
  TrafficKeys() : active_(false), cipher_(0), seq_(0) {
    memset(secret_, 0, sizeof(secret_));
    memset(key_, 0, sizeof(key_));
    memset(iv_, 0, sizeof(iv_));
  }

  /** Wipes the key material. */
  ~TrafficKeys() {
    memset(secret_, 0, sizeof(secret_));
    memset(key_, 0, sizeof(key_));
    memset(iv_, 0, sizeof(iv_));
  }

  TrafficKeys(const TrafficKeys &) = delete;
  TrafficKeys &operator=(const TrafficKeys &) = delete;

  /** Derives key and IV from a traffic secret and starts a new sequence. */
  bool install(uint16_t cipher, const uint8_t secret[32]) {
    size_t key_len = cipher == CipherAes128GcmSha256 ? 16 : 32;
    memcpy(secret_, secret, 32);
    if (!hkdf_.expandLabel(secret, "key", nullptr, 0, key_, key_len)) return false;
    if (!hkdf_.expandLabel(secret, "iv", nullptr, 0, iv_, 12)) return false;
    cipher_ = cipher;
    seq_ = 0;
    if (cipher == CipherAes128GcmSha256) {
      if (!gcm_.setKey(key_, 128)) return false;
    } else {
      cp_.setKey(key_);
    }
    active_ = true;
    return true;
  }

  /** True once install() has succeeded. */
  bool active() const { return active_; }
  /** Cipher suite code point. */
  uint16_t cipher() const { return cipher_; }
  /** Current traffic secret (updated by KeyUpdate). */
  const uint8_t *secret() const { return secret_; }
  /** Record sequence number. */
  uint64_t sequence() const { return seq_; }
  /** Counts one record. */
  void advance() { seq_++; }

  /** AEAD-encrypts buf in place and writes the 16-byte tag. */
  bool seal(const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t len, uint8_t tag[16]) {
    uint8_t nonce[12];
    makeNonce(nonce);
    if (cipher_ == CipherAes128GcmSha256) {
      return gcm_.encrypt(nonce, 12, aad, aad_len, buf, len, buf, tag);
    }
    cp_.encrypt(nonce, aad, aad_len, buf, len, buf, tag);
    return true;
  }

  /** AEAD-verifies and decrypts buf in place. */
  Error open(const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t len, const uint8_t tag[16]) {
    uint8_t nonce[12];
    makeNonce(nonce);
    if (cipher_ == CipherAes128GcmSha256) {
      return gcm_.decrypt(nonce, 12, aad, aad_len, buf, len, tag, buf);
    }
    return cp_.decrypt(nonce, aad, aad_len, buf, len, tag, buf);
  }

  /** Clears the state; the keys become inactive. */
  void reset() {
    memset(secret_, 0, sizeof(secret_));
    memset(key_, 0, sizeof(key_));
    memset(iv_, 0, sizeof(iv_));
    active_ = false;
    seq_ = 0;
  }

 private:
  void makeNonce(uint8_t nonce[12]) const {
    memcpy(nonce, iv_, 12);
    for (int i = 0; i < 8; i++) nonce[4 + i] ^= (uint8_t)(seq_ >> (56 - 8 * i));
  }

  bool active_;
  uint16_t cipher_;
  uint8_t secret_[32];
  uint8_t key_[32];
  uint8_t iv_[12];
  uint64_t seq_;
  Gcm gcm_;
  ChaCha20Poly1305 cp_;
  Hkdf hkdf_;  ///< Key-derivation helper (member, not a per-call local).
};

/**
 * @brief TLS 1.3 client session (RFC 8446): handshake, record layer and application data.
 *
 * The session runs over a Transport and draws randomness from a Drbg. Every
 * operation that would block returns Error::WantRead or Error::WantWrite, and the
 * next call continues where the previous one stopped. This keeps the session
 * usable from a single-threaded Arduino loop.
 *
 * Supported: TLS 1.3, client role, the cipher suites TLS_AES_128_GCM_SHA256 and
 * TLS_CHACHA20_POLY1305_SHA256, the X25519 key exchange, SNI, KeyUpdate, and the
 * verification modes None, Optional and Required.
 *
 * Not supported: HelloRetryRequest, client certificates, pre-shared keys, 0-RTT and
 * session resumption.
 *
 * Applications normally use TinyTLS, which owns the entropy, the DRBG and the
 * configuration. Session is available for code that manages those parts itself.
 */
class Session {
 public:
  /** Creates a session. The transport and rng must outlive the session. */
  Session()
      : net_(nullptr), rng_(nullptr), hkdf_(), hmac_(), ks_(kKsSize), mode_(VerifyMode::Required),
        trust_(nullptr), time_(nullptr),
        has_hostname_(false), state_(State::Start), handshake_complete_(false), cipher_(0),
        verify_flags_(0), peer_close_notify_(false), peer_alert_(0), close_notify_sent_(false),
        chain_(TINYTLS_X509_MAX_CHAIN, Placement::Psram), rx_hdr_have_(0), rx_buf_(kMaxCiphertext, Placement::Psram), rx_have_(0),
        pt_type_(0), pt_off_(0), pt_len_(0), hs_buf_(kMaxHandshake, Placement::Psram), hs_have_(0), hs_need_(0),
        tx_buf_(kHeaderSize + kMaxCiphertext, Placement::Psram), tx_len_(0), tx_off_(0), tx_pending_(false),
        tx_user_len_(0) {
    hostname_[0] = 0;
  }

  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  /** Sets the transport and random source. Call before handshake(). */
  void bind(Transport *net, Drbg *rng) {
    net_ = net;
    rng_ = rng;
  }

  /** Sets the certificate verification mode, trust store and time source. */
  void configure(VerifyMode mode, const CertificateStore *trust, TimeFn time) {
    mode_ = mode;
    trust_ = trust;
    time_ = time;
  }

  /** Sets the server name for SNI and certificate checks. Returns false if it is too long. */
  bool setHostname(const char *host) {
    if (host == nullptr) {
      has_hostname_ = false;
      hostname_[0] = 0;
      return true;
    }
    size_t len = strlen(host);
    if (len == 0 || len > TINYTLS_MAX_HOSTNAME_LENGTH) return false;
    memcpy(hostname_, host, len);
    hostname_[len] = 0;
    has_hostname_ = true;
    return true;
  }

  /** Discards all state so that a new connection can be negotiated. Keeps the bindings and settings. */
  void reset() {
    tx_keys_.reset();
    rx_keys_.reset();
    handshake_complete_ = false;
    cipher_ = 0;
    verify_flags_ = 0;
    peer_close_notify_ = false;
    peer_alert_ = 0;
    close_notify_sent_ = false;
    hs_have_ = hs_need_ = 0;
    rx_hdr_have_ = rx_have_ = 0;
    pt_off_ = pt_len_ = 0;
    tx_len_ = tx_off_ = 0;
    tx_pending_ = false;
    tx_user_len_ = 0;
    state_ = State::Start;
    transcript_.reset();
  }

  /** Runs the handshake. Returns Error::Ok when complete, WantRead / WantWrite to retry, or an error. */
  Error handshake();

  /** Writes up to one record of application data. Returns the bytes accepted, or a negative Error. */
  int write(const uint8_t *buf, size_t len);

  /** Reads decrypted application data. Returns the byte count, or a negative Error. */
  int read(uint8_t *buf, size_t len);

  /** Decrypted application bytes ready to read. */
  int pending() const {
    return pt_len_ && pt_type_ == kTypeApplication ? (int)pt_len_ : 0;
  }

  /** Number of application bytes that can be read without blocking. */
  int available();

  /** Sends close_notify once. */
  Error closeNotify();

  /** True after the handshake completed. */
  bool handshakeComplete() const { return handshake_complete_; }
  /** True after the peer sent close_notify or a fatal alert. */
  bool peerClosed() const { return peer_close_notify_ || peer_alert_ != 0; }
  /** Verification flags for the server certificate. */
  uint32_t verifyFlags() const { return verify_flags_; }
  /** Negotiated protocol version as text. */
  const char *version() const { return handshake_complete_ ? "TLSv1.3" : "unknown"; }
  /** Negotiated cipher suite as text. */
  const char *cipherSuite() const;

 private:
  enum class State {
    Start,
    FlushClientHello,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
    FlushClientFinished,
    Done
  };

  /** SHA-256 of the empty string (used by the key schedule). */
  static constexpr uint8_t kEmptySha256[32] = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
  static constexpr uint8_t kTypeChangeCipherSpec = 20;
  static constexpr uint8_t kTypeAlert = 21;
  static constexpr uint8_t kTypeHandshake = 22;
  static constexpr uint8_t kTypeApplication = 23;

  static constexpr uint8_t kHsClientHello = 1;
  static constexpr uint8_t kHsServerHello = 2;
  static constexpr uint8_t kHsNewSessionTicket = 4;
  static constexpr uint8_t kHsEncryptedExtensions = 8;
  static constexpr uint8_t kHsCertificate = 11;
  static constexpr uint8_t kHsCertificateRequest = 13;
  static constexpr uint8_t kHsCertificateVerify = 15;
  static constexpr uint8_t kHsFinished = 20;
  static constexpr uint8_t kHsKeyUpdate = 24;

  static constexpr size_t kHeaderSize = 5;
  static constexpr size_t kMaxFragment = TINYTLS_MAX_FRAGMENT_LENGTH;
  static constexpr size_t kMaxCiphertext = TINYTLS_MAX_FRAGMENT_LENGTH + 256;
  static constexpr size_t kMaxHandshake = TINYTLS_MAX_HANDSHAKE_MESSAGE;
  static constexpr size_t kMaxHostname = TINYTLS_MAX_HOSTNAME_LENGTH;

  /* ---- Helpers ---- */
  uint16_t rd16(const uint8_t *p) const { return (uint16_t)((p[0] << 8) | p[1]); }
  uint32_t rd24(const uint8_t *p) const {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
  }
  size_t wr16(uint8_t *p, size_t o, uint32_t v) const {
    p[o] = (uint8_t)(v >> 8);
    p[o + 1] = (uint8_t)v;
    return o + 2;
  }
  void transcriptHash(uint8_t out[32]) const {
    Sha256 copy = transcript_;
    copy.finish(out);
  }
  Error sendRecord(uint8_t type, const uint8_t *data, size_t len);
  Error flush();
  Error fetchRecord();
  Error readHandshake(const uint8_t *&msg, size_t &msg_len);
  void consumeHandshake() {
    hs_have_ = 0;
    hs_need_ = 0;
  }
  Error recvSome(uint8_t *buf, size_t len, size_t &got);

  Error buildClientHello();
  Error deriveApplicationKeys(const uint8_t th_sf[32]);
  Error processServerHello(const uint8_t *m, size_t mlen);
  Error processCertificate(const uint8_t *m, size_t mlen);
  Error verifyCertificateVerify(const uint8_t *m, size_t mlen);
  Error postHandshake();

  static constexpr size_t kKsSize = 256;  ///< Key-schedule scratch: 8 x 32 bytes.

  Transport *net_;
  Drbg *rng_;
  Hkdf hkdf_;                  ///< Key-derivation helper (member, not a per-call local).
  Hmac hmac_;                  ///< MAC helper for the Finished messages.
  HeapArray<uint8_t> ks_;      ///< Key-schedule scratch on the heap (secrets, wiped after use).
  VerifyMode mode_;
  const CertificateStore *trust_;
  TimeFn time_;
  char hostname_[kMaxHostname + 1];
  bool has_hostname_;
  State state_;
  bool handshake_complete_;
  uint16_t cipher_;
  uint32_t verify_flags_;
  bool peer_close_notify_;
  uint8_t peer_alert_;
  bool close_notify_sent_;

  // Handshake state.
  uint8_t client_random_[32];
  uint8_t session_id_[32];
  uint8_t x_priv_[32];
  uint8_t x_pub_[32];
  Sha256 transcript_;
  uint8_t handshake_secret_[32];
  uint8_t finished_key_c_[32];
  uint8_t finished_key_s_[32];
  HeapArray<Certificate> chain_;  ///< Server chain (PSRAM when available).
  PublicKey leaf_key_;

  // Record layer.
  TrafficKeys tx_keys_;
  TrafficKeys rx_keys_;
  uint8_t rx_hdr_[kHeaderSize];
  size_t rx_hdr_have_;
  HeapArray<uint8_t> rx_buf_;  ///< Inbound record body (PSRAM when available).
  size_t rx_have_;
  uint8_t pt_type_;
  size_t pt_off_;
  size_t pt_len_;

  // Handshake message reassembly.
  HeapArray<uint8_t> hs_buf_;  ///< Handshake reassembly buffer (PSRAM when available).
  size_t hs_have_;
  size_t hs_need_;

  // Outbound record.
  HeapArray<uint8_t> tx_buf_;  ///< Outbound record (PSRAM when available).
  size_t tx_len_;
  size_t tx_off_;
  bool tx_pending_;
  size_t tx_user_len_;
};

inline const char *Session::cipherSuite() const {
  if (!handshake_complete_) return "unknown";
  if (cipher_ == TrafficKeys::CipherAes128GcmSha256) return "TLS1-3-AES-128-GCM-SHA256";
  if (cipher_ == TrafficKeys::CipherChaCha20Poly1305Sha256) return "TLS1-3-CHACHA20-POLY1305-SHA256";
  return "unknown";
}

inline Error Session::sendRecord(uint8_t type, const uint8_t *data, size_t len) {
  if (tx_pending_) return Error::Internal;
  uint8_t *out = tx_buf_.data();
  size_t body;
  if (tx_keys_.active()) {
    if (len > kMaxFragment) return Error::BadInput;
    body = len + 1 + 16;  // content, inner type, tag
    out[0] = kTypeApplication;  // the outer type of protected records is always 23
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(body >> 8);
    out[4] = (uint8_t)body;
    if (len) memcpy(out + 5, data, len);
    out[5 + len] = type;
    uint8_t tag[16];
    if (!tx_keys_.seal(out, kHeaderSize, out + 5, len + 1, tag)) return Error::Internal;
    memcpy(out + 5 + len + 1, tag, 16);
    tx_keys_.advance();
  } else {
    if (len > kMaxFragment) return Error::BadInput;
    body = len;
    out[0] = type;
    out[1] = 0x03;
    out[2] = 0x01;  // legacy_record_version of the initial ClientHello
    out[3] = (uint8_t)(body >> 8);
    out[4] = (uint8_t)body;
    if (len) memcpy(out + 5, data, len);
  }
  tx_len_ = kHeaderSize + body;
  tx_off_ = 0;
  tx_pending_ = true;
  return Error::Ok;
}

inline Error Session::flush() {
  while (tx_pending_ && tx_off_ < tx_len_) {
    size_t n = net_->write(tx_buf_.data() + tx_off_, tx_len_ - tx_off_);
    if (n == 0) return Error::WantWrite;
    tx_off_ += n;
  }
  tx_pending_ = false;
  tx_off_ = 0;
  tx_len_ = 0;
  return Error::Ok;
}

inline Error Session::recvSome(uint8_t *buf, size_t len, size_t &got) {
  if (!net_->connected() && net_->available() <= 0) return Error::ConnectionClosed;
  int avail = net_->available();
  if (avail <= 0) return Error::WantRead;
  size_t want = (size_t)avail < len ? (size_t)avail : len;
  int n = net_->read(buf, want);
  if (n <= 0) return Error::WantRead;
  got = (size_t)n;
  return Error::Ok;
}

inline Error Session::fetchRecord() {
  if (peer_close_notify_) return Error::PeerCloseNotify;
  if (peer_alert_) return Error::AlertReceived;
  for (;;) {
    Error rc;
    size_t got = 0;
    while (rx_hdr_have_ < kHeaderSize) {
      rc = recvSome(rx_hdr_ + rx_hdr_have_, kHeaderSize - rx_hdr_have_, got);
      if (rc != Error::Ok) return rc;
      rx_hdr_have_ += got;
    }
    uint8_t type = rx_hdr_[0];
    size_t len = rd16(rx_hdr_ + 3);
    if (rx_hdr_[1] != 0x03) return Error::InvalidRecord;
    if (type < kTypeChangeCipherSpec || type > kTypeApplication) return Error::InvalidRecord;
    size_t max_len = rx_keys_.active() ? kMaxCiphertext : kMaxFragment;
    if (len > max_len) return Error::InvalidRecord;
    while (rx_have_ < len) {
      rc = recvSome(rx_buf_.data() + rx_have_, len - rx_have_, got);
      if (rc != Error::Ok) return rc;
      rx_have_ += got;
    }

    // ChangeCipherSpec is never encrypted, even after keys are installed.
    if (rx_keys_.active() && type != kTypeChangeCipherSpec) {
      if (type != kTypeApplication || len < 17) return Error::InvalidRecord;
      size_t ct = len - 16;
      if (rx_keys_.open(rx_hdr_, kHeaderSize, rx_buf_.data(), ct, rx_buf_.data() + ct) != Error::Ok) {
        return Error::InvalidRecord;  // bad record MAC
      }
      rx_keys_.advance();
      size_t n = ct;
      while (n > 0 && rx_buf_[n - 1] == 0) n--;  // strip zero padding
      if (n == 0) return Error::InvalidRecord;
      pt_type_ = rx_buf_[n - 1];
      pt_len_ = n - 1;
    } else {
      pt_type_ = type;
      pt_len_ = len;
    }
    pt_off_ = 0;
    rx_hdr_have_ = 0;
    rx_have_ = 0;

    if (pt_type_ == kTypeChangeCipherSpec) {
      if (pt_len_ != 1 || rx_buf_[0] != 1) return Error::InvalidRecord;
      pt_len_ = 0;
      continue;
    }
    if (pt_type_ == kTypeAlert) {
      if (pt_len_ < 2) return Error::InvalidRecord;
      uint8_t level = rx_buf_[0];
      uint8_t desc = rx_buf_[1];
      pt_len_ = 0;
      if (desc == 0) {  // close_notify
        peer_close_notify_ = true;
        return Error::PeerCloseNotify;
      }
      if (level == 2) {  // fatal
        peer_alert_ = desc ? desc : 1;
        return Error::AlertReceived;
      }
      continue;  // warnings are ignored
    }
    if (pt_len_ == 0) continue;  // empty fragment
    return Error::Ok;
  }
}

inline Error Session::readHandshake(const uint8_t *&msg, size_t &msg_len) {
  for (;;) {
    if (hs_need_ && hs_have_ == hs_need_) break;
    if (pt_len_ == 0) {
      Error rc = fetchRecord();
      if (rc != Error::Ok) return rc;
    }
    if (pt_type_ != kTypeHandshake) return Error::UnexpectedMessage;
    size_t want = hs_have_ < 4 ? 4 - hs_have_ : hs_need_ - hs_have_;
    size_t n = want < pt_len_ ? want : pt_len_;
    memcpy(hs_buf_.data() + hs_have_, rx_buf_.data() + pt_off_, n);
    hs_have_ += n;
    pt_off_ += n;
    pt_len_ -= n;
    if (hs_need_ == 0 && hs_have_ == 4) {
      size_t body = rd24(hs_buf_.data() + 1);
      if (4 + body > kMaxHandshake) return Error::MessageTooLarge;
      hs_need_ = 4 + body;
    }
  }
  msg = hs_buf_.data();
  msg_len = hs_need_;
  return Error::Ok;
}

inline Error Session::buildClientHello() {
  if (rng_ == nullptr) return Error::BadInput;
  uint8_t rnd[32 + 32 + 32];
  if (!rng_->random(rnd, sizeof(rnd))) return Error::EntropyFailed;
  memcpy(client_random_, rnd, 32);
  memcpy(session_id_, rnd + 32, 32);
  memcpy(x_priv_, rnd + 64, 32);
  memset(rnd, 0, sizeof(rnd));
  X25519 x25519;
  if (!x25519.publicKey(x_priv_, x_pub_)) return Error::X25519LowOrder;

  HeapArray<uint8_t> m_store(512);
  uint8_t *m = m_store.data();
  size_t o = 4;  // handshake header is filled in at the end
  o = wr16(m, o, 0x0303);
  memcpy(m + o, client_random_, 32);
  o += 32;
  m[o++] = 32;
  memcpy(m + o, session_id_, 32);
  o += 32;
  o = wr16(m, o, 4);
  o = wr16(m, o, TrafficKeys::CipherAes128GcmSha256);
  o = wr16(m, o, TrafficKeys::CipherChaCha20Poly1305Sha256);
  m[o++] = 1;  // legacy_compression_methods
  m[o++] = 0;

  size_t ext_len_pos = o;
  o += 2;
  size_t ext_start = o;
  if (has_hostname_) {
    size_t hl = strlen(hostname_);
    o = wr16(m, o, 0x0000);  // server_name
    o = wr16(m, o, hl + 5);
    o = wr16(m, o, hl + 3);
    m[o++] = 0;              // host_name
    o = wr16(m, o, hl);
    memcpy(m + o, hostname_, hl);
    o += hl;
  }
  o = wr16(m, o, 0x000a);  // supported_groups
  o = wr16(m, o, 4);
  o = wr16(m, o, 2);
  o = wr16(m, o, 0x001d);  // x25519
  o = wr16(m, o, 0x000d);  // signature_algorithms
  o = wr16(m, o, 8);
  o = wr16(m, o, 6);
  o = wr16(m, o, 0x0804);  // rsa_pss_rsae_sha256
  o = wr16(m, o, 0x0403);  // ecdsa_secp256r1_sha256
  o = wr16(m, o, 0x0401);  // rsa_pkcs1_sha256
  o = wr16(m, o, 0x002b);  // supported_versions
  o = wr16(m, o, 3);
  m[o++] = 2;
  o = wr16(m, o, 0x0304);
  o = wr16(m, o, 0x0033);  // key_share
  o = wr16(m, o, 38);
  o = wr16(m, o, 36);
  o = wr16(m, o, 0x001d);
  o = wr16(m, o, 32);
  memcpy(m + o, x_pub_, 32);
  o += 32;
  wr16(m, ext_len_pos, (uint32_t)(o - ext_start));

  m[0] = kHsClientHello;
  m[1] = (uint8_t)((o - 4) >> 16);
  m[2] = (uint8_t)((o - 4) >> 8);
  m[3] = (uint8_t)(o - 4);
  transcript_.update(m, o);
  Error rc = sendRecord(kTypeHandshake, m, o);
  m_store.wipe();
  return rc;
}

inline Error Session::processServerHello(const uint8_t *m, size_t mlen) {
  static const uint8_t hrr_random[32] = {
      0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};
  const uint8_t *b = m + 4;
  size_t bl = mlen - 4;
  if (bl < 2 + 32 + 1) return Error::BadServerHello;
  if (b[0] != 0x03 || b[1] != 0x03) return Error::BadServerHello;
  if (memcmp(b + 2, hrr_random, 32) == 0) return Error::Unsupported;  // HelloRetryRequest

  size_t o = 34;
  size_t sid_len = b[o++];
  if (sid_len != 32 || o + sid_len + 2 + 1 + 2 > bl) return Error::BadServerHello;
  if (memcmp(b + o, session_id_, 32) != 0) return Error::BadServerHello;
  o += 32;
  uint16_t cipher = rd16(b + o);
  o += 2;
  if (b[o] != 0) return Error::BadServerHello;
  o += 1;
  size_t ext_len = rd16(b + o);
  o += 2;
  if (o + ext_len != bl) return Error::BadServerHello;

  bool version_ok = false, share_ok = false;
  uint8_t server_pub[32];
  size_t end = o + ext_len;
  while (o < end) {
    if (o + 4 > end) return Error::BadServerHello;
    uint16_t et = rd16(b + o);
    size_t el = rd16(b + o + 2);
    o += 4;
    if (o + el > end) return Error::BadServerHello;
    const uint8_t *d = b + o;
    if (et == 0x002b) {  // supported_versions
      if (el != 2 || rd16(d) != 0x0304) return Error::ProtocolVersion;
      version_ok = true;
    } else if (et == 0x0033) {  // key_share
      if (el != 36 || rd16(d) != 0x001d || rd16(d + 2) != 32) return Error::BadServerHello;
      memcpy(server_pub, d + 4, 32);
      share_ok = true;
    }
    o += el;
  }
  if (!version_ok || !share_ok) return Error::BadServerHello;
  if (cipher != TrafficKeys::CipherAes128GcmSha256 &&
      cipher != TrafficKeys::CipherChaCha20Poly1305Sha256) {
    return Error::BadServerHello;
  }
  cipher_ = cipher;

  // Key-schedule scratch (see ks_): th | empty | zeros | early | derived | c_hs | s_hs | shared.
  uint8_t *ks = ks_.data();
  uint8_t *th = ks, *empty = ks + 32, *zeros = ks + 64, *early = ks + 96, *derived = ks + 128,
          *c_hs = ks + 160, *s_hs = ks + 192, *shared = ks + 224;
  memset(zeros, 0, 32);
  X25519 x25519;
  if (!x25519.scalarmult(shared, x_priv_, server_pub)) return Error::BadServerHello;

  // Key schedule (RFC 8446 section 7.1) without PSK.
  transcript_.update(m, mlen);
  transcriptHash(th);
  memcpy(empty, kEmptySha256, 32);
  hkdf_.extract(nullptr, 0, zeros, 32, early);
  hkdf_.deriveSecret(early, "derived", empty, derived);
  hkdf_.extract(derived, 32, shared, 32, handshake_secret_);
  hkdf_.deriveSecret(handshake_secret_, "c hs traffic", th, c_hs);
  hkdf_.deriveSecret(handshake_secret_, "s hs traffic", th, s_hs);
  hkdf_.expandLabel(c_hs, "finished", nullptr, 0, finished_key_c_, 32);
  hkdf_.expandLabel(s_hs, "finished", nullptr, 0, finished_key_s_, 32);
  Error rc = tx_keys_.install(cipher, c_hs) ? Error::Ok : Error::Internal;
  if (rc == Error::Ok) rc = rx_keys_.install(cipher, s_hs) ? Error::Ok : Error::Internal;
  ks_.wipe();
  return rc;
}

inline Error Session::processCertificate(const uint8_t *m, size_t mlen) {
  const uint8_t *b = m + 4;
  size_t bl = mlen - 4;
  if (bl < 4 || b[0] != 0) return Error::BadCertificate;
  size_t list_len = rd24(b + 1);
  if (4 + list_len != bl || list_len == 0) return Error::BadCertificate;

  // Parse the chain in place: the DER pointers stay valid until the message is consumed.
  size_t o = 4;
  size_t n = 0;
  bool parse_failed = false;
  while (o < bl) {
    if (o + 3 > bl) return Error::BadCertificate;
    size_t clen = rd24(b + o);
    o += 3;
    if (clen == 0 || o + clen + 2 > bl) return Error::BadCertificate;
    const uint8_t *der = b + o;
    o += clen;
    size_t elen = rd16(b + o);
    o += 2;
    if (o + elen > bl) return Error::BadCertificate;
    o += elen;
    if (n < TINYTLS_X509_MAX_CHAIN) {
      if (chain_[n].parse(der, clen) != Error::Ok) parse_failed = true;
    } else {
      parse_failed = true;  // longer than TINYTLS_X509_MAX_CHAIN
    }
    n++;
  }
  if (o != bl || n == 0) return Error::BadCertificate;

  if (mode_ == VerifyMode::None) {
    verify_flags_ |= VerifySkipped;
    if (!parse_failed) leaf_key_ = chain_[0].publicKey();
    return Error::Ok;
  }

  uint32_t flags = 0;
  Error rc;
  if (parse_failed) {
    flags |= VerifyBadCertificate;
    rc = Error::X509BadCertificate;
  } else {
    int64_t now = time_ ? time_() : -1;
    ChainVerifier verifier(trust_, hostname_, now);
    rc = verifier.verify(chain_.data(), n, flags);
    leaf_key_ = chain_[0].publicKey();
  }
  verify_flags_ |= flags;
  if (mode_ == VerifyMode::Required && (rc != Error::Ok || flags != 0)) {
    return Error::CertificateVerifyFailed;
  }
  return Error::Ok;
}

inline Error Session::verifyCertificateVerify(const uint8_t *m, size_t mlen) {
  const uint8_t *b = m + 4;
  size_t bl = mlen - 4;
  if (bl < 4) return Error::BadCertificate;
  uint16_t scheme = rd16(b);
  size_t sig_len = rd16(b + 2);
  if (4 + sig_len != bl) return Error::BadCertificate;
  if (mode_ == VerifyMode::None) return Error::Ok;

  // Signed content: 64 spaces, context string, a zero byte, transcript hash (RFC 8446 section 4.4.3).
  static const char context[] = "TLS 1.3, server CertificateVerify";
  const size_t ctx_len = sizeof(context) - 1;
  uint8_t content[64 + sizeof(context) - 1 + 1 + 32];
  memset(content, 0x20, 64);
  memcpy(content + 64, context, ctx_len);
  content[64 + ctx_len] = 0;
  transcriptHash(content + 64 + ctx_len + 1);

  if (leaf_key_.verify(scheme, content, sizeof(content), b + 4, sig_len) == Error::Ok) {
    return Error::Ok;
  }
  verify_flags_ |= VerifyBadSignature;
  return mode_ == VerifyMode::Required ? Error::X509BadSignature : Error::Ok;
}

inline Error Session::deriveApplicationKeys(const uint8_t th_sf[32]) {
  // Key-schedule scratch (see ks_): empty | zeros | derived2 | master | c_ap | s_ap.
  uint8_t *ks = ks_.data();
  uint8_t *empty = ks, *zeros = ks + 32, *derived2 = ks + 64, *master = ks + 96, *c_ap = ks + 128,
          *s_ap = ks + 160;
  memcpy(empty, kEmptySha256, 32);
  memset(zeros, 0, 32);
  hkdf_.deriveSecret(handshake_secret_, "derived", empty, derived2);
  hkdf_.extract(derived2, 32, zeros, 32, master);
  hkdf_.deriveSecret(master, "c ap traffic", th_sf, c_ap);
  hkdf_.deriveSecret(master, "s ap traffic", th_sf, s_ap);

  // Client Finished is still sent under the client handshake keys.
  uint8_t verify[32];
  hmac_.start(finished_key_c_, 32);
  hmac_.update(th_sf, 32);
  hmac_.finish(verify);
  uint8_t fin[4 + 32];
  fin[0] = kHsFinished;
  fin[1] = 0;
  fin[2] = 0;
  fin[3] = 32;
  memcpy(fin + 4, verify, 32);
  Error rc = sendRecord(kTypeHandshake, fin, sizeof(fin));
  if (rc == Error::Ok) {
    tx_keys_.install(cipher_, c_ap);
    rx_keys_.install(cipher_, s_ap);
  }
  ks_.wipe();
  return rc;
}

inline Error Session::handshake() {
  if (net_ == nullptr || rng_ == nullptr) return Error::BadInput;
  if (handshake_complete_) return Error::Ok;

  for (;;) {
    Error rc = Error::Ok;
    const uint8_t *msg = nullptr;
    size_t mlen = 0;
    switch (state_) {
      case State::Start:
        rc = buildClientHello();
        if (rc != Error::Ok) return rc;
        state_ = State::FlushClientHello;
        break;

      case State::FlushClientHello:
        rc = flush();
        if (rc != Error::Ok) return rc;
        state_ = State::ServerHello;
        break;

      case State::ServerHello:
        rc = readHandshake(msg, mlen);
        if (rc != Error::Ok) return rc;
        if (msg[0] != kHsServerHello) return Error::UnexpectedMessage;
        rc = processServerHello(msg, mlen);
        if (rc != Error::Ok) return rc;
        // Plaintext bytes after ServerHello are not allowed.
        if (rx_keys_.active() && pt_len_ != 0) return Error::UnexpectedMessage;
        consumeHandshake();
        state_ = State::EncryptedExtensions;
        break;

      case State::EncryptedExtensions:
        rc = readHandshake(msg, mlen);
        if (rc != Error::Ok) return rc;
        if (msg[0] != kHsEncryptedExtensions) return Error::UnexpectedMessage;
        if (mlen < 4 + 2 || rd16(msg + 4) != mlen - 6) return Error::BadInput;
        transcript_.update(msg, mlen);
        consumeHandshake();
        state_ = State::Certificate;
        break;

      case State::Certificate:
        rc = readHandshake(msg, mlen);
        if (rc != Error::Ok) return rc;
        if (msg[0] == kHsCertificateRequest) return Error::Unsupported;  // client certificates
        if (msg[0] != kHsCertificate) return Error::UnexpectedMessage;
        rc = processCertificate(msg, mlen);
        if (rc != Error::Ok) return rc;
        transcript_.update(msg, mlen);
        consumeHandshake();
        state_ = State::CertificateVerify;
        break;

      case State::CertificateVerify:
        rc = readHandshake(msg, mlen);
        if (rc != Error::Ok) return rc;
        if (msg[0] != kHsCertificateVerify) return Error::UnexpectedMessage;
        rc = verifyCertificateVerify(msg, mlen);
        if (rc != Error::Ok) return rc;
        transcript_.update(msg, mlen);
        consumeHandshake();
        state_ = State::Finished;
        break;

      case State::Finished: {
        rc = readHandshake(msg, mlen);
        if (rc != Error::Ok) return rc;
        if (msg[0] != kHsFinished || mlen != 4 + 32) return Error::BadFinished;
        uint8_t th[32], expected[32];
        transcriptHash(th);
        hmac_.start(finished_key_s_, 32);
        hmac_.update(th, 32);
        hmac_.finish(expected);
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++) diff |= (uint8_t)(expected[i] ^ msg[4 + i]);
        if (diff != 0) return Error::BadFinished;
        transcript_.update(msg, mlen);
        consumeHandshake();
        uint8_t th_sf[32];
        transcriptHash(th_sf);
        rc = deriveApplicationKeys(th_sf);
        if (rc != Error::Ok) return rc;
        state_ = State::FlushClientFinished;
        break;
      }

      case State::FlushClientFinished:
        rc = flush();
        if (rc != Error::Ok) return rc;
        handshake_complete_ = true;
        state_ = State::Done;
        memset(handshake_secret_, 0, sizeof(handshake_secret_));
        memset(finished_key_c_, 0, sizeof(finished_key_c_));
        memset(finished_key_s_, 0, sizeof(finished_key_s_));
        return Error::Ok;

      case State::Done:
        return Error::Ok;
    }
  }
}

inline Error Session::postHandshake() {
  if (tx_pending_) {
    Error rc = flush();
    if (rc != Error::Ok) return rc;
  }
  const uint8_t *msg = nullptr;
  size_t mlen = 0;
  Error rc = readHandshake(msg, mlen);
  if (rc != Error::Ok) return rc;

  if (msg[0] == kHsNewSessionTicket) {  // tickets are ignored
    consumeHandshake();
    return Error::Ok;
  }
  if (msg[0] != kHsKeyUpdate || mlen != 5 || msg[4] > 1) {
    consumeHandshake();
    return Error::UnexpectedMessage;
  }
  uint8_t request = msg[4];
  consumeHandshake();

  // Update the receive keys.
  uint8_t next[32];
  Hkdf hk;
  if (!hk.expandLabel(rx_keys_.secret(), "traffic upd", nullptr, 0, next, 32)) return Error::Internal;
  if (!rx_keys_.install(rx_keys_.cipher(), next)) return Error::Internal;

  if (request) {
    // Reply under the old sending keys, then update the sending keys.
    static const uint8_t reply[5] = {kHsKeyUpdate, 0, 0, 1, 0};
    rc = sendRecord(kTypeHandshake, reply, sizeof(reply));
    if (rc != Error::Ok) return rc;
    if (!hk.expandLabel(tx_keys_.secret(), "traffic upd", nullptr, 0, next, 32)) return Error::Internal;
    if (!tx_keys_.install(tx_keys_.cipher(), next)) return Error::Internal;
    return flush();
  }
  return Error::Ok;
}

inline int Session::write(const uint8_t *buf, size_t len) {
  if (!handshake_complete_) return code(Error::BadInput);
  if (tx_pending_) {
    Error rc = flush();
    if (rc != Error::Ok) return code(rc);
    if (tx_user_len_) {
      int n = (int)tx_user_len_;
      tx_user_len_ = 0;
      return n;
    }
  }
  if (len == 0) return 0;
  if (len > kMaxFragment) len = kMaxFragment;
  Error rc = sendRecord(kTypeApplication, buf, len);
  if (rc != Error::Ok) return code(rc);
  tx_user_len_ = len;
  rc = flush();
  if (rc != Error::Ok) return code(rc);
  tx_user_len_ = 0;
  return (int)len;
}

inline int Session::read(uint8_t *buf, size_t len) {
  if (!handshake_complete_) return code(Error::BadInput);
  if (tx_pending_) {
    Error rc = flush();
    if (rc != Error::Ok) return code(rc);
  }
  if (len == 0) return 0;
  for (;;) {
    if (pt_len_ == 0) {
      Error rc = fetchRecord();
      if (rc != Error::Ok) return code(rc);
    }
    if (pt_type_ == kTypeApplication) {
      size_t n = len < pt_len_ ? len : pt_len_;
      memcpy(buf, rx_buf_.data() + pt_off_, n);
      pt_off_ += n;
      pt_len_ -= n;
      return (int)n;
    }
    if (pt_type_ == kTypeHandshake) {
      Error rc = postHandshake();
      if (rc != Error::Ok) return code(rc);
      continue;
    }
    return code(Error::UnexpectedMessage);
  }
}

inline int Session::available() {
  if (!handshake_complete_) return 0;
  for (;;) {
    if (pending() > 0) return pending();
    Error rc = fetchRecord();
    if (rc != Error::Ok) return 0;
    if (pt_type_ == kTypeHandshake) {
      rc = postHandshake();
      if (rc != Error::Ok) return 0;
    }
  }
}

inline Error Session::closeNotify() {
  if (!handshake_complete_) return Error::Ok;
  if (tx_pending_) {
    Error rc = flush();
    if (rc != Error::Ok) return rc;
  }
  if (!close_notify_sent_) {
    static const uint8_t alert[2] = {1, 0};  // warning, close_notify
    Error rc = sendRecord(kTypeAlert, alert, sizeof(alert));
    if (rc != Error::Ok) return rc;
    close_notify_sent_ = true;
  }
  return flush();
}

/* Out-of-class definition needed for pointer use under C++11. */
constexpr uint8_t Session::kEmptySha256[32];

}  // namespace tinytls
