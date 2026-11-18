/**
 * @file hkdf.h
 * HMAC-SHA256 (RFC 2104) and HKDF (RFC 5869), including the TLS 1.3 label
 * helpers of RFC 8446 section 7.1.
 */
#pragma once

#include <string.h>
#include "config.h"
#include "heap.h"
#include "sha256.h"

namespace tinytls {

/**
 * Incremental HMAC-SHA256 message authentication (RFC 2104).
 *
 * The constructor starts a computation with a key. Keys longer than the
 * SHA-256 block size are hashed first. start() restarts the object with a new
 * key, so one object can compute many tags. The derived outer padding is wiped
 * when the object is destroyed.
 *
 * @code
 * Hmac m(key, key_len);
 * m.update(data, data_len);
 * m.finish(tag);   // tag: 32 bytes
 * @endcode
 */
class Hmac {
 public:
  static constexpr size_t TagSize = 32;  ///< Tag length in bytes.

  /** Creates an HMAC object with an empty key. Call start() before use. */
  Hmac() : Hmac(nullptr, 0) {}

  /** Starts an HMAC computation with the given key. */
  Hmac(const uint8_t *key, size_t key_len) { start(key, key_len); }

  ~Hmac() { memset(opad_, 0, sizeof(opad_)); }

  /** Restarts the computation with a new key. */
  void start(const uint8_t *key, size_t key_len) {
    // The padded key is built in opad_ first, then turned into the outer and inner pads.
    memset(opad_, 0, sizeof(opad_));
    if (key_len > Sha256::BlockSize) {
      Sha256 h;
      h.digest(key, key_len, opad_);  // the 32-byte digest; the rest stays zero
    } else if (key_len) {
      memcpy(opad_, key, key_len);
    }
    for (size_t i = 0; i < Sha256::BlockSize; i++) {
      uint8_t k = opad_[i];
      opad_[i] = k ^ 0x5c;
      pad_[i] = k ^ 0x36;
    }
    inner_.reset();
    inner_.update(pad_, sizeof(pad_));
    memset(pad_, 0, sizeof(pad_));
  }

  /** Feeds data into the MAC. */
  void update(const uint8_t *data, size_t len) { inner_.update(data, len); }

  /** Completes the MAC and writes the 32-byte tag. */
  void finish(uint8_t tag[TagSize]) {
    uint8_t inner_hash[32];
    inner_.finish(inner_hash);
    Sha256 outer;
    outer.update(opad_, sizeof(opad_));
    outer.update(inner_hash, sizeof(inner_hash));
    outer.finish(tag);
  }

  /** Computes HMAC-SHA256 of a buffer in one call. */
  void compute(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len,
               uint8_t tag[TagSize]) {
    start(key, key_len);
    update(data, len);
    finish(tag);
  }

 private:
  Sha256 inner_;
  uint8_t opad_[Sha256::BlockSize];  ///< Outer pad (key XOR 0x5c).
  uint8_t pad_[Sha256::BlockSize];   ///< Inner pad, used only while starting.
};

/**
 * HMAC-based key derivation (RFC 5869) and the TLS 1.3 secret helpers (RFC 8446 section 7.1).
 *
 * The class provides the steps of the TLS 1.3 key schedule:
 * - extract() derives a pseudorandom key (PRK) from salt and input key material,
 * - expand() derives output keying material of up to 8160 bytes,
 * - expandLabel() and deriveSecret() add the "tls13 " label and the transcript
 *   context that TLS 1.3 requires.
 *
 * The object only owns scratch buffers, so one instance can serve a whole handshake.
 *
 * @code
 * Hkdf hk;
 * uint8_t prk[32], key[16];
 * hk.extract(salt, salt_len, ikm, ikm_len, prk);
 * hk.expandLabel(prk, "key", nullptr, 0, key, sizeof(key));
 * @endcode
 */
class Hkdf {
 public:
  /** Creates the helper; it owns a small heap buffer for the label structure. */
  Hkdf() : info_(2 + 1 + 6 + 249 + 1 + 255) {}

  /** HKDF-Extract: prk = HMAC(salt, ikm). An empty salt means HashLen zeros. */
  void extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
               uint8_t prk[32]) {
    const uint8_t zeros[32] = {0};
    if (salt == nullptr || salt_len == 0) {
      salt = zeros;
      salt_len = sizeof(zeros);
    }
    hmac_.compute(salt, salt_len, ikm, ikm_len, prk);
  }

  /** HKDF-Expand: derives out_len bytes from prk. Returns false if out_len is too large. */
  bool expand(const uint8_t prk[32], const uint8_t *info, size_t info_len, uint8_t *out,
              size_t out_len) {
    if (out_len > 255 * 32) return false;
    uint8_t t[32];
    size_t t_len = 0, done = 0;
    uint8_t counter = 1;
    while (done < out_len) {
      hmac_.start(prk, 32);
      hmac_.update(t, t_len);
      hmac_.update(info, info_len);
      hmac_.update(&counter, 1);
      hmac_.finish(t);
      t_len = 32;
      size_t n = out_len - done < 32 ? out_len - done : 32;
      memcpy(out + done, t, n);
      done += n;
      counter++;
    }
    memset(t, 0, sizeof(t));
    return true;
  }

  /** HKDF-Expand-Label (RFC 8446 section 7.1); the label gets the "tls13 " prefix. */
  bool expandLabel(const uint8_t secret[32], const char *label, const uint8_t *context,
                   size_t context_len, uint8_t *out, size_t out_len) {
    const char prefix[] = "tls13 ";
    size_t label_len = strlen(label);
    size_t full_label_len = sizeof(prefix) - 1 + label_len;
    if (full_label_len > 255 || context_len > 255 || out_len > 0xFFFF) return false;

    uint8_t *info = info_.data();
    size_t p = 0;
    info[p++] = (uint8_t)(out_len >> 8);
    info[p++] = (uint8_t)out_len;
    info[p++] = (uint8_t)full_label_len;
    memcpy(info + p, prefix, sizeof(prefix) - 1);
    p += sizeof(prefix) - 1;
    memcpy(info + p, label, label_len);
    p += label_len;
    info[p++] = (uint8_t)context_len;
    if (context_len) memcpy(info + p, context, context_len);
    p += context_len;

    uint8_t prk[32];
    memcpy(prk, secret, 32);
    bool rc = expand(prk, info, p, out, out_len);
    memset(prk, 0, sizeof(prk));
    return rc;
  }

  /** Derive-Secret (RFC 8446 section 7.1): expandLabel over a transcript hash. */
  bool deriveSecret(const uint8_t secret[32], const char *label,
                    const uint8_t transcript_hash[32], uint8_t out[32]) {
    return expandLabel(secret, label, transcript_hash, 32, out, 32);
  }

 private:
  Hmac hmac_{nullptr, 0};
  HeapArray<uint8_t> info_;  ///< HkdfLabel buffer (heap, not stack).
};

}  // namespace tinytls
