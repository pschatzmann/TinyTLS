/**
 * @file poly1305.h
 * Poly1305 one-time authenticator (RFC 8439 section 2.5).
 */
#pragma once

#include <string.h>
#include "config.h"

namespace tinytls {

/**
 * Poly1305 one-time authenticator (RFC 8439 section 2.5).
 *
 * Poly1305 takes a 32-byte one-time key and produces a 16-byte tag. Each key
 * must be used for one message only. ChaCha20Poly1305 derives that key itself,
 * so applications rarely need this class directly.
 *
 * The arithmetic uses five 26-bit limbs, so every product fits in 64 bits and no
 * 128-bit type is needed. That keeps the class fast on 32-bit microcontrollers.
 *
 * @code
 * Poly1305 p;
 * p.setKey(otk);
 * p.update(data, len);
 * p.finish(tag);
 * @endcode
 */
class Poly1305 {
 public:
  static constexpr size_t KeySize = 32;  ///< One-time key size in bytes.
  static constexpr size_t TagSize = 16;  ///< Tag size in bytes.

  /** Creates an authenticator. Call setKey() before update(). */
  Poly1305() { memset(this, 0, sizeof(*this)); }

  ~Poly1305() { memset(this, 0, sizeof(*this)); }

  /** Sets the one-time key (r and s). */
  void setKey(const uint8_t key[32]) {
    r_[0] = le32(key + 0) & 0x3ffffff;
    r_[1] = (le32(key + 3) >> 2) & 0x3ffff03;
    r_[2] = (le32(key + 6) >> 4) & 0x3ffc0ff;
    r_[3] = (le32(key + 9) >> 6) & 0x3f03fff;
    r_[4] = (le32(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) h_[i] = 0;
    for (int i = 0; i < 4; i++) pad_[i] = le32(key + 16 + 4 * i);
    buflen_ = 0;
  }

  /** Feeds data into the authenticator. */
  void update(const uint8_t *input, size_t ilen) {
    if (ilen == 0) return;
    if (buflen_) {
      size_t want = 16 - buflen_;
      if (want > ilen) want = ilen;
      memcpy(buffer_ + buflen_, input, want);
      buflen_ += want;
      input += want;
      ilen -= want;
      if (buflen_ < 16) return;
      block(buffer_, 1u << 24);
      buflen_ = 0;
    }
    while (ilen >= 16) {
      block(input, 1u << 24);
      input += 16;
      ilen -= 16;
    }
    if (ilen) {
      memcpy(buffer_, input, ilen);
      buflen_ = ilen;
    }
  }

  /** Completes the computation and writes the 16-byte tag. */
  void finish(uint8_t tag[16]) {
    if (buflen_) {
      uint8_t last[16] = {0};
      memcpy(last, buffer_, buflen_);
      last[buflen_] = 1;
      block(last, 0);
      memset(last, 0, sizeof(last));
    }
    uint32_t h0 = h_[0], h1 = h_[1], h2 = h_[2], h3 = h_[3], h4 = h_[4];
    const uint32_t mask = 0x3ffffff;
    uint32_t c = h1 >> 26; h1 &= mask;
    h2 += c; c = h2 >> 26; h2 &= mask;
    h3 += c; c = h3 >> 26; h3 &= mask;
    h4 += c; c = h4 >> 26; h4 &= mask;
    h0 += c * 5; c = h0 >> 26; h0 &= mask;
    h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= mask;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= mask;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= mask;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= mask;
    uint32_t g4 = h4 + c - (1u << 26);
    uint32_t sel = (g4 >> 31) - 1;  // all ones when h >= p
    uint32_t nsel = ~sel;
    h0 = (h0 & nsel) | (g0 & sel);
    h1 = (h1 & nsel) | (g1 & sel);
    h2 = (h2 & nsel) | (g2 & sel);
    h3 = (h3 & nsel) | (g3 & sel);
    h4 = (h4 & nsel) | (g4 & sel);

    uint32_t w0 = h0 | (h1 << 26);
    uint32_t w1 = (h1 >> 6) | (h2 << 20);
    uint32_t w2 = (h2 >> 12) | (h3 << 14);
    uint32_t w3 = (h3 >> 18) | (h4 << 8);
    uint64_t f = (uint64_t)w0 + pad_[0];
    uint32_t out[4];
    out[0] = (uint32_t)f;
    f = (uint64_t)w1 + pad_[1] + (f >> 32);
    out[1] = (uint32_t)f;
    f = (uint64_t)w2 + pad_[2] + (f >> 32);
    out[2] = (uint32_t)f;
    f = (uint64_t)w3 + pad_[3] + (f >> 32);
    out[3] = (uint32_t)f;
    for (int i = 0; i < 4; i++) {
      tag[4 * i] = (uint8_t)out[i];
      tag[4 * i + 1] = (uint8_t)(out[i] >> 8);
      tag[4 * i + 2] = (uint8_t)(out[i] >> 16);
      tag[4 * i + 3] = (uint8_t)(out[i] >> 24);
    }
  }

  /** One-shot MAC of a buffer under a one-time key. */
  void mac(const uint8_t key[32], const uint8_t *input, size_t ilen, uint8_t tag[16]) {
    setKey(key);
    update(input, ilen);
    finish(tag);
  }

 private:
  uint32_t le32(const uint8_t *p) const {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  }

  void block(const uint8_t *m, uint32_t hibit) {
    const uint32_t mask = 0x3ffffff;
    uint32_t r0 = r_[0], r1 = r_[1], r2 = r_[2], r3 = r_[3], r4 = r_[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = h_[0], h1 = h_[1], h2 = h_[2], h3 = h_[3], h4 = h_[4];

    h0 += le32(m + 0) & mask;
    h1 += (le32(m + 3) >> 2) & mask;
    h2 += (le32(m + 6) >> 4) & mask;
    h3 += (le32(m + 9) >> 6) & mask;
    h4 += (le32(m + 12) >> 8) | hibit;

    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 +
                  (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 +
                  (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 +
                  (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
                  (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
                  (uint64_t)h4 * r0;

    uint32_t c = (uint32_t)(d0 >> 26);
    h0 = (uint32_t)d0 & mask;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & mask;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & mask;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & mask;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & mask;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= mask;
    h1 += c;

    h_[0] = h0; h_[1] = h1; h_[2] = h2; h_[3] = h3; h_[4] = h4;
  }

  uint32_t r_[5];
  uint32_t h_[5];
  uint32_t pad_[4];
  uint8_t buffer_[16];
  size_t buflen_;
};

}  // namespace tinytls
