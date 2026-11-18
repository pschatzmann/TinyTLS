/**
 * @file sha256.h
 * SHA-256 hash function (FIPS 180-4).
 */
#pragma once

#include <string.h>
#include "config.h"

namespace tinytls {

/**
 * Incremental SHA-256 hash (FIPS 180-4).
 *
 * Feed data with update() and read the digest with finish(). For a single
 * buffer, digest() resets the object and hashes it in one call. A Sha256
 * object is a value type: copying it snapshots the running state, which the
 * TLS transcript hash relies on.
 *
 * @code
 * uint8_t out[Sha256::DigestSize];
 * Sha256 h;
 * h.update(part1, n1);
 * h.update(part2, n2);
 * h.finish(out);
 * @endcode
 *
 * @note finish() consumes the state. Call reset() before reusing the object.
 */
class Sha256 {
 public:
  static constexpr size_t DigestSize = 32;   ///< Digest length in bytes.
  static constexpr size_t BlockSize = 64;    ///< Block length in bytes.

  /** Creates a hash in the initial state. */
  Sha256() { reset(); }

  /** Resets the hash to the initial state. */
  void reset() {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(state_, iv, sizeof(iv));
    total_len_ = 0;
    memset(buffer_, 0, sizeof(buffer_));
  }

  /** Feeds len bytes into the hash. */
  void update(const uint8_t *data, size_t len) {
    if (len == 0) return;
    size_t fill = (size_t)(total_len_ % BlockSize);
    total_len_ += len;
    if (fill) {
      size_t need = BlockSize - fill;
      if (len < need) {
        memcpy(buffer_ + fill, data, len);
        return;
      }
      memcpy(buffer_ + fill, data, need);
      compress(buffer_);
      data += need;
      len -= need;
    }
    while (len >= BlockSize) {
      compress(data);
      data += BlockSize;
      len -= BlockSize;
    }
    if (len) memcpy(buffer_, data, len);
  }

  /** Completes the hash and writes the 32-byte digest. The object must be reset before reuse. */
  void finish(uint8_t digest[DigestSize]) {
    uint64_t bits = total_len_ * 8;
    const uint8_t pad = 0x80, zero = 0;
    update(&pad, 1);
    while ((total_len_ % BlockSize) != 56) update(&zero, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    update(len, 8);
    for (int i = 0; i < 8; i++) {
      digest[4 * i] = (uint8_t)(state_[i] >> 24);
      digest[4 * i + 1] = (uint8_t)(state_[i] >> 16);
      digest[4 * i + 2] = (uint8_t)(state_[i] >> 8);
      digest[4 * i + 3] = (uint8_t)state_[i];
    }
  }

  /** Computes the digest of a buffer in one call. Resets this object first. */
  void digest(const uint8_t *data, size_t len, uint8_t out[DigestSize]) {
    reset();
    update(data, len);
    finish(out);
  }

 private:
  uint32_t rotr(uint32_t x, unsigned n) const { return (x >> n) | (x << (32 - n)); }

  void compress(const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    // Rolling 16-word message schedule: only 64 bytes of stack are used.
    uint32_t w[16];
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
             ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    }
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3], e = state_[4],
             f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; i++) {
      if (i >= 16) {  // w[i & 15] still holds W[i-16]; replace it with W[i]
        uint32_t s0 = rotr(w[(i - 15) & 15], 7) ^ rotr(w[(i - 15) & 15], 18) ^ (w[(i - 15) & 15] >> 3);
        uint32_t s1 = rotr(w[(i - 2) & 15], 17) ^ rotr(w[(i - 2) & 15], 19) ^ (w[(i - 2) & 15] >> 10);
        w[i & 15] = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
      }
      uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = h + s1 + ch + k[i] + w[i & 15];
      uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  uint32_t state_[8];
  uint64_t total_len_;
  uint8_t buffer_[BlockSize];
};

}  // namespace tinytls
