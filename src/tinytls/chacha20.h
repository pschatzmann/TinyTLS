/**
 * @file chacha20.h
 * ChaCha20 stream cipher (RFC 8439 sections 2.3 and 2.4).
 */
#pragma once

#include <string.h>
#include "config.h"

namespace tinytls {

/**
 * @brief ChaCha20 stream cipher (RFC 8439 sections 2.3 and 2.4).
 *
 * A keystream generator with a 256-bit key, a 96-bit nonce and a 32-bit block
 * counter. update() XORs keystream into data and can be called repeatedly, so a
 * stream can be processed in pieces. crypt() is a one-shot convenience.
 *
 * Never reuse a nonce with the same key: the keystream is then identical, and
 * an attacker can recover the XOR of the two plaintexts.
 *
 * @code
 * ChaCha20 c;
 * c.setKey(key);
 * c.start(nonce, 1);
 * c.update(n, in, out);
 * @endcode
 */
class ChaCha20 {
 public:
  static constexpr size_t KeySize = 32;    ///< Key size in bytes.
  static constexpr size_t NonceSize = 12;  ///< Nonce size in bytes.
  static constexpr size_t BlockSize = 64;  ///< Keystream block size in bytes.

  /** Creates a cipher without a key. */
  ChaCha20() : keystream_offset_(BlockSize) {
    memset(state_, 0, sizeof(state_));
    memset(keystream_, 0, sizeof(keystream_));
  }

  ~ChaCha20() {
    memset(state_, 0, sizeof(state_));
    memset(keystream_, 0, sizeof(keystream_));
  }

  /** Loads the 256-bit key. */
  void setKey(const uint8_t key[32]) {
    state_[0] = 0x61707865;
    state_[1] = 0x3320646e;
    state_[2] = 0x79622d32;
    state_[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) state_[4 + i] = le32(key + 4 * i);
  }

  /** Sets the nonce and the initial block counter, and discards buffered keystream. */
  void start(const uint8_t nonce[12], uint32_t counter) {
    state_[12] = counter;
    for (int i = 0; i < 3; i++) state_[13 + i] = le32(nonce + 4 * i);
    keystream_offset_ = BlockSize;
  }

  /** XORs keystream into input, continuing across calls. input and output may alias. */
  void update(size_t size, const uint8_t *input, uint8_t *output) {
    for (size_t i = 0; i < size; i++) {
      if (keystream_offset_ >= BlockSize) {
        block(state_, keystream_);
        state_[12]++;
        keystream_offset_ = 0;
      }
      output[i] = input[i] ^ keystream_[keystream_offset_++];
    }
  }

  /** One-shot keystream XOR with the given key, nonce and counter. */
  void crypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, size_t size,
             const uint8_t *input, uint8_t *output) {
    setKey(key);
    start(nonce, counter);
    update(size, input, output);
  }

 private:
  /** Produces one 64-byte block from a 16-word state. */
  void block(const uint32_t state[16], uint8_t out[64]) const {
    uint32_t x[16];
    memcpy(x, state, sizeof(x));
    for (int i = 0; i < 10; i++) {
      qr(x, 0, 4, 8, 12);
      qr(x, 1, 5, 9, 13);
      qr(x, 2, 6, 10, 14);
      qr(x, 3, 7, 11, 15);
      qr(x, 0, 5, 10, 15);
      qr(x, 1, 6, 11, 12);
      qr(x, 2, 7, 8, 13);
      qr(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
      uint32_t v = x[i] + state[i];
      out[4 * i] = (uint8_t)v;
      out[4 * i + 1] = (uint8_t)(v >> 8);
      out[4 * i + 2] = (uint8_t)(v >> 16);
      out[4 * i + 3] = (uint8_t)(v >> 24);
    }
  }

  uint32_t rotl(uint32_t x, unsigned n) const { return (x << n) | (x >> (32 - n)); }
  uint32_t le32(const uint8_t *p) const {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  }
  void qr(uint32_t *x, int a, int b, int c, int d) const {
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
  }

  uint32_t state_[16];
  uint8_t keystream_[64];
  size_t keystream_offset_;
};

}  // namespace tinytls
