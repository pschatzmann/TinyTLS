/**
 * @file gcm.h
 * AES-GCM authenticated encryption (NIST SP 800-38D).
 */
#pragma once

#include <string.h>
#include "aes.h"
#include "config.h"

namespace tinytls {

/**
 * @brief AES-GCM authenticated encryption (NIST SP 800-38D).
 *
 * Call setKey() once with a 16- or 32-byte AES key, then encrypt() or decrypt()
 * for each message. Any IV length is accepted; 12 bytes is the case used by
 * TLS 1.3. encrypt() and decrypt() may work in place. decrypt() verifies the tag
 * in constant time before it releases any plaintext, and it zeros the output on
 * failure.
 *
 * @code
 * Gcm g;
 * g.setKey(key, 128);
 * g.encrypt(iv, 12, aad, aad_len, plain, n, cipher, tag);
 * Error rc = g.decrypt(iv, 12, aad, aad_len, cipher, n, tag, plain);
 * @endcode
 *
 * @note GHASH is bit-serial: the code is small, but throughput on a 240 MHz
 * microcontroller is only a few hundred kilobytes per second.
 */
class Gcm {
 public:
  static constexpr size_t TagSize = 16;  ///< Tag length in bytes.

  /** Creates a context without a key. */
  Gcm() { memset(h_, 0, sizeof(h_)); }

  /** Sets the AES key (128 or 256 bits) and derives the GHASH subkey. */
  bool setKey(const uint8_t *key, unsigned keybits) {
    if (!aes_.setKey(key, keybits)) return false;
    memset(h_, 0, 16);
    aes_.encryptBlock(h_, h_);
    return true;
  }

  /**
   * Encrypts input into output and writes the tag. input and output may alias.
   */
  bool encrypt(const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
               const uint8_t *input, size_t length, uint8_t *output, uint8_t tag[TagSize]) const {
    if (iv_len == 0 || (length && (input == nullptr || output == nullptr))) return false;
    uint8_t j0[16];
    computeJ0(iv, iv_len, j0);
    ctr(j0, length, input, output);
    tagOf(j0, aad, aad_len, output, length, tag);
    return true;
  }

  /**
   * Verifies the tag in constant time and then decrypts. On failure the output
   * is zeroed and AuthenticationFailed is returned.
   */
  Error decrypt(const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len,
                const uint8_t *input, size_t length, const uint8_t tag[TagSize],
                uint8_t *output) const {
    if (iv_len == 0 || (length && (input == nullptr || output == nullptr))) return Error::BadInput;
    uint8_t j0[16], expected[16];
    computeJ0(iv, iv_len, j0);
    tagOf(j0, aad, aad_len, input, length, expected);
    uint8_t diff = 0;
    for (size_t i = 0; i < TagSize; i++) diff |= (uint8_t)(expected[i] ^ tag[i]);
    if (diff != 0) {
      if (length) memset(output, 0, length);
      return Error::AuthenticationFailed;
    }
    ctr(j0, length, input, output);
    return Error::Ok;
  }

 private:
  void gfMult(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]) const {
    uint8_t zz[16] = {0}, v[16];
    memcpy(v, y, 16);
    for (int i = 0; i < 128; i++) {
      if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
        for (int j = 0; j < 16; j++) zz[j] ^= v[j];
      }
      uint8_t lsb = v[15] & 1;
      for (int j = 15; j > 0; j--) v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
      v[0] >>= 1;
      if (lsb) v[0] ^= 0xe1;
    }
    memcpy(z, zz, 16);
    memset(zz, 0, sizeof(zz));
    memset(v, 0, sizeof(v));
  }

  void ghash(const uint8_t *a, size_t alen, const uint8_t *c, size_t clen, uint8_t out[16]) const {
    uint8_t y[16] = {0}, blk[16];
    for (int pass = 0; pass < 2; pass++) {
      const uint8_t *data = pass == 0 ? a : c;
      size_t len = pass == 0 ? alen : clen;
      while (len > 0) {
        size_t n = len < 16 ? len : 16;
        memset(blk, 0, 16);
        memcpy(blk, data, n);
        for (int j = 0; j < 16; j++) y[j] ^= blk[j];
        gfMult(y, h_, y);
        data += n;
        len -= n;
      }
    }
    uint64_t abits = (uint64_t)alen * 8, cbits = (uint64_t)clen * 8;
    for (int i = 0; i < 8; i++) {
      blk[i] = (uint8_t)(abits >> (56 - 8 * i));
      blk[8 + i] = (uint8_t)(cbits >> (56 - 8 * i));
    }
    for (int j = 0; j < 16; j++) y[j] ^= blk[j];
    gfMult(y, h_, out);
  }

  void computeJ0(const uint8_t *iv, size_t iv_len, uint8_t j0[16]) const {
    if (iv_len == 12) {
      memcpy(j0, iv, 12);
      j0[12] = j0[13] = j0[14] = 0;
      j0[15] = 1;
    } else {
      ghash(nullptr, 0, iv, iv_len, j0);
    }
  }

  void inc32(uint8_t counter[16]) const {
    for (int i = 15; i >= 12; i--) {
      if (++counter[i] != 0) break;
    }
  }

  void ctr(const uint8_t j0[16], size_t length, const uint8_t *input, uint8_t *output) const {
    uint8_t counter[16], ks[16];
    memcpy(counter, j0, 16);
    inc32(counter);
    size_t done = 0;
    while (done < length) {
      aes_.encryptBlock(counter, ks);
      size_t n = length - done < 16 ? length - done : 16;
      for (size_t i = 0; i < n; i++) output[done + i] = input[done + i] ^ ks[i];
      inc32(counter);
      done += n;
    }
    memset(ks, 0, sizeof(ks));
  }

  void tagOf(const uint8_t j0[16], const uint8_t *aad, size_t aad_len, const uint8_t *ct,
             size_t length, uint8_t tag[16]) const {
    uint8_t ks[16];
    ghash(aad, aad_len, ct, length, tag);
    aes_.encryptBlock(j0, ks);
    for (int i = 0; i < 16; i++) tag[i] ^= ks[i];
    memset(ks, 0, sizeof(ks));
  }

  Aes aes_;
  uint8_t h_[16];
};

}  // namespace tinytls
