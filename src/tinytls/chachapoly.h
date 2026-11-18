/**
 * @file chachapoly.h
 * ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8).
 */
#pragma once

#include <string.h>
#include "chacha20.h"
#include "config.h"
#include "poly1305.h"

namespace tinytls {

/**
 * ChaCha20-Poly1305 authenticated encryption (RFC 8439 section 2.8).
 *
 * The AEAD construction used by TLS_CHACHA20_POLY1305_SHA256. The one-time
 * Poly1305 key comes from the first ChaCha20 block, and the payload is encrypted
 * from block counter 1. Nonces are 12 bytes and tags are 16 bytes.
 *
 * encrypt() and decrypt() work in place. decrypt() verifies the tag in constant
 * time before it produces plaintext, and zeros the output on failure.
 *
 * Never reuse a (key, nonce) pair: that breaks both confidentiality and the authenticator.
 *
 * @code
 * ChaCha20Poly1305 aead;
 * aead.setKey(key);
 * aead.encrypt(nonce, aad, aad_len, plain, n, cipher, tag);
 * Error rc = aead.decrypt(nonce, aad, aad_len, cipher, n, tag, plain);
 * @endcode
 */
class ChaCha20Poly1305 {
 public:
  static constexpr size_t TagSize = 16;  ///< Tag length in bytes.

  /** Creates a context without a key. */
  ChaCha20Poly1305() { memset(key_, 0, sizeof(key_)); }

  ~ChaCha20Poly1305() { memset(key_, 0, sizeof(key_)); }

  /** Stores the 256-bit key. */
  void setKey(const uint8_t key[32]) { memcpy(key_, key, 32); }

  /** Encrypts input into output and writes the tag. input and output may alias. */
  void encrypt(const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *input,
               size_t length, uint8_t *output, uint8_t tag[TagSize]) const {
    uint8_t otk[32];
    oneTimeKey(nonce, otk);
    ChaCha20 cipher;
    cipher.crypt(key_, nonce, 1, length, input, output);
    computeTag(otk, aad, aad_len, output, length, tag);
    memset(otk, 0, sizeof(otk));
  }

  /** Verifies the tag in constant time, then decrypts. On failure the output is zeroed. */
  Error decrypt(const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                const uint8_t *input, size_t length, const uint8_t tag[TagSize],
                uint8_t *output) const {
    uint8_t otk[32], expected[16];
    oneTimeKey(nonce, otk);
    computeTag(otk, aad, aad_len, input, length, expected);
    memset(otk, 0, sizeof(otk));
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(expected[i] ^ tag[i]);
    if (diff != 0) {
      if (length) memset(output, 0, length);
      return Error::AuthenticationFailed;
    }
    ChaCha20 cipher;
    cipher.crypt(key_, nonce, 1, length, input, output);
    return Error::Ok;
  }

 private:
  void oneTimeKey(const uint8_t nonce[12], uint8_t otk[32]) const {
    uint8_t zeros[32] = {0};
    ChaCha20 cipher;
    cipher.crypt(key_, nonce, 0, 32, zeros, otk);
  }

  void computeTag(const uint8_t otk[32], const uint8_t *aad, size_t aad_len, const uint8_t *ct,
                  size_t ct_len, uint8_t tag[16]) const {
    const uint8_t pad[16] = {0};
    Poly1305 p;
    p.setKey(otk);
    p.update(aad, aad_len);
    p.update(pad, (16 - (aad_len % 16)) % 16);
    p.update(ct, ct_len);
    p.update(pad, (16 - (ct_len % 16)) % 16);
    uint8_t lens[16];
    for (int i = 0; i < 8; i++) {
      lens[i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
      lens[8 + i] = (uint8_t)((uint64_t)ct_len >> (8 * i));
    }
    p.update(lens, 16);
    p.finish(tag);
  }

  uint8_t key_[32];
};

}  // namespace tinytls
