/**
 * @file drbg.h
 * Deterministic random bit generator seeded from an Entropy pool.
 */
#pragma once

#include <string.h>
#include "chacha20.h"
#include "config.h"
#include "entropy.h"
#include "sha256.h"

namespace tinytls {

/**
 * @brief Deterministic random bit generator (ChaCha20-based).
 *
 * seed() takes 48 bytes from an Entropy pool and derives a 256-bit key. random()
 * produces output under the current key and then rekeys with the next 32
 * keystream bytes, so a later compromise of the state does not reveal earlier
 * output. Calls fail until seed() succeeds.
 *
 * The TLS session uses the generator for the ClientHello random, the session ID
 * and the X25519 private key.
 *
 * @code
 * Entropy entropy;
 * Drbg drbg;
 * drbg.seed(entropy);
 * uint8_t key[32];
 * drbg.random(key, sizeof(key));
 * @endcode
 */
class Drbg {
 public:
  /** Creates an unseeded generator. */
  Drbg() : seeded_(false) { memset(key_, 0, sizeof(key_)); }

  /** Wipes the key. */
  ~Drbg() { memset(key_, 0, sizeof(key_)); }

  Drbg(const Drbg &) = delete;
  Drbg &operator=(const Drbg &) = delete;

  /** Seeds from 48 bytes of entropy and an optional personalisation string. */
  bool seed(Entropy &entropy, const uint8_t *custom = nullptr, size_t len = 0) {
    uint8_t material[48];
    if (!entropy.getBytes(material, sizeof(material))) return false;
    Sha256 h;
    h.update(material, sizeof(material));
    if (custom && len) h.update(custom, len);
    h.finish(key_);
    memset(material, 0, sizeof(material));
    seeded_ = true;
    return true;
  }

  /** Fills out with pseudo-random bytes. Returns false if the generator is not seeded. */
  bool random(uint8_t *out, size_t len) {
    if (!seeded_) return false;
    static const uint8_t nonce[12] = {0};
    static const uint8_t zeros[64] = {0};
    ChaCha20 c;
    c.setKey(key_);
    c.start(nonce, 0);
    size_t done = 0;
    while (done < len) {
      size_t n = len - done < 64 ? len - done : 64;
      c.update(n, zeros, out + done);
      done += n;
    }
    c.update(32, zeros, key_);  // rekey
    return true;
  }

  /** True once seed() has succeeded. */
  bool seeded() const { return seeded_; }

 private:
  uint8_t key_[32];
  bool seeded_;
};

}  // namespace tinytls
