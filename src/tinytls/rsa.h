/**
 * @file rsa.h
 * RSA signature verification with SHA-256: RSASSA-PKCS1-v1_5 (RFC 8017 8.2)
 * and RSASSA-PSS (RFC 8017 8.1) with MGF1 and a 32-byte salt, as used by TLS 1.3.
 */
#pragma once

#include <string.h>
#include "bignum.h"
#include "config.h"
#include "heap.h"
#include "sha256.h"

namespace tinytls {

/**
 * RSA public key with SHA-256 signature verification.
 *
 * Stores the modulus and public exponent as big-endian bytes. Two schemes are
 * supported, as TLS 1.3 uses them:
 * - verifyPkcs1Sha256(): RSASSA-PKCS1-v1_5 (scheme 0x0401),
 * - verifyPssSha256(): RSASSA-PSS with MGF1-SHA256 and a 32-byte salt (scheme 0x0804).
 *
 * The modulus must fit in TINYTLS_MPI_MAX_LIMBS limbs; the default covers RSA-2048.
 *
 * @code
 * RsaPublicKey key;
 * key.set(n, n_len, e, e_len);
 * Error rc = key.verifyPssSha256(digest, sig, sig_len);
 * @endcode
 */
class RsaPublicKey {
 public:
  /** Largest modulus in bytes that can be stored. */
  static constexpr size_t MaxModulusBytes = BigInt::MaxLimbs * 4;

  /** Creates an empty key. */
  RsaPublicKey() : n_len_(0), e_len_(0) {
    memset(n_, 0, sizeof(n_));
    memset(e_, 0, sizeof(e_));
  }

  /** Sets the modulus and exponent (big-endian). Returns false if they do not fit. */
  bool set(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len) {
    if (n_len == 0 || n_len > MaxModulusBytes || e_len == 0 || e_len > sizeof(e_)) return false;
    memcpy(n_, n, n_len);
    n_len_ = n_len;
    memcpy(e_, e, e_len);
    e_len_ = e_len;
    return true;
  }

  /** Modulus length in bytes. */
  size_t modulusBytes() const { return n_len_; }

  /** Verifies an RSASSA-PKCS1-v1_5 signature over a SHA-256 digest. */
  Error verifyPkcs1Sha256(const uint8_t hash[32], const uint8_t *sig, size_t sig_len) const {
    static const uint8_t digest_info[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    size_t k = n_len_;
    if (k < 11 + 19 + 32) return Error::RsaVerifyFailed;
    HeapArray<uint8_t> em_store(MaxModulusBytes);
    uint8_t *em = em_store.data();
    if (publicOp(sig, sig_len, em) != Error::Ok) return Error::RsaVerifyFailed;

    // EM = 00 01 FF..FF 00 DigestInfo H
    const size_t t_len = 19 + 32;
    uint8_t expected[19 + 32];
    memcpy(expected, digest_info, 19);
    memcpy(expected + 19, hash, 32);
    if (em[0] != 0x00 || em[1] != 0x01) return Error::RsaVerifyFailed;
    size_t sep = k - t_len - 1;  // index of the 0x00 separator
    for (size_t i = 2; i < sep; i++) {
      if (em[i] != 0xff) return Error::RsaVerifyFailed;
    }
    if (sep < 10 || em[sep] != 0x00) return Error::RsaVerifyFailed;
    uint8_t diff = 0;
    for (size_t i = 0; i < t_len; i++) diff |= (uint8_t)(em[sep + 1 + i] ^ expected[i]);
    return diff == 0 ? Error::Ok : Error::RsaVerifyFailed;
  }

  /** Verifies an RSASSA-PSS signature (MGF1-SHA256, salt length 32) over a SHA-256 digest. */
  Error verifyPssSha256(const uint8_t hash[32], const uint8_t *sig, size_t sig_len) const {
    const size_t h_len = 32, s_len = 32;
    BigInt n;
    if (!n.fromBytes(n_, n_len_)) return Error::RsaVerifyFailed;
    size_t em_bits = n.bitLength() - 1;
    size_t em_len = (em_bits + 7) / 8;
    size_t k = n_len_;
    if (em_len < h_len + s_len + 2 || k < em_len) return Error::RsaVerifyFailed;

    HeapArray<uint8_t> full_store(MaxModulusBytes);
    uint8_t *full = full_store.data();
    if (publicOp(sig, sig_len, full) != Error::Ok) return Error::RsaVerifyFailed;
    for (size_t i = 0; i < k - em_len; i++) {
      if (full[i] != 0) return Error::RsaVerifyFailed;
    }
    const uint8_t *em = full + (k - em_len);
    if (em[em_len - 1] != 0xbc) return Error::RsaVerifyFailed;

    size_t db_len = em_len - h_len - 1;
    const uint8_t *masked_db = em;
    const uint8_t *h = em + db_len;
    HeapArray<uint8_t> db_store(MaxModulusBytes);
    uint8_t *db = db_store.data();
    mgf1Sha256(h, h_len, db, db_len);
    for (size_t i = 0; i < db_len; i++) db[i] ^= masked_db[i];
    size_t top_bits = 8 * em_len - em_bits;
    db[0] &= (uint8_t)(0xff >> top_bits);

    size_t ps_len = db_len - s_len - 1;
    for (size_t i = 0; i < ps_len; i++) {
      if (db[i] != 0) return Error::RsaVerifyFailed;
    }
    if (db[ps_len] != 0x01) return Error::RsaVerifyFailed;
    const uint8_t *salt = db + ps_len + 1;

    // H' = Hash(8 zero bytes || mHash || salt)
    Sha256 ctx;
    uint8_t zeros[8] = {0};
    ctx.update(zeros, 8);
    ctx.update(hash, 32);
    ctx.update(salt, s_len);
    uint8_t h_prime[32];
    ctx.finish(h_prime);

    uint8_t diff = 0;
    for (size_t i = 0; i < h_len; i++) diff |= (uint8_t)(h[i] ^ h_prime[i]);
    return diff == 0 ? Error::Ok : Error::RsaVerifyFailed;
  }

 private:
  /** Computes s^e mod n into out (k bytes). */
  Error publicOp(const uint8_t *sig, size_t sig_len, uint8_t *out) const {
    BigInt n, s, e, m;
    if (!n.fromBytes(n_, n_len_) || !e.fromBytes(e_, e_len_)) return Error::BadInput;
    if (sig_len != n_len_) return Error::RsaVerifyFailed;
    if (!s.fromBytes(sig, sig_len)) return Error::RsaVerifyFailed;
    Montgomery ctx;
    if (!ctx.init(n)) return Error::BadInput;
    if (s.compare(ctx.modulus()) >= 0) return Error::RsaVerifyFailed;
    m = ctx.pow(s, e);
    return m.toBytes(out, n_len_) ? Error::Ok : Error::RsaVerifyFailed;
  }

  /** MGF1 with SHA-256 (RFC 8017 B.2.1). */
  void mgf1Sha256(const uint8_t *seed, size_t seed_len, uint8_t *mask, size_t mask_len) const {
    size_t done = 0;
    uint32_t counter = 0;
    while (done < mask_len) {
      uint8_t c[4] = {(uint8_t)(counter >> 24), (uint8_t)(counter >> 16), (uint8_t)(counter >> 8),
                      (uint8_t)counter};
      Sha256 h;
      h.update(seed, seed_len);
      h.update(c, 4);
      uint8_t block[32];
      h.finish(block);
      size_t n = mask_len - done < 32 ? mask_len - done : 32;
      memcpy(mask + done, block, n);
      done += n;
      counter++;
    }
  }

  uint8_t n_[MaxModulusBytes];
  size_t n_len_;
  uint8_t e_[8];
  size_t e_len_;
};

}  // namespace tinytls
