/**
 * @file bignum.h
 * Unsigned big integers (BigInt) and Montgomery arithmetic (Montgomery) for
 * the signature verification code.
 *
 * BigInt keeps its limbs on the heap, so a BigInt object is a few bytes on the
 * stack and temporaries do not enlarge the call frames. Modular multiplication
 * uses Montgomery reduction (CIOS), so no division is needed. Moduli must be odd.
 */
#pragma once

#include <string.h>
#include "config.h"
#include "heap.h"

namespace tinytls {

class Montgomery;

/**
 * @brief Unsigned integer with a capacity of TINYTLS_MPI_MAX_LIMBS little-endian
 * 32-bit limbs. The limbs live on the heap. Copies allocate their own storage.
 */
class BigInt {
 public:
  /** Capacity in 32-bit limbs. */
  static constexpr size_t MaxLimbs = TINYTLS_MPI_MAX_LIMBS;

  /** Creates the value zero. */
  BigInt() : limb_(MaxLimbs), n_(1) {}

  /** Creates a small value. */
  explicit BigInt(uint32_t v) : limb_(MaxLimbs), n_(1) { limb_[0] = v; }

  /** Copies the value (allocates new storage). */
  BigInt(const BigInt &o) : limb_(MaxLimbs), n_(o.n_) {
    memcpy(limb_.data(), o.limb_.data(), MaxLimbs * sizeof(uint32_t));
  }

  /** Copies the value into existing storage. */
  BigInt &operator=(const BigInt &o) {
    if (this != &o) {
      memcpy(limb_.data(), o.limb_.data(), MaxLimbs * sizeof(uint32_t));
      n_ = o.n_;
    }
    return *this;
  }

  /** Sets the value from a big-endian byte string. Returns false if it does not fit. */
  bool fromBytes(const uint8_t *p, size_t len) {
    size_t limbs = (len + 3) / 4;
    if (limbs == 0) limbs = 1;
    if (limbs > MaxLimbs) return false;
    limb_.wipe();
    n_ = limbs;
    for (size_t i = 0; i < len; i++) {
      size_t bit = len - 1 - i;
      limb_[bit / 4] |= (uint32_t)p[i] << (8 * (bit % 4));
    }
    return true;
  }

  /** Writes the value as a big-endian string of exactly len bytes. Returns false if it does not fit. */
  bool toBytes(uint8_t *out, size_t len) const {
    for (size_t i = 0; i < len; i++) {
      size_t bit = len - 1 - i;
      size_t limb = bit / 4;
      out[i] = limb < n_ ? (uint8_t)(limb_[limb] >> (8 * (bit % 4))) : 0;
    }
    for (size_t l = (len + 3) / 4; l < n_; l++) {
      if (limb_[l]) return false;
    }
    return true;
  }

  /** Number of significant bits. */
  size_t bitLength() const {
    size_t n = significantLimbs();
    uint32_t top = limb_[n - 1];
    if (top == 0) return 0;
    size_t bits = 0;
    while (top) {
      bits++;
      top >>= 1;
    }
    return (n - 1) * 32 + bits;
  }

  /** Returns bit i (0 is the least significant). */
  bool testBit(size_t i) const {
    size_t limb = i / 32;
    return limb < n_ && ((limb_[limb] >> (i % 32)) & 1);
  }

  /** True if the value is zero. */
  bool isZero() const {
    for (size_t i = 0; i < n_; i++) {
      if (limb_[i]) return false;
    }
    return true;
  }

  /** Compares two values: returns -1, 0 or 1. */
  int compare(const BigInt &o) const {
    size_t n = n_ > o.n_ ? n_ : o.n_;
    for (size_t i = n; i-- > 0;) {
      uint32_t x = i < n_ ? limb_[i] : 0;
      uint32_t y = i < o.n_ ? o.limb_[i] : 0;
      if (x != y) return x < y ? -1 : 1;
    }
    return 0;
  }

  /**
   * Computes r = this + b. The width of r is max(this, b). Returns the carry
   * out of the top limb. r may alias this or b: each limb is read before the
   * same index of r is written.
   */
  uint32_t add(const BigInt &b, BigInt &r) const {
    size_t n = n_ > b.n_ ? n_ : b.n_;
    uint64_t carry = 0;
    for (size_t i = 0; i < n; i++) {
      uint64_t s = (uint64_t)(i < n_ ? limb_[i] : 0) + (i < b.n_ ? b.limb_[i] : 0) + carry;
      r.limb_[i] = (uint32_t)s;
      carry = s >> 32;
    }
    for (size_t i = n; i < MaxLimbs; i++) r.limb_[i] = 0;
    r.n_ = n;
    return (uint32_t)carry;
  }

  /**
   * Computes r = this - b. The width of r is max(this, b). Returns 1 when
   * this < b (the result then wraps). r may alias this or b.
   */
  uint32_t sub(const BigInt &b, BigInt &r) const {
    size_t n = n_ > b.n_ ? n_ : b.n_;
    int64_t borrow = 0;
    for (size_t i = 0; i < n; i++) {
      int64_t d = (int64_t)(i < n_ ? limb_[i] : 0) - (int64_t)(i < b.n_ ? b.limb_[i] : 0) - borrow;
      borrow = d < 0 ? 1 : 0;
      r.limb_[i] = (uint32_t)(d + (borrow ? ((int64_t)1 << 32) : 0));
    }
    for (size_t i = n; i < MaxLimbs; i++) r.limb_[i] = 0;
    r.n_ = n;
    return (uint32_t)borrow;
  }

 private:
  friend class Montgomery;

  size_t significantLimbs() const {
    size_t n = n_;
    while (n > 1 && limb_[n - 1] == 0) n--;
    return n;
  }

  HeapArray<uint32_t> limb_;  ///< Little-endian limbs on the heap.
  size_t n_;                  ///< Number of limbs in use (may include leading zeros).
};

/**
 * @brief Modular arithmetic modulo an odd modulus, using Montgomery reduction.
 * Values are kept in Montgomery form (a * R mod m, with R = 2^(32k)) when they
 * are multiplied repeatedly. Not copyable: it owns heap scratch space.
 */
class Montgomery {
 public:
  /** Creates a context without a modulus. Call init() before use. */
  Montgomery() : m_(), rr_(), k_(0), mprime_(0), scratch_(TINYTLS_MPI_MAX_LIMBS + 2) {}

  Montgomery(const Montgomery &) = delete;
  Montgomery &operator=(const Montgomery &) = delete;

  /** Sets the odd modulus. Returns false for an even or zero modulus. */
  bool init(const BigInt &m) {
    if ((m.limb_[0] & 1) == 0 || m.isZero()) return false;
    m_ = m;
    m_.n_ = m.significantLimbs();
    k_ = m_.n_;
    uint32_t m0 = m_.limb_[0], inv = m0;
    for (int i = 0; i < 5; i++) inv *= 2 - m0 * inv;  // Newton: inv = m0^-1 mod 2^32
    mprime_ = (uint32_t)(0u - inv);

    // rr = R^2 mod m, obtained by doubling 1 modulo m 64k times.
    BigInt x(1), mm = m_;
    x.n_ = k_ + 1;
    mm.n_ = k_ + 1;
    for (size_t i = 0; i < 64 * k_; i++) {
      x.add(x, x);
      if (x.compare(mm) >= 0) x.sub(mm, x);
    }
    rr_ = x;
    rr_.n_ = k_;
    return true;
  }

  /** The modulus. */
  const BigInt &modulus() const { return m_; }

  /** Montgomery product r = a * b * R^-1 mod m. a and b must be below m. r may alias a or b. */
  void mul(const BigInt &a, const BigInt &b, BigInt &r) const {
    const size_t k = k_;
    const uint32_t *n = m_.limb_.data();
    uint32_t *t = scratch_.data();
    scratch_.wipe();
    for (size_t i = 0; i < k; i++) {
      uint32_t bi = i < b.n_ ? b.limb_[i] : 0;
      uint64_t c = 0;
      for (size_t j = 0; j < k; j++) {
        uint32_t aj = j < a.n_ ? a.limb_[j] : 0;
        uint64_t s = (uint64_t)t[j] + (uint64_t)aj * bi + c;
        t[j] = (uint32_t)s;
        c = s >> 32;
      }
      uint64_t s = (uint64_t)t[k] + c;
      t[k] = (uint32_t)s;
      t[k + 1] = (uint32_t)(s >> 32);

      uint32_t mi = t[0] * mprime_;
      c = ((uint64_t)t[0] + (uint64_t)mi * n[0]) >> 32;
      for (size_t j = 1; j < k; j++) {
        uint64_t s2 = (uint64_t)t[j] + (uint64_t)mi * n[j] + c;
        t[j - 1] = (uint32_t)s2;
        c = s2 >> 32;
      }
      uint64_t s3 = (uint64_t)t[k] + c;
      t[k - 1] = (uint32_t)s3;
      t[k] = t[k + 1] + (uint32_t)(s3 >> 32);
    }

    // Final conditional subtraction of m.
    bool ge = t[k] != 0;
    if (!ge) {
      ge = true;
      for (size_t i = k; i-- > 0;) {
        if (t[i] != n[i]) {
          ge = t[i] > n[i];
          break;
        }
      }
    }
    if (ge) {
      int64_t borrow = 0;
      for (size_t i = 0; i < k; i++) {
        int64_t d = (int64_t)t[i] - (int64_t)n[i] - borrow;
        borrow = d < 0 ? 1 : 0;
        t[i] = (uint32_t)(d + (borrow ? ((int64_t)1 << 32) : 0));
      }
    }
    for (size_t i = 0; i < BigInt::MaxLimbs; i++) r.limb_[i] = i < k ? t[i] : 0;
    r.n_ = k;
  }

  /** Converts a below-m value into Montgomery form. */
  BigInt enter(const BigInt &a) const {
    BigInt r;
    mul(a, rr_, r);
    return r;
  }

  /** Converts a Montgomery-form value back to the normal domain. */
  BigInt leave(const BigInt &a) const {
    BigInt r, one(1);
    mul(a, one, r);
    return r;
  }

  /** Montgomery form of 1 (that is, R mod m). */
  BigInt one() const { return enter(BigInt(1)); }

  /** base^exp mod m; base and the result are in Montgomery form, exp is a normal integer. */
  BigInt powMont(const BigInt &base_m, const BigInt &exp) const {
    BigInt acc = one();
    size_t bits = exp.bitLength();
    for (size_t i = bits; i-- > 0;) {
      mul(acc, acc, acc);
      if (exp.testBit(i)) mul(acc, base_m, acc);
    }
    return acc;
  }

  /** base^exp mod m for a normal-domain base below m and a normal exponent. */
  BigInt pow(const BigInt &base, const BigInt &exp) const {
    return leave(powMont(enter(base), exp));
  }

  /** r = (a + b) mod m for a, b < m. r may alias a or b. */
  void addMod(const BigInt &a, const BigInt &b, BigInt &r) const {
    // Widen the operands by one limb so that the carry of a + b is kept.
    BigInt wa = a, wb = b, t;
    wa.n_ = m_.n_ + 1;
    wb.n_ = m_.n_ + 1;
    wa.add(wb, t);
    if (t.compare(m_) >= 0) t.sub(m_, t);
    t.n_ = m_.n_;
    r = t;
  }

  /** r = (a - b) mod m for a, b < m. r may alias a or b. */
  void subMod(const BigInt &a, const BigInt &b, BigInt &r) const {
    BigInt t;
    if (a.sub(b, t)) t.add(m_, t);
    t.n_ = m_.n_;
    r = t;
  }

 private:
  BigInt m_;
  BigInt rr_;
  size_t k_;
  uint32_t mprime_;
  mutable HeapArray<uint32_t> scratch_;  ///< Accumulator for mul(), on the heap (scratch space, written by const methods).
};

}  // namespace tinytls
