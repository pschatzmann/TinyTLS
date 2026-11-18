/**
 * @file x25519.h
 * X25519 Diffie-Hellman key agreement (RFC 7748).
 */
#pragma once

#include <string.h>
#include "config.h"
#include "heap.h"

namespace tinytls {

/**
 * @brief X25519 Diffie-Hellman key agreement on Curve25519 (RFC 7748).
 *
 * The Montgomery ladder works on the u-coordinate only. publicKey() computes the
 * public key for a 32-byte private scalar, and scalarmult() computes the shared
 * secret with a peer's public key. Both return false for an all-zero result,
 * which a low-order peer key produces. The caller must reject that case.
 *
 * Scalars are clamped as the RFC requires, so any 32 random bytes are a valid private key.
 *
 * @code
 * X25519 x;
 * uint8_t pub[32], shared[32];
 * x.publicKey(priv, pub);
 * if (!x.scalarmult(shared, priv, peer_pub)) { // low-order peer key }
 * @endcode
 */
class X25519 {
 public:
  static constexpr size_t KeySize = 32;  ///< Key and point size in bytes.

  /**
   * Computes q = n * p. Returns false when the result is the all-zero point,
   * which indicates a low-order input that must be rejected.
   */
  bool scalarmult(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]) {
    uint8_t z[32];
    // Field workspace on the heap: x[80] followed by the six field elements a..f.
    HeapArray<int64_t> work(80 + 6 * 16);
    int64_t *x = work.data();
    int64_t *a = x + 80, *b = a + 16, *c = b + 16, *d = c + 16, *e = d + 16, *f = e + 16;
    memcpy(z, n, 31);
    z[31] = (uint8_t)((n[31] & 127) | 64);
    z[0] &= 248;

    unpack(x, p);
    for (int i = 0; i < 16; i++) {
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (int i = 254; i >= 0; --i) {
      int r = (z[i >> 3] >> (i & 7)) & 1;
      sel(a, b, r);
      sel(c, d, r);
      add(e, a, c);
      sub(a, a, c);
      add(c, b, d);
      sub(b, b, d);
      mul(d, e, e);
      mul(f, a, a);
      mul(a, c, a);
      mul(c, b, e);
      add(e, a, c);
      sub(a, a, c);
      mul(b, a, a);
      sub(c, d, f);
      mul(a, c, a121665());
      add(a, a, d);
      mul(c, c, a);
      mul(a, d, f);
      mul(d, b, x);
      mul(b, e, e);
      sel(a, b, r);
      sel(c, d, r);
    }
    for (int i = 0; i < 16; i++) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }
    inv(x + 32, x + 32);
    mul(x + 16, x + 16, x + 32);
    pack(q, x + 16);

    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= q[i];
    memset(z, 0, sizeof(z));
    return acc != 0;
  }

  /** Computes the public key pub = priv * 9 from a 32-byte private scalar. */
  bool publicKey(const uint8_t priv[32], uint8_t pub[32]) {
    static const uint8_t base[32] = {9};
    return scalarmult(pub, priv, base);
  }

 private:
  typedef int64_t Gf[16];

  const Gf &a121665() const {
    static const Gf value = {0xDB41, 1};
    return value;
  }

  void car(Gf o) const {
    for (int i = 0; i < 16; i++) {
      o[i] += (1LL << 16);
      int64_t c = o[i] >> 16;
      o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
      o[i] -= c * (1LL << 16);  // multiplication: left-shifting a negative value is undefined before C++20
    }
  }

  void sel(Gf p, Gf q, int b) const {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
      int64_t t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }

  void unpack(int64_t *o, const uint8_t n[32]) const {
    for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
  }

  void pack(uint8_t o[32], const Gf n) const {
    Gf m, t;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    car(t);
    car(t);
    car(t);
    for (int j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (int i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      int b = (int)((m[15] >> 16) & 1);
      m[14] &= 0xffff;
      sel(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
      o[2 * i] = (uint8_t)(t[i] & 0xff);
      o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
  }

  void mul(Gf o, const Gf a, const Gf b) const {
    int64_t t[31];
    memset(t, 0, sizeof(t));
    for (int i = 0; i < 16; i++) {
      for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    }
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car(o);
    car(o);
  }

  void add(Gf o, const Gf a, const Gf b) const {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
  }

  void sub(Gf o, const Gf a, const Gf b) const {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
  }

  void inv(Gf o, const Gf i) const {
    Gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
      mul(c, c, c);
      if (a != 2 && a != 4) mul(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
  }
};

}  // namespace tinytls
