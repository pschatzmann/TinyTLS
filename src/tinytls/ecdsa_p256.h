/**
 * @file ecdsa_p256.h
 * ECDSA signature verification on NIST P-256 (FIPS 186-4).
 */
#pragma once

#include <memory>
#include "bignum.h"
#include "config.h"
#include "heap.h"

namespace tinytls {

/**
 * ECDSA signature verification on NIST P-256 (secp256r1, FIPS 186-4).
 *
 * Construct the object once; it sets up the curve constants. ready() reports
 * whether the setup succeeded. verify() can then be called for each signature.
 * Points are computed in Jacobian coordinates in Montgomery form, so the only
 * field inversion is the final conversion to affine coordinates. The public key
 * is checked to lie on the curve.
 *
 * Only verification is implemented. It works on public data only and is not
 * constant-time, which is acceptable for verification.
 *
 * @code
 * EcdsaP256 curve;
 * Error rc = curve.verify(x, y, digest, 32, r, s);   // x, y, r, s: 32 bytes each
 * @endcode
 */
class EcdsaP256 {
 public:
  /** Creates a verifier and sets up the curve constants. Check ready() afterwards. */
  EcdsaP256() : ready_(init()) {}

  /** True if the curve constants were set up successfully. */
  bool ready() const { return ready_; }

  /**
   * Verifies a signature over a digest.
   *
   * @param x,y       Public key coordinates (32 bytes each, big-endian).
   * @param digest     Message digest.
   * @param digest_len Length of digest in bytes; the leftmost 32 bytes are used.
   * @param r,s       Signature values (32 bytes each, big-endian).
   * @return Error::Ok when the signature is valid, otherwise an error.
   */
  Error verify(const uint8_t x[32], const uint8_t y[32], const uint8_t *digest, size_t digest_len,
               const uint8_t r[32], const uint8_t s[32]) const {
    if (!ready_) return Error::Internal;
    return verifyWith(x, y, digest, digest_len, r, s);
  }

 private:
  /** Jacobian point (X:Y:Z) in Montgomery form; Z = 0 is the point at infinity. */
  struct Point {
    BigInt X, Y, Z;
  };

  BigInt hex(const char *h) const {
    HeapArray<uint8_t> buf_store(TINYTLS_MPI_MAX_LIMBS * 4);
    uint8_t *buf = buf_store.data();
    size_t len = strlen(h) / 2;
    for (size_t i = 0; i < len; i++) {
      buf[i] = (uint8_t)((nibble(h[2 * i]) << 4) | nibble(h[2 * i + 1]));
    }
    BigInt v;
    v.fromBytes(buf, len);
    return v;
  }

  uint8_t nibble(char c) const {
    return (uint8_t)(c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0');
  }

  bool init() {
    BigInt p = hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    BigInt n = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    BigInt b = hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    BigInt gx = hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    BigInt gy = hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    if (!fp_.init(p) || !fn_.init(n)) return false;
    bm_ = fp_.enter(b);
    g_.X = fp_.enter(gx);
    g_.Y = fp_.enter(gy);
    g_.Z = fp_.one();
    return true;
  }

  /** R = 2P for a = -3 (dbl-2001-b). */
  void dbl(const Point &P, Point &R) const {
    if (P.Z.isZero() || P.Y.isZero()) {
      R.Z = BigInt();
      return;
    }
    const Montgomery &f = fp_;
    BigInt delta, gamma, beta, alpha, t1, t2, X3, Y3, Z3;
    f.mul(P.Z, P.Z, delta);
    f.mul(P.Y, P.Y, gamma);
    f.mul(P.X, gamma, beta);
    f.subMod(P.X, delta, t1);
    f.addMod(P.X, delta, t2);
    f.mul(t1, t2, alpha);
    f.addMod(alpha, alpha, t1);
    f.addMod(alpha, t1, alpha);              // alpha = 3 (X - delta)(X + delta)
    f.mul(alpha, alpha, t1);
    f.addMod(beta, beta, t2);
    f.addMod(t2, t2, t2);
    f.addMod(t2, t2, t2);                    // 8 beta
    f.subMod(t1, t2, X3);
    f.addMod(P.Y, P.Z, t1);
    f.mul(t1, t1, t1);
    f.subMod(t1, gamma, t1);
    f.subMod(t1, delta, Z3);
    f.addMod(beta, beta, t1);
    f.addMod(t1, t1, t1);                    // 4 beta
    f.subMod(t1, X3, t1);
    f.mul(alpha, t1, t1);
    f.mul(gamma, gamma, t2);
    f.addMod(t2, t2, t2);
    f.addMod(t2, t2, t2);
    f.addMod(t2, t2, t2);                    // 8 gamma^2
    f.subMod(t1, t2, Y3);
    R.X = X3;
    R.Y = Y3;
    R.Z = Z3;
  }

  /** R = P + Q (general Jacobian addition). */
  void add(const Point &P, const Point &Q, Point &R) const {
    if (P.Z.isZero()) {
      R = Q;
      return;
    }
    if (Q.Z.isZero()) {
      R = P;
      return;
    }
    const Montgomery &f = fp_;
    BigInt Z1Z1, Z2Z2, U1, U2, S1, S2, H, r, t;
    f.mul(P.Z, P.Z, Z1Z1);
    f.mul(Q.Z, Q.Z, Z2Z2);
    f.mul(P.X, Z2Z2, U1);
    f.mul(Q.X, Z1Z1, U2);
    f.mul(Q.Z, Z2Z2, t);
    f.mul(P.Y, t, S1);
    f.mul(P.Z, Z1Z1, t);
    f.mul(Q.Y, t, S2);
    f.subMod(U2, U1, H);
    f.subMod(S2, S1, r);
    f.addMod(r, r, r);
    if (H.isZero()) {
      if (r.isZero()) {
        dbl(P, R);
      } else {
        R.Z = BigInt();
      }
      return;
    }
    BigInt I, J, V, X3, Y3, Z3;
    f.addMod(H, H, t);
    f.mul(t, t, I);
    f.mul(H, I, J);
    f.mul(U1, I, V);
    f.mul(r, r, X3);
    f.subMod(X3, J, X3);
    f.addMod(V, V, t);
    f.subMod(X3, t, X3);
    f.subMod(V, X3, t);
    f.mul(r, t, Y3);
    f.mul(S1, J, t);
    f.addMod(t, t, t);
    f.subMod(Y3, t, Y3);
    f.addMod(P.Z, Q.Z, Z3);
    f.mul(Z3, Z3, Z3);
    f.subMod(Z3, Z1Z1, Z3);
    f.subMod(Z3, Z2Z2, Z3);
    f.mul(Z3, H, Z3);
    R.X = X3;
    R.Y = Y3;
    R.Z = Z3;
  }

  /** R = k * P (double-and-add from the most significant bit). */
  void mul(const BigInt &k, const Point &P, Point &R) const {
    Point acc;
    acc.Z = BigInt();
    size_t bits = k.bitLength();
    for (size_t i = bits; i-- > 0;) {
      dbl(acc, acc);
      if (k.testBit(i)) add(acc, P, acc);
    }
    R = acc;
  }

  /** True if the affine point (x, y), given in the normal domain, satisfies y^2 = x^3 - 3x + b. */
  bool onCurve(const BigInt &x, const BigInt &y) const {
    const Montgomery &f = fp_;
    BigInt xm = f.enter(x), ym = f.enter(y), lhs, rhs, t;
    f.mul(ym, ym, lhs);
    f.mul(xm, xm, rhs);
    f.mul(rhs, xm, rhs);
    f.addMod(xm, xm, t);
    f.addMod(t, xm, t);
    f.subMod(rhs, t, rhs);
    f.addMod(rhs, bm_, rhs);
    return lhs.compare(rhs) == 0;
  }

  /** Working values of one verification, allocated on the heap. */
  struct Workspace {
    BigInt qx, qy, r, s, e, two, nm2, w, t, u1, u2, pm2, zn, zinv, x;
    Point Q, G1, G2, R;
  };

  Error verifyWith(const uint8_t qx_b[32], const uint8_t qy_b[32], const uint8_t *digest,
                   size_t digest_len, const uint8_t r_b[32], const uint8_t s_b[32]) const {
    const Montgomery &fn = fn_;
    std::unique_ptr<Workspace> ws(new Workspace());
    BigInt &qx = ws->qx, &qy = ws->qy, &r = ws->r, &s = ws->s, &e = ws->e, &two = ws->two,
           &nm2 = ws->nm2, &w = ws->w, &t = ws->t, &u1 = ws->u1, &u2 = ws->u2, &pm2 = ws->pm2,
           &zn = ws->zn, &zinv = ws->zinv, &x = ws->x;
    Point &Q = ws->Q, &G1 = ws->G1, &G2 = ws->G2, &R = ws->R;

    qx.fromBytes(qx_b, 32);
    qy.fromBytes(qy_b, 32);
    if (qx.compare(fp_.modulus()) >= 0 || qy.compare(fp_.modulus()) >= 0 || !onCurve(qx, qy)) {
      return Error::EcdsaBadInput;
    }
    r.fromBytes(r_b, 32);
    s.fromBytes(s_b, 32);
    if (r.isZero() || s.isZero() || r.compare(fn.modulus()) >= 0 || s.compare(fn.modulus()) >= 0) {
      return Error::EcdsaVerifyFailed;
    }

    // e = leftmost 256 bits of the digest, reduced mod n.
    e.fromBytes(digest, digest_len < 32 ? digest_len : 32);
    if (e.compare(fn.modulus()) >= 0) e.sub(fn.modulus(), e);

    // w = s^-1 mod n (n is prime), u1 = e w, u2 = r w.
    two = BigInt(2);
    fn.modulus().sub(two, nm2);
    w = fn.powMont(fn.enter(s), nm2);
    fn.mul(fn.enter(r), w, t);
    u2 = fn.leave(t);
    fn.mul(fn.enter(e), w, t);
    u1 = fn.leave(t);

    // R = u1 G + u2 Q
    Q.X = fp_.enter(qx);
    Q.Y = fp_.enter(qy);
    Q.Z = fp_.one();
    mul(u1, g_, G1);
    mul(u2, Q, G2);
    add(G1, G2, R);
    if (R.Z.isZero()) return Error::EcdsaVerifyFailed;

    // x = X / Z^2 (affine), reduced mod n, must equal r.
    fp_.modulus().sub(two, pm2);
    zn = fp_.leave(R.Z);
    zinv = fp_.pow(zn, pm2);
    zinv = fp_.enter(zinv);
    fp_.mul(zinv, zinv, zinv);
    fp_.mul(R.X, zinv, x);
    x = fp_.leave(x);
    if (x.compare(fn.modulus()) >= 0) x.sub(fn.modulus(), x);
    return x.compare(r) == 0 ? Error::Ok : Error::EcdsaVerifyFailed;
  }

  Montgomery fp_;  ///< Field arithmetic modulo p.
  Montgomery fn_;  ///< Arithmetic modulo the group order n.
  BigInt bm_;      ///< Curve coefficient b in Montgomery form.
  Point g_;        ///< Generator in Montgomery form.
  bool ready_;     ///< Declared last: init() fills the members above.
};

}  // namespace tinytls
