/**
 * @file x509.h
 * X.509 certificates (RFC 5280 subset): DER parsing, PEM decoding, trust
 * stores and chain verification for TLS 1.3 server authentication.
 *
 * Supported: ECDSA P-256 keys with ecdsa-with-SHA256, RSA keys up to
 * TINYTLS_MPI_MAX_LIMBS limbs with sha256WithRSAEncryption and RSASSA-PSS
 * (SHA-256, MGF1, salt 32). Hostnames are matched against dNSName entries of
 * subjectAltName only. Issuer and subject are compared as DER encodings.
 */
#pragma once

#include <string.h>
#include <memory>
#include "config.h"
#include "ecdsa_p256.h"
#include "heap.h"
#include "rsa.h"
#include "sha256.h"

namespace tinytls {

namespace detail {

/** Object identifiers (DER content bytes) used by the certificate parser. */
/// Object identifier: id-ecPublicKey (1.2.840.10045.2.1).
static const uint8_t kEcPublicKey[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
/// Object identifier: prime256v1 curve (1.2.840.10045.3.1.7).
static const uint8_t kPrime256v1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
/// Object identifier: rsaEncryption (1.2.840.113549.1.1.1).
static const uint8_t kRsaEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
/// Object identifier: ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
static const uint8_t kEcdsaSha256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
/// Object identifier: sha256WithRSAEncryption (1.2.840.113549.1.1.11).
static const uint8_t kRsaSha256[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
/// Object identifier: RSASSA-PSS (1.2.840.113549.1.1.10).
static const uint8_t kRsaPss[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a};
/// Object identifier: SHA-256 (2.16.840.1.101.3.4.2.1), found in PSS parameters.
static const uint8_t kSha256[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
/// Object identifier: basicConstraints extension (2.5.29.19).
static const uint8_t kBasicConstraints[] = {0x55, 0x1d, 0x13};
/// Object identifier: subjectAltName extension (2.5.29.17).
static const uint8_t kSubjectAltName[] = {0x55, 0x1d, 0x11};

}  // namespace detail

/**
 * Reader for consecutive DER tag-length-value elements.
 *
 * next() returns the tag and content of the next element and advances the reader.
 * expect() does the same and also checks the tag. Both accept the short and long
 * length forms. Multi-byte tags are rejected, because certificates do not use them.
 *
 * The reader copies nothing: returned pointers refer to the buffer given to the constructor.
 *
 * @code
 * DerReader seq(der, der_len);
 * const uint8_t *val; size_t len;
 * if (seq.expect(0x30, val, len)) { // ... }
 * @endcode
 */
class DerReader {
 public:
  /** Creates a reader over len bytes at data. */
  DerReader(const uint8_t *data, size_t len) : p_(data), end_(data + len) {}

  /** Reads the next element. On success val/len point at its content and the reader advances. */
  bool next(uint8_t &tag, const uint8_t *&val, size_t &len) {
    if (p_ >= end_) return false;
    uint8_t t = *p_;
    if ((t & 0x1f) == 0x1f) return false;  // multi-byte tags are not used in certificates
    p_++;
    if (p_ >= end_) return false;
    uint8_t l = *p_++;
    size_t n = 0;
    if (l < 0x80) {
      n = l;
    } else {
      int nb = l & 0x7f;
      if (nb == 0 || nb > 4 || (size_t)(end_ - p_) < (size_t)nb) return false;
      for (int i = 0; i < nb; i++) n = (n << 8) | *p_++;
    }
    if ((size_t)(end_ - p_) < n) return false;
    tag = t;
    val = p_;
    len = n;
    p_ += n;
    return true;
  }

  /** Reads the next element and requires the given tag. */
  bool expect(uint8_t tag, const uint8_t *&val, size_t &len) {
    uint8_t t;
    return next(t, val, len) && t == tag;
  }

  /** Start of the next unread element. */
  const uint8_t *position() const { return p_; }

  /** True when all elements have been read. */
  bool atEnd() const { return p_ >= end_; }

 private:
  const uint8_t *p_;
  const uint8_t *end_;
};

/**
 * Base64 decoder for PEM bodies (RFC 4648).
 *
 * Decodes standard-alphabet text. Whitespace and '=' padding are skipped; any other
 * character is an error. The caller provides the output buffer. Used by
 * CertificateStore::addPem().
 */
class Base64 {
 public:
  /** Decodes text (whitespace ignored) into out. Returns the byte count, or -1 on error. */
  int decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) const {
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
      uint8_t c = in[i];
      int v;
      if (c >= 'A' && c <= 'Z') v = c - 'A';
      else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
      else if (c >= '0' && c <= '9') v = c - '0' + 52;
      else if (c == '+') v = 62;
      else if (c == '/') v = 63;
      else if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
      else return -1;
      acc = (acc << 6) | (uint32_t)v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        if (o >= out_cap) return -1;
        out[o++] = (uint8_t)(acc >> bits);
      }
    }
    return (int)o;
  }
};

/**
 * Public key taken from an X.509 certificate.
 *
 * The key is ECDSA on P-256 (an uncompressed point) or RSA. parse() reads the
 * content of a SubjectPublicKeyInfo structure and rejects other curves and
 * algorithms. verify() checks a signature over a message with the scheme codes
 * that TLS 1.3 uses in CertificateVerify and in certificate signatures:
 * - 0x0403 ECDSA with SHA-256 (DER-encoded signature),
 * - 0x0401 RSASSA-PKCS1-v1_5 with SHA-256,
 * - 0x0804 RSASSA-PSS with SHA-256.
 *
 * A scheme that does not match the key type fails, so schemes cannot be mixed up.
 */
class PublicKey {
 public:
  /** Key algorithm. */
  enum class Type { None, Ec, Rsa };

  /** Creates an empty key. */
  PublicKey() : type_(Type::None) {
    memset(x_, 0, sizeof(x_));
    memset(y_, 0, sizeof(y_));
  }

  /** Key algorithm. */
  Type type() const { return type_; }

  /** Resets to the empty key. */
  void clear() { type_ = Type::None; }

  /** Parses the content of a SubjectPublicKeyInfo SEQUENCE. */
  Error parse(const uint8_t *v, size_t len) {
    type_ = Type::None;
    DerReader r(v, len);
    const uint8_t *av, *bv;
    size_t al, bl;
    if (!r.expect(0x30, av, al)) return Error::X509BadCertificate;
    DerReader alg(av, al);
    const uint8_t *oid, *params_start = nullptr;
    size_t oid_len;
    if (!alg.expect(0x06, oid, oid_len)) return Error::X509BadCertificate;
    params_start = alg.position();
    size_t params_len = (size_t)((av + al) - params_start);
    if (!r.expect(0x03, bv, bl) || bl < 2 || bv[0] != 0) return Error::X509BadCertificate;
    const uint8_t *key = bv + 1;
    size_t key_len = bl - 1;

    if (oidIs(oid, oid_len, detail::kEcPublicKey, sizeof(detail::kEcPublicKey))) {
      DerReader pr(params_start, params_len);
      const uint8_t *curve;
      size_t curve_len;
      if (!pr.expect(0x06, curve, curve_len) ||
          !oidIs(curve, curve_len, detail::kPrime256v1, sizeof(detail::kPrime256v1))) {
        return Error::X509Unsupported;
      }
      if (key_len != 65 || key[0] != 0x04) return Error::X509BadCertificate;
      memcpy(x_, key + 1, 32);
      memcpy(y_, key + 33, 32);
      type_ = Type::Ec;
      return Error::Ok;
    }
    if (oidIs(oid, oid_len, detail::kRsaEncryption, sizeof(detail::kRsaEncryption))) {
      // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
      DerReader seq(key, key_len);
      const uint8_t *seqv;
      size_t seql;
      if (!seq.expect(0x30, seqv, seql) || !seq.atEnd()) return Error::X509BadCertificate;
      DerReader ints(seqv, seql);
      const uint8_t *nv, *ev;
      size_t nl, el;
      if (!ints.expect(0x02, nv, nl) || !ints.expect(0x02, ev, el)) return Error::X509BadCertificate;
      magnitude(nv, nl, nv, nl);
      magnitude(ev, el, ev, el);
      if (!rsa_.set(nv, nl, ev, el)) return Error::X509Unsupported;
      type_ = Type::Rsa;
      return Error::Ok;
    }
    return Error::X509Unsupported;
  }

  /**
   * Verifies a signature over msg (SHA-256 is applied here). scheme is a TLS
   * SignatureScheme code: 0x0403 ECDSA, 0x0401 RSA PKCS#1 v1.5, 0x0804 RSA-PSS.
   * ECDSA signatures are DER encoded.
   */
  Error verify(uint16_t scheme, const uint8_t *msg, size_t msg_len, const uint8_t *sig,
               size_t sig_len) const {
    uint8_t digest[32];
    Sha256 h;
    h.digest(msg, msg_len, digest);

    if (scheme == 0x0403) {
      if (type_ != Type::Ec) return Error::X509BadSignature;
      uint8_t r[32] = {0}, s[32] = {0};
      if (!derEcdsaSignature(sig, sig_len, r, s)) return Error::X509BadSignature;
      std::unique_ptr<EcdsaP256> curve(new EcdsaP256());
      return curve->verify(x_, y_, digest, 32, r, s) == Error::Ok ? Error::Ok : Error::X509BadSignature;
    }
    if (type_ != Type::Rsa) return Error::X509BadSignature;
    if (scheme == 0x0401) {
      return rsa_.verifyPkcs1Sha256(digest, sig, sig_len) == Error::Ok ? Error::Ok : Error::X509BadSignature;
    }
    if (scheme == 0x0804) {
      return rsa_.verifyPssSha256(digest, sig, sig_len) == Error::Ok ? Error::Ok : Error::X509BadSignature;
    }
    return Error::X509BadSignature;
  }

 private:

  bool oidIs(const uint8_t *v, size_t len, const uint8_t *oid, size_t oid_len) const {
    return len == oid_len && memcmp(v, oid, oid_len) == 0;
  }

  /** Strips leading zero bytes of an INTEGER and stores the magnitude in dst (out params alias src). */
  void magnitude(const uint8_t *v, size_t len, const uint8_t *&out, size_t &out_len) const {
    while (len > 1 && v[0] == 0) {
      v++;
      len--;
    }
    out = v;
    out_len = len;
  }

  /** Extracts r and s (32 bytes each) from a DER ECDSA-Sig-Value. */
  bool derEcdsaSignature(const uint8_t *sig, size_t sig_len, uint8_t r[32], uint8_t s[32]) const {
    DerReader outer(sig, sig_len);
    const uint8_t *seq;
    size_t seql;
    if (!outer.expect(0x30, seq, seql) || !outer.atEnd()) return false;
    DerReader ints(seq, seql);
    const uint8_t *rv, *sv;
    size_t rl, sl;
    if (!ints.expect(0x02, rv, rl) || !ints.expect(0x02, sv, sl) || !ints.atEnd()) return false;
    const uint8_t *rm, *sm;
    size_t rml, sml;
    magnitude(rv, rl, rm, rml);
    magnitude(sv, sl, sm, sml);
    if (rml > 32 || sml > 32) return false;
    memcpy(r + 32 - rml, rm, rml);
    memcpy(s + 32 - sml, sm, sml);
    return true;
  }

  Type type_;
  uint8_t x_[32];
  uint8_t y_[32];
  RsaPublicKey rsa_;
};

/** Signature algorithm of a certificate. */
enum class SignatureAlgorithm { None, EcdsaSha256, RsaPkcs1Sha256, RsaPssSha256 };

/**
 * Parsed X.509 certificate (RFC 5280 subset).
 *
 * parse() decodes a DER certificate and extracts what chain validation needs: the
 * issuer and subject names, the validity period, the basicConstraints CA flag, the
 * subjectAltName DNS names, the signature algorithm and value, and the public key.
 *
 * A Certificate refers to the DER buffer it was parsed from, which must outlive it.
 * CertificateStore owns such buffers for trust anchors, and the TLS session parses
 * server certificates in place inside the handshake buffer.
 *
 * Only the TLS-relevant fields are read. No revocation checks are made.
 *
 * @code
 * Certificate c;
 * if (c.parse(der, len) == Error::Ok && c.matchesHost("example.com")) { // ... }
 * @endcode
 */
class Certificate {
 public:
  /** Creates an empty certificate. */
  Certificate() : der_(nullptr), der_len_(0), tbs_(nullptr), tbs_len_(0), issuer_(nullptr),
                  issuer_len_(0), subject_(nullptr), subject_len_(0), not_before_(0),
                  not_after_(0), is_ca_(false), has_basic_constraints_(false), san_(nullptr),
                  san_len_(0), alg_(SignatureAlgorithm::None), sig_(nullptr), sig_len_(0) {}

  /** Parses a DER certificate. */
  Error parse(const uint8_t *der, size_t len) {
    reset();
    der_ = der;
    der_len_ = len;
    DerReader top(der, len);
    const uint8_t *v;
    size_t vl;
    if (!top.expect(0x30, v, vl) || !top.atEnd()) return Error::X509BadCertificate;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    DerReader cert(v, vl);
    const uint8_t *tbs_start = cert.position();
    if (!cert.expect(0x30, v, vl)) return Error::X509BadCertificate;
    tbs_ = tbs_start;
    tbs_len_ = (size_t)(cert.position() - tbs_start);

    const uint8_t *alg_v;
    size_t alg_l;
    if (!cert.expect(0x30, alg_v, alg_l)) return Error::X509BadCertificate;
    DerReader alg(alg_v, alg_l);
    const uint8_t *oid;
    size_t oid_len;
    if (!alg.expect(0x06, oid, oid_len)) return Error::X509BadCertificate;
    if (oidIs(oid, oid_len, detail::kEcdsaSha256, sizeof(detail::kEcdsaSha256))) {
      alg_ = SignatureAlgorithm::EcdsaSha256;
    } else if (oidIs(oid, oid_len, detail::kRsaSha256, sizeof(detail::kRsaSha256))) {
      alg_ = SignatureAlgorithm::RsaPkcs1Sha256;
    } else if (oidIs(oid, oid_len, detail::kRsaPss, sizeof(detail::kRsaPss))) {
      // The PSS parameters must name SHA-256; its OID must appear in them.
      bool sha256 = false;
      for (const uint8_t *s = alg.position(); s + sizeof(detail::kSha256) <= alg_v + alg_l; s++) {
        if (memcmp(s, detail::kSha256, sizeof(detail::kSha256)) == 0) sha256 = true;
      }
      if (!sha256) return Error::X509Unsupported;
      alg_ = SignatureAlgorithm::RsaPssSha256;
    } else {
      return Error::X509Unsupported;
    }

    const uint8_t *sv;
    size_t sl;
    if (!cert.expect(0x03, sv, sl) || sl < 2 || sv[0] != 0 || !cert.atEnd()) {
      return Error::X509BadCertificate;
    }
    sig_ = sv + 1;
    sig_len_ = sl - 1;

    return parseTbs(v, vl);
  }

  /** Clears all fields without building a temporary Certificate. */
  void reset() {
    der_ = nullptr;
    der_len_ = 0;
    tbs_ = nullptr;
    tbs_len_ = 0;
    issuer_ = nullptr;
    issuer_len_ = 0;
    subject_ = nullptr;
    subject_len_ = 0;
    not_before_ = 0;
    not_after_ = 0;
    is_ca_ = false;
    has_basic_constraints_ = false;
    san_ = nullptr;
    san_len_ = 0;
    alg_ = SignatureAlgorithm::None;
    sig_ = nullptr;
    sig_len_ = 0;
    key_.clear();
  }

  /** The whole DER encoding. */
  const uint8_t *der() const { return der_; }
  /** Length of the DER encoding. */
  size_t derLength() const { return der_len_; }
  /** The DER-encoded TBSCertificate (the signed data). */
  const uint8_t *tbs() const { return tbs_; }
  /** Length of tbs(). */
  size_t tbsLength() const { return tbs_len_; }
  /** The signature value without the BIT STRING padding byte. */
  const uint8_t *signature() const { return sig_; }
  /** Length of signature(). */
  size_t signatureLength() const { return sig_len_; }
  /** Signature algorithm. */
  SignatureAlgorithm signatureAlgorithm() const { return alg_; }
  /** Subject public key. */
  const PublicKey &publicKey() const { return key_; }
  /** Validity start, Unix seconds. */
  int64_t notBefore() const { return not_before_; }
  /** Validity end, Unix seconds. */
  int64_t notAfter() const { return not_after_; }
  /** True when basicConstraints says cA = TRUE. */
  bool isCa() const { return is_ca_; }
  /** True when a basicConstraints extension is present. */
  bool hasBasicConstraints() const { return has_basic_constraints_; }

  /** True when this certificate's subject equals the child's issuer (DER comparison). */
  bool issued(const Certificate &child) const {
    return subject_len_ == child.issuer_len_ && memcmp(subject_, child.issuer_, subject_len_) == 0;
  }

  /** True when both certificates have identical DER encodings. */
  bool sameAs(const Certificate &other) const {
    return der_len_ == other.der_len_ && memcmp(der_, other.der_, der_len_) == 0;
  }

  /** Verifies the child's signature with this certificate's public key. */
  Error verifySignatureOf(const Certificate &child) const {
    return key_.verify(schemeOf(child.alg_), child.tbs_, child.tbs_len_, child.sig_, child.sig_len_);
  }

  /** True if a subjectAltName dNSName matches host (leftmost-label wildcard allowed). */
  bool matchesHost(const char *host) const {
    if (san_ == nullptr) return false;
    DerReader names(san_, san_len_);
    uint8_t tag;
    const uint8_t *v;
    size_t len;
    while (names.next(tag, v, len)) {
      if (tag == 0x82 && matchName(v, len, host)) return true;  // dNSName [2]
    }
    return false;
  }

  /** TLS SignatureScheme code matching a certificate signature algorithm, or 0. */
  uint16_t schemeOf(SignatureAlgorithm alg) const {
    switch (alg) {
      case SignatureAlgorithm::EcdsaSha256: return 0x0403;
      case SignatureAlgorithm::RsaPkcs1Sha256: return 0x0401;
      case SignatureAlgorithm::RsaPssSha256: return 0x0804;
      default: return 0;
    }
  }

 private:

  bool oidIs(const uint8_t *v, size_t len, const uint8_t *oid, size_t oid_len) const {
    return len == oid_len && memcmp(v, oid, oid_len) == 0;
  }

  bool matchName(const uint8_t *pat, size_t pat_len, const char *host) const {
    size_t host_len = strlen(host);
    if (pat_len > 2 && pat[0] == '*' && pat[1] == '.') {
      // "*.example.com" matches exactly one label in front of example.com.
      const char *dot = strchr(host, '.');
      if (dot == nullptr || dot == host) return false;
      size_t suffix_len = pat_len - 1;
      size_t label_len = (size_t)(dot - host);
      if (host_len - label_len != suffix_len) return false;
      return ciEqual(pat + 1, suffix_len, dot, suffix_len);
    }
    return ciEqual(pat, pat_len, host, host_len);
  }

  bool ciEqual(const uint8_t *a, size_t al, const char *b, size_t bl) const {
    if (al != bl) return false;
    for (size_t i = 0; i < al; i++) {
      uint8_t x = a[i], y = (uint8_t)b[i];
      if (x >= 'A' && x <= 'Z') x = (uint8_t)(x + 32);
      if (y >= 'A' && y <= 'Z') y = (uint8_t)(y + 32);
      if (x != y) return false;
    }
    return true;
  }

  int twoDigits(const uint8_t *p) const {
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') return -1;
    return (p[0] - '0') * 10 + (p[1] - '0');
  }

  /** Days from 1970-01-01 for a proleptic Gregorian date. */
  int64_t daysFromCivil(int64_t y, unsigned m, unsigned d) const {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
  }

  /** Converts a UTCTime or GeneralizedTime value to Unix seconds. */
  bool parseTime(uint8_t tag, const uint8_t *v, size_t len, int64_t &out) const {
    int year, off;
    if (tag == 0x17 && len == 13) {
      int yy = twoDigits(v);
      if (yy < 0) return false;
      year = yy < 50 ? 2000 + yy : 1900 + yy;
      off = 2;
    } else if (tag == 0x18 && len == 15) {
      int hi = twoDigits(v), lo = twoDigits(v + 2);
      if (hi < 0 || lo < 0) return false;
      year = hi * 100 + lo;
      off = 4;
    } else {
      return false;
    }
    if (v[len - 1] != 'Z') return false;
    int mon = twoDigits(v + off), day = twoDigits(v + off + 2);
    int hour = twoDigits(v + off + 4), min = twoDigits(v + off + 6), sec = twoDigits(v + off + 8);
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 || min < 0 ||
        min > 59 || sec < 0 || sec > 60) {
      return false;
    }
    out = daysFromCivil(year, (unsigned)mon, (unsigned)day) * 86400 + hour * 3600 + min * 60 + sec;
    return true;
  }

  Error parseTbs(const uint8_t *v, size_t vl) {
    DerReader t(v, vl);
    const uint8_t *e;
    size_t el;
    uint8_t tag;
    const uint8_t *cv;
    size_t cl;
    // Optional explicit version [0], then serialNumber and the inner signature algorithm.
    if (!t.atEnd() && *t.position() == 0xa0 && !t.next(tag, cv, cl)) return Error::X509BadCertificate;
    if (!t.expect(0x02, e, el)) return Error::X509BadCertificate;
    if (!t.expect(0x30, e, el)) return Error::X509BadCertificate;

    const uint8_t *issuer_start = t.position();
    if (!t.expect(0x30, e, el)) return Error::X509BadCertificate;
    issuer_ = issuer_start;
    issuer_len_ = (size_t)(t.position() - issuer_start);

    if (!t.expect(0x30, e, el)) return Error::X509BadCertificate;
    {
      DerReader times(e, el);
      const uint8_t *a, *b;
      size_t al, bl;
      uint8_t ta, tb;
      if (!times.next(ta, a, al) || !times.next(tb, b, bl)) return Error::X509BadCertificate;
      if (!parseTime(ta, a, al, not_before_) || !parseTime(tb, b, bl, not_after_)) {
        return Error::X509BadCertificate;
      }
    }

    const uint8_t *subject_start = t.position();
    if (!t.expect(0x30, e, el)) return Error::X509BadCertificate;
    subject_ = subject_start;
    subject_len_ = (size_t)(t.position() - subject_start);

    if (!t.expect(0x30, e, el)) return Error::X509BadCertificate;
    if (key_.parse(e, el) != Error::Ok) return Error::X509Unsupported;

    // Optional unique IDs and extensions [3].
    while (!t.atEnd()) {
      if (!t.next(tag, e, el)) return Error::X509BadCertificate;
      if (tag != 0xa3) continue;
      DerReader ext_list(e, el);
      const uint8_t *list;
      size_t list_len;
      if (!ext_list.expect(0x30, list, list_len)) return Error::X509BadCertificate;
      DerReader exts(list, list_len);
      while (!exts.atEnd()) {
        const uint8_t *ext;
        size_t ext_len;
        if (!exts.expect(0x30, ext, ext_len)) return Error::X509BadCertificate;
        DerReader fields(ext, ext_len);
        const uint8_t *oid;
        size_t oid_len;
        const uint8_t *fv;
        size_t fl;
        uint8_t ft;
        if (!fields.expect(0x06, oid, oid_len)) return Error::X509BadCertificate;
        if (!fields.next(ft, fv, fl)) return Error::X509BadCertificate;
        if (ft == 0x01) {  // critical flag
          if (!fields.next(ft, fv, fl)) return Error::X509BadCertificate;
        }
        if (ft != 0x04) return Error::X509BadCertificate;  // extnValue OCTET STRING

        if (oidIs(oid, oid_len, detail::kBasicConstraints, sizeof(detail::kBasicConstraints))) {
          DerReader bc(fv, fl);
          const uint8_t *bv;
          size_t bl;
          if (!bc.expect(0x30, bv, bl)) return Error::X509BadCertificate;
          has_basic_constraints_ = true;
          is_ca_ = false;
          DerReader body(bv, bl);
          uint8_t bt;
          const uint8_t *bbv;
          size_t bbl;
          if (!body.atEnd() && body.next(bt, bbv, bbl) && bt == 0x01 && bbl == 1) {
            is_ca_ = bbv[0] != 0;
          }
        } else if (oidIs(oid, oid_len, detail::kSubjectAltName, sizeof(detail::kSubjectAltName))) {
          DerReader san(fv, fl);
          if (!san.expect(0x30, san_, san_len_)) return Error::X509BadCertificate;
        }
      }
    }
    return Error::Ok;
  }

  const uint8_t *der_;
  size_t der_len_;
  const uint8_t *tbs_;
  size_t tbs_len_;
  const uint8_t *issuer_;
  size_t issuer_len_;
  const uint8_t *subject_;
  size_t subject_len_;
  int64_t not_before_;
  int64_t not_after_;
  bool is_ca_;
  bool has_basic_constraints_;
  const uint8_t *san_;
  size_t san_len_;
  SignatureAlgorithm alg_;
  const uint8_t *sig_;
  size_t sig_len_;
  PublicKey key_;
};

/**
 * Trust store: a fixed set of owned DER certificates.
 *
 * Trust anchors are added from DER with addDer(), from PEM text with addPem(), or
 * from either with add(). The store copies the bytes, so the caller's buffer can
 * be released afterwards. The capacity is TINYTLS_X509_MAX_CERTS certificates of
 * at most TINYTLS_X509_MAX_CERT_SIZE bytes each, set at compile time.
 *
 * The class is not copyable, because the parsed certificates point into its
 * storage. Keep the store alive for as long as connections use it.
 *
 * @code
 * CertificateStore roots;
 * roots.addPem(pem_text, strlen(pem_text));
 * tls.setTrustStore(&roots);
 * @endcode
 */
class CertificateStore {
 public:
  /** Creates an empty store. Its storage is allocated in PSRAM when available. */
  CertificateStore()
      : der_(TINYTLS_X509_MAX_CERTS * TINYTLS_X509_MAX_CERT_SIZE, Placement::Psram),
        cert_(TINYTLS_X509_MAX_CERTS, Placement::Psram), count_(0) {
    memset(der_len_, 0, sizeof(der_len_));
  }

  CertificateStore(const CertificateStore &) = delete;
  CertificateStore &operator=(const CertificateStore &) = delete;

  /** Number of certificates. */
  size_t size() const { return count_; }

  /** The certificate at index i (i < size()). */
  const Certificate &at(size_t i) const { return cert_[i]; }

  /** Adds one DER certificate. */
  Error addDer(const uint8_t *der, size_t len) {
    if (count_ >= TINYTLS_X509_MAX_CERTS || len > TINYTLS_X509_MAX_CERT_SIZE) return Error::X509Full;
    uint8_t *slot = der_.data() + count_ * TINYTLS_X509_MAX_CERT_SIZE;
    memcpy(slot, der, len);
    Error rc = cert_[count_].parse(slot, len);
    if (rc != Error::Ok) {
      memset(slot, 0, len);
      return rc;
    }
    der_len_[count_] = len;
    count_++;
    return Error::Ok;
  }

  /** Adds all certificates of PEM text (one or more CERTIFICATE blocks). */
  Error addPem(const uint8_t *buf, size_t len) {
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    const size_t bl = sizeof(begin) - 1, el = sizeof(end) - 1;
    size_t added = 0, pos = 0;
    while (pos < len) {
      const uint8_t *body = nullptr;
      for (size_t i = pos; i + bl <= len; i++) {
        if (memcmp(buf + i, begin, bl) == 0) {
          body = buf + i + bl;
          break;
        }
      }
      if (body == nullptr) break;
      const uint8_t *body_end = nullptr;
      for (const uint8_t *s = body; (size_t)(s - buf) + el <= len; s++) {
        if (memcmp(s, end, el) == 0) {
          body_end = s;
          break;
        }
      }
      if (body_end == nullptr) return Error::X509BadCertificate;
      HeapArray<uint8_t> der(TINYTLS_X509_MAX_CERT_SIZE, Placement::Psram);
      int n = base64_.decode(body, (size_t)(body_end - body), der.data(), der.size());
      if (n < 0) return Error::X509BadCertificate;
      Error rc = addDer(der.data(), (size_t)n);
      if (rc != Error::Ok) return rc;
      added++;
      pos = (size_t)(body_end - buf) + el;
    }
    return added > 0 ? Error::Ok : Error::X509BadCertificate;
  }

  /** Adds certificates from PEM text or a single DER certificate, detected from the first bytes. */
  Error add(const uint8_t *buf, size_t len) {
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    if (len >= sizeof(begin) - 1 && memcmp(buf, begin, sizeof(begin) - 1) == 0) {
      return addPem(buf, len);
    }
    return addDer(buf, len);
  }

 private:
  HeapArray<uint8_t> der_;      ///< Owned DER bytes of all entries (PSRAM when available).
  size_t der_len_[TINYTLS_X509_MAX_CERTS];
  HeapArray<Certificate> cert_;  ///< Parsed entries (PSRAM when available).
  size_t count_;
  Base64 base64_;
};

/**
 * Validates a server certificate chain against a trust store.
 *
 * A verifier is created for one check, with a host name (or NULL to skip the name
 * check), the current time (negative if unknown) and the trust store. verify()
 * checks, in order:
 * - every certificate is inside its validity period (only when a time is known),
 * - the leaf names the host through a subjectAltName dNSName,
 * - each certificate is issued by the next, which must be a CA,
 * - the last certificate is a trust anchor, or is issued by one.
 *
 * Failures are reported as VerifyFlag bits. A chain is trusted only when verify()
 * returns Error::Ok, which requires every check to pass.
 *
 * @note Revocation (CRL, OCSP) and name constraints are not checked.
 */
class ChainVerifier {
 public:
  /**
   * @param trust  Trust anchors (NULL trusts nothing).
   * @param host   Expected server name, or NULL to skip the name check.
   * @param now    Current Unix time, or a negative value if unknown.
   */
  ChainVerifier(const CertificateStore *trust, const char *host, int64_t now)
      : trust_(trust), host_(host), now_(now) {}

  /**
   * Verifies a chain. chain[0] is the leaf; each certificate is issued by the
   * next one, which must be a CA; the last certificate must be a trust anchor
   * or be issued by one.
   *
   * @param chain  Certificates in TLS order, leaf first.
   * @param n      Number of certificates in chain.
   * @param flags  Receives the VerifyFlag bits found.
   * @return Error::Ok when the chain is trusted and every check passed.
   */
  Error verify(const Certificate *chain, size_t n, uint32_t &flags) const {
    uint32_t f = 0;
    if (n == 0) {
      flags |= VerifyBadCertificate;
      return Error::X509BadCertificate;
    }
    if (host_ && !chain[0].matchesHost(host_)) f |= VerifyNameMismatch;

    if (now_ < 0) {
      f |= VerifyTimeUnchecked;
    } else {
      for (size_t i = 0; i < n; i++) {
        if (now_ < chain[i].notBefore()) f |= VerifyFuture;
        if (now_ > chain[i].notAfter()) f |= VerifyExpired;
      }
    }

    for (size_t i = 0; i + 1 < n; i++) {
      const Certificate &issuer = chain[i + 1];
      if (!issuer.issued(chain[i])) f |= VerifyNotTrusted;
      if (!issuer.isCa()) f |= VerifyNotTrusted;
      if (issuer.verifySignatureOf(chain[i]) != Error::Ok) f |= VerifyBadSignature;
    }

    const Certificate &last = chain[n - 1];
    bool trusted = false;
    if (trust_) {
      for (size_t t = 0; t < trust_->size() && !trusted; t++) {
        const Certificate &anchor = trust_->at(t);
        if (anchor.sameAs(last)) {
          trusted = true;  // the chain includes the anchor itself
          break;
        }
        if (!anchor.issued(last) || !anchor.isCa()) continue;
        if (now_ >= 0 && (now_ < anchor.notBefore() || now_ > anchor.notAfter())) continue;
        if (anchor.verifySignatureOf(last) == Error::Ok) trusted = true;
      }
    }
    if (!trusted) f |= VerifyNotTrusted;

    flags |= f;
    return f == 0 ? Error::Ok : Error::X509CertVerifyFailed;
  }

 private:
  const CertificateStore *trust_;
  const char *host_;
  int64_t now_;
};

}  // namespace tinytls
