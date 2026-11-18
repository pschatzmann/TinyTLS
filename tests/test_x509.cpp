// Tests for X.509 parsing, chain validation and certificate signature checks.
// The PKI and signed messages are created by make_test_pki.sh at configure time.
#include "test_main.h"
#include "TinyTLS.h"

#include <chrono>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#ifndef TINYTLS_TEST_PKI
#error "TINYTLS_TEST_PKI must be defined by CMake"
#endif

using namespace tinytls;
using namespace tinytls_test;

namespace {

std::string pki(const char *name) { return std::string(TINYTLS_TEST_PKI) + "/" + name; }

std::vector<uint8_t> load(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
}

int64_t nowUnix() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

/** Loads a PEM file into a trust store. */
std::unique_ptr<CertificateStore> loadStore(const char *name) {
  std::unique_ptr<CertificateStore> store(new CertificateStore());
  auto data = load(pki(name));
  TT_CHECK(store->addPem(data.data(), data.size()) == Error::Ok);
  return store;
}

/** A chain built from a PEM file, referring to a store that owns the DER bytes. */
struct Chain {
  std::unique_ptr<CertificateStore> store;
  std::vector<Certificate> certs;
};

Chain loadChain(const char *name) {
  Chain c;
  c.store.reset(new CertificateStore());
  auto data = load(pki(name));
  TT_CHECK(c.store->addPem(data.data(), data.size()) == Error::Ok);
  for (size_t i = 0; i < c.store->size(); i++) c.certs.push_back(c.store->at(i));
  return c;
}

Error verify(const Chain &c, const CertificateStore *trust, const char *host, int64_t now,
             uint32_t &flags) {
  flags = 0;
  ChainVerifier v(trust, host, now);
  return v.verify(c.certs.data(), c.certs.size(), flags);
}

PublicKey spkiKey(const char *name) {
  auto der = load(pki(name));
  PublicKey key;
  DerReader top(der.data(), der.size());
  const uint8_t *v;
  size_t vl;
  uint8_t tag;
  if (top.next(tag, v, vl) && tag == 0x30) {
    TT_CHECK(key.parse(v, vl) == Error::Ok);
  }
  return key;
}

}  // namespace

TT_TEST(x509_parses_leaf_fields) {
  Chain c = loadChain("ec_leaf.pem");
  TT_CHECK(c.certs.size() == 1);
  const Certificate &leaf = c.certs[0];
  TT_CHECK(leaf.publicKey().type() == PublicKey::Type::Ec);
  TT_CHECK(leaf.signatureAlgorithm() == SignatureAlgorithm::EcdsaSha256);
  TT_CHECK(leaf.hasBasicConstraints() && !leaf.isCa());
  TT_CHECK(leaf.matchesHost("localhost"));
  TT_CHECK(leaf.notAfter() > leaf.notBefore());
}

TT_TEST(x509_pem_chain_parses_two_certificates) {
  Chain c = loadChain("ec_leaf_chain.pem");
  TT_CHECK(c.certs.size() == 2);
  TT_CHECK(c.certs[1].isCa());
}

TT_TEST(x509_ec_chain_trusted_with_hostname) {
  Chain c = loadChain("ec_leaf_chain.pem");
  auto trust = loadStore("ec_root.pem");
  uint32_t flags;
  TT_CHECK(verify(c, trust.get(), "localhost", nowUnix(), flags) == Error::Ok);
  TT_CHECK(flags == 0);
}

TT_TEST(x509_wildcard_hostname_matching) {
  Chain c = loadChain("ec_leaf_chain.pem");
  auto trust = loadStore("ec_root.pem");
  uint32_t flags;
  TT_CHECK(verify(c, trust.get(), "a.example.test", nowUnix(), flags) == Error::Ok);
  // A wildcard matches exactly one label.
  TT_CHECK(verify(c, trust.get(), "a.b.example.test", nowUnix(), flags) != Error::Ok);
  TT_CHECK(flags & VerifyNameMismatch);
  TT_CHECK(verify(c, trust.get(), "example.test", nowUnix(), flags) != Error::Ok);
}

TT_TEST(x509_wrong_hostname_rejected) {
  Chain c = loadChain("ec_leaf_chain.pem");
  auto trust = loadStore("ec_root.pem");
  uint32_t flags;
  TT_CHECK(verify(c, trust.get(), "evil.org", nowUnix(), flags) != Error::Ok);
  TT_CHECK(flags == VerifyNameMismatch);
}

TT_TEST(x509_untrusted_root_rejected) {
  Chain c = loadChain("ec_leaf_chain.pem");
  auto evil = loadStore("evil_root.pem");
  uint32_t flags;
  TT_CHECK(verify(c, evil.get(), "localhost", nowUnix(), flags) != Error::Ok);
  TT_CHECK(flags & VerifyNotTrusted);
}

TT_TEST(x509_empty_trust_store_rejected) {
  Chain c = loadChain("ec_leaf_chain.pem");
  uint32_t flags;
  TT_CHECK(verify(c, nullptr, "localhost", nowUnix(), flags) != Error::Ok);
  TT_CHECK(flags & VerifyNotTrusted);
}

TT_TEST(x509_expired_and_not_yet_valid) {
  Chain c = loadChain("ec_leaf_chain.pem");
  auto trust = loadStore("ec_root.pem");
  uint32_t flags;
  TT_CHECK(verify(c, trust.get(), "localhost", c.certs[0].notAfter() + 1, flags) != Error::Ok);
  TT_CHECK(flags & VerifyExpired);
  TT_CHECK(verify(c, trust.get(), "localhost", c.certs[0].notBefore() - 1, flags) != Error::Ok);
  TT_CHECK(flags & VerifyFuture);
}

TT_TEST(x509_unknown_time_is_flagged) {
  Chain c = loadChain("ec_leaf_chain.pem");
  auto trust = loadStore("ec_root.pem");
  uint32_t flags;
  TT_CHECK(verify(c, trust.get(), "localhost", -1, flags) != Error::Ok);
  TT_CHECK(flags == VerifyTimeUnchecked);
}

TT_TEST(x509_rsa_chain_trusted) {
  Chain c = loadChain("rsa_leaf.pem");
  auto trust = loadStore("rsa_root.pem");
  TT_CHECK(c.certs[0].publicKey().type() == PublicKey::Type::Rsa);
  TT_CHECK(c.certs[0].signatureAlgorithm() == SignatureAlgorithm::RsaPkcs1Sha256);
  uint32_t flags;
  TT_CHECK(verify(c, trust.get(), "localhost", nowUnix(), flags) == Error::Ok);
  TT_CHECK(flags == 0);
}

TT_TEST(x509_tampered_certificate_rejected) {
  // Flip one bit inside the signed TBSCertificate at several offsets. Any
  // tampered certificate that still parses must fail chain verification.
  Chain source = loadChain("ec_leaf.pem");
  const Certificate &orig = source.certs[0];
  std::vector<uint8_t> original(orig.der(), orig.der() + orig.derLength());
  Chain issuer = loadChain("ec_int.pem");
  auto trust = loadStore("ec_root.pem");
  int parsed = 0;
  for (size_t off = original.size() / 4; off < original.size() / 2; off += 29) {
    std::vector<uint8_t> tampered = original;
    tampered[off] ^= 0x01;
    std::unique_ptr<std::vector<uint8_t>> keep(new std::vector<uint8_t>(tampered));
    Certificate leaf;
    if (leaf.parse(keep->data(), keep->size()) != Error::Ok) continue;
    parsed++;
    Chain c;
    c.certs.push_back(leaf);
    c.certs.push_back(issuer.certs[0]);
    uint32_t flags;
    TT_CHECK(verify(c, trust.get(), "localhost", nowUnix(), flags) != Error::Ok);
    TT_CHECK(flags & VerifyBadSignature);
  }
  TT_CHECK(parsed > 0);
}

TT_TEST(x509_signature_ecdsa_p256) {
  PublicKey key = spkiKey("ec_leaf_spki.der");
  auto msg = load(pki("msg.bin"));
  auto sig = load(pki("ec_sig.der"));
  TT_CHECK(key.verify(0x0403, msg.data(), msg.size(), sig.data(), sig.size()) == Error::Ok);
  msg[0] ^= 1;
  TT_CHECK(key.verify(0x0403, msg.data(), msg.size(), sig.data(), sig.size()) != Error::Ok);
}

TT_TEST(x509_signature_rsa_pkcs1_and_pss) {
  PublicKey key = spkiKey("rsa_leaf_spki.der");
  auto msg = load(pki("msg.bin"));
  auto pkcs1 = load(pki("rsa_pkcs1_sig.bin"));
  auto pss = load(pki("rsa_pss_sig.bin"));
  TT_CHECK(key.verify(0x0401, msg.data(), msg.size(), pkcs1.data(), pkcs1.size()) == Error::Ok);
  TT_CHECK(key.verify(0x0804, msg.data(), msg.size(), pss.data(), pss.size()) == Error::Ok);
  // A PSS signature must not verify as PKCS#1 v1.5, and vice versa.
  TT_CHECK(key.verify(0x0401, msg.data(), msg.size(), pss.data(), pss.size()) != Error::Ok);
  TT_CHECK(key.verify(0x0804, msg.data(), msg.size(), pkcs1.data(), pkcs1.size()) != Error::Ok);
  // Signature schemes do not cross key types.
  PublicKey ec = spkiKey("ec_leaf_spki.der");
  TT_CHECK(ec.verify(0x0804, msg.data(), msg.size(), pss.data(), pss.size()) != Error::Ok);
}

TT_TEST(x509_pem_rejects_garbage) {
  CertificateStore store;
  const char *bad = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
  TT_CHECK(store.addPem((const uint8_t *)bad, strlen(bad)) != Error::Ok);
  TT_CHECK(store.size() == 0);
}
