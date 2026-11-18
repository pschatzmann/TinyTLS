// Fuzz entry points. See fuzz_targets.h.
#include "fuzz_targets.h"

#include <string.h>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "TinyTLS.h"

namespace fuzz {

namespace {

const uint8_t kMessage[] = "tinytls fuzz message";

/** Copies up to n bytes from data, zero-padded. */
std::vector<uint8_t> padded(const uint8_t *data, size_t size, size_t n) {
  std::vector<uint8_t> out(n, 0);
  size_t c = size < n ? size : n;
  if (c) memcpy(out.data(), data, c);
  return out;
}

}  // namespace

void fuzzCertificate(const uint8_t *data, size_t size) {
  tinytls::Certificate cert;
  if (cert.parse(data, size) != tinytls::Error::Ok) return;
  cert.matchesHost("localhost");
  cert.matchesHost("a.example.test");
  cert.matchesHost("");
  cert.isCa();
  cert.hasBasicConstraints();
  cert.notBefore();
  cert.notAfter();
  cert.publicKey().type();
  cert.sameAs(cert);
  cert.issued(cert);
  cert.verifySignatureOf(cert);
  cert.publicKey().verify(0x0403, kMessage, sizeof(kMessage), cert.signature(), cert.signatureLength());
  cert.publicKey().verify(0x0401, kMessage, sizeof(kMessage), cert.signature(), cert.signatureLength());
  cert.publicKey().verify(0x0804, kMessage, sizeof(kMessage), cert.signature(), cert.signatureLength());
}

void fuzzPublicKey(const uint8_t *data, size_t size) {
  tinytls::PublicKey key;
  if (key.parse(data, size) != tinytls::Error::Ok) return;
  // Verify with the fuzzed bytes as signature, for every scheme.
  key.verify(0x0403, kMessage, sizeof(kMessage), data, size);
  key.verify(0x0401, kMessage, sizeof(kMessage), data, size);
  key.verify(0x0804, kMessage, sizeof(kMessage), data, size);
}

void fuzzCertificateStore(const uint8_t *data, size_t size) {
  tinytls::CertificateStore store;
  store.add(data, size);
  if (store.size() == 0) return;
  tinytls::Certificate chain[2];
  chain[0] = store.at(0);
  chain[1] = store.at(store.size() - 1);
  tinytls::ChainVerifier verifier(&store, "localhost", 1700000000);
  uint32_t flags = 0;
  verifier.verify(chain, 1, flags);
  verifier.verify(chain, 2, flags);
}

void fuzzBase64(const uint8_t *data, size_t size) {
  tinytls::Base64 b64;
  uint8_t out[256];
  b64.decode(data, size, out, sizeof(out));
  b64.decode(data, size, out, 1);  // tiny output buffer
}

void fuzzDerReader(const uint8_t *data, size_t size) {
  tinytls::DerReader reader(data, size);
  uint8_t tag;
  const uint8_t *val;
  size_t len;
  // Walk nested structures: every element is itself read as a sequence.
  for (int i = 0; i < 256 && reader.next(tag, val, len); i++) {
    tinytls::DerReader inner(val, len);
    uint8_t t2;
    const uint8_t *v2;
    size_t l2;
    while (inner.next(t2, v2, l2)) {
    }
  }
}

void fuzzRsa(const uint8_t *data, size_t size) {
  // Layout: [1 byte modulus length][modulus][exponent length][exponent][signature...]
  if (size < 4) return;
  size_t n_len = 1 + data[0] % tinytls::RsaPublicKey::MaxModulusBytes;
  if (1 + n_len + 1 > size) return;
  const uint8_t *n = data + 1;
  size_t e_len = 1 + data[1 + n_len] % 8;
  if (1 + n_len + 1 + e_len > size) return;
  const uint8_t *e = data + 2 + n_len;
  const uint8_t *sig = e + e_len;
  size_t sig_len = size - (size_t)(sig - data);
  tinytls::RsaPublicKey key;
  if (!key.set(n, n_len, e, e_len)) return;
  uint8_t digest[32];
  tinytls::Sha256 h;
  h.digest(kMessage, sizeof(kMessage), digest);
  key.verifyPkcs1Sha256(digest, sig, sig_len);
  key.verifyPssSha256(digest, sig, sig_len);
  key.verifyPssSha256(digest, sig, sig_len > 0 ? 1 : 0);  // short signatures
}

void fuzzEcdsa(const uint8_t *data, size_t size) {
  // Layout: x (32), y (32), r (32), s (32), digest (rest, at least 1 byte).
  std::vector<uint8_t> in = padded(data, size, 128);
  tinytls::EcdsaP256 curve;
  size_t digest_len = size > 128 ? size - 128 : 1;
  const uint8_t *digest = size > 128 ? data + 128 : in.data();
  curve.verify(in.data(), in.data() + 32, digest, digest_len, in.data() + 64, in.data() + 96);
  curve.verify(in.data(), in.data() + 32, digest, digest_len, in.data() + 96, in.data() + 64);
}

namespace {

unsigned long g_flights = 0;
unsigned long g_completions = 0;

/** Transport that captures what the client writes and replays a scripted server reply. */
class ScriptedTransport : public tinytls::Transport {
 public:
  bool connect(const char *, uint16_t) override { return true; }

  size_t write(const uint8_t *buf, size_t len) override {
    out_.insert(out_.end(), buf, buf + len);
    return len;
  }

  int read(uint8_t *buf, size_t len) override {
    if (pos_ >= in_.size()) return -1;  // no data: would block
    size_t n = in_.size() - pos_ < len ? in_.size() - pos_ : len;
    memcpy(buf, in_.data() + pos_, n);
    pos_ += n;
    return (int)n;
  }

  int available() override { return (int)(in_.size() - pos_); }
  bool connected() override { return true; }
  void stop() override {}

  /** Bytes written by the client. */
  const std::vector<uint8_t> &written() const { return out_; }
  /** Queues server bytes for the client to read. */
  void feed(const std::vector<uint8_t> &bytes) { in_.insert(in_.end(), bytes.begin(), bytes.end()); }

 private:
  std::vector<uint8_t> out_;
  std::vector<uint8_t> in_;
  size_t pos_ = 0;
};

/** Appends a plaintext TLS record. */
void appendRecord(std::vector<uint8_t> &out, uint8_t type, const uint8_t *body, size_t len) {
  out.push_back(type);
  out.push_back(0x03);
  out.push_back(0x03);
  out.push_back((uint8_t)(len >> 8));
  out.push_back((uint8_t)len);
  out.insert(out.end(), body, body + len);
}

/** Appends an encrypted record (outer type 23) carrying inner_type. */
void appendEncrypted(std::vector<uint8_t> &out, tinytls::TrafficKeys &keys, uint8_t inner_type,
                     const std::vector<uint8_t> &body) {
  size_t body_len = body.size() + 1 + 16;
  uint8_t header[5] = {23, 0x03, 0x03, (uint8_t)(body_len >> 8), (uint8_t)body_len};
  std::vector<uint8_t> buf(body);
  buf.push_back(inner_type);
  uint8_t tag[16];
  keys.seal(header, 5, buf.data(), buf.size(), tag);
  keys.advance();
  out.insert(out.end(), header, header + 5);
  out.insert(out.end(), buf.begin(), buf.end());
  out.insert(out.end(), tag, tag + 16);
}

/** Handshake message: 4-byte header followed by the body. */
std::vector<uint8_t> handshakeMessage(uint8_t type, const std::vector<uint8_t> &body) {
  std::vector<uint8_t> m;
  m.push_back(type);
  m.push_back((uint8_t)(body.size() >> 16));
  m.push_back((uint8_t)(body.size() >> 8));
  m.push_back((uint8_t)body.size());
  m.insert(m.end(), body.begin(), body.end());
  return m;
}

/** Certificate chains from the test PKI: DER of the leaf and of the intermediate. */
struct Corpus {
  std::vector<std::vector<uint8_t>> certificates;
  Corpus() {
#ifdef TINYTLS_TEST_PKI
    static const char *name = "/ec_leaf_chain.pem";
    std::ifstream f(std::string(TINYTLS_TEST_PKI) + name, std::ios::binary);
    std::vector<uint8_t> pem((std::istreambuf_iterator<char>(f)), {});
    tinytls::CertificateStore store;
    if (store.addPem(pem.data(), pem.size()) == tinytls::Error::Ok) {
      for (size_t i = 0; i < store.size(); i++) {
        const tinytls::Certificate &c = store.at(i);
        certificates.push_back(std::vector<uint8_t>(c.der(), c.der() + c.derLength()));
      }
    }
#endif
  }
};

}  // namespace

void fuzzTlsHandshake(const uint8_t *data, size_t size) {
  static tinytls::Entropy entropy;
  static tinytls::Drbg drbg;
  static bool seeded = drbg.seed(entropy);
  static Corpus corpus;
  static tinytls::CertificateStore trust;
  if (!seeded) return;
  // Leaf and intermediate, trusted anchor: the test root is not loaded here,
  // so validation fails in Required mode, which is itself a path worth fuzzing.

  // Choices from the first bytes of the input.
  std::vector<uint8_t> in(data, data + size);
  in.resize(size < 256 ? 256 : size, 0);  // the fixed fields below need 128 bytes; keep room
  const uint8_t choice = in[0];
  const uint16_t cipher = (choice & 1) ? tinytls::TrafficKeys::CipherChaCha20Poly1305Sha256
                                       : tinytls::TrafficKeys::CipherAes128GcmSha256;
  const tinytls::VerifyMode mode = (tinytls::VerifyMode)((choice >> 1) % 3);
  const uint16_t scheme = (uint16_t)(0x0401 + 0x0002 * ((choice >> 3) % 3));  // 0x0401/0x0403/0x0405
  const bool corrupt_flight = (choice & 0x40) != 0;

  ScriptedTransport net;
  tinytls::Session session;
  session.bind(&net, &drbg);
  session.configure(mode, &trust, nullptr);
  session.setHostname("localhost");

  // Step 1: the client sends its ClientHello.
  tinytls::Error rc = session.handshake();
  if (rc != tinytls::Error::WantRead || net.written().size() < 5 + 4) return;
  const std::vector<uint8_t> &chr = net.written();
  // Record body = handshake message; the transcript uses the message bytes.
  std::vector<uint8_t> client_hello(chr.begin() + 5, chr.begin() + 5 + ((chr[3] << 8) | chr[4]));
  if (client_hello.size() < 4 + 2 + 32 + 1 + 32) return;
  const uint8_t *session_id = client_hello.data() + 4 + 2 + 32 + 1;

  // Client key share (x25519) from the ClientHello extensions.
  std::vector<uint8_t> client_pub(32, 0);
  {
    const uint8_t *p = client_hello.data() + 4 + 2 + 32 + 1 + 32;
    const uint8_t *end = client_hello.data() + client_hello.size();
    if (p + 2 > end) return;
    p += 2 + ((p[0] << 8) | p[1]);             // cipher suites
    if (p + 1 > end) return;
    p += 1 + p[0];                             // compression
    if (p + 2 > end) return;
    const uint8_t *ext_end = p + 2 + ((p[0] << 8) | p[1]);
    p += 2;
    while (p + 4 <= ext_end && ext_end <= end) {
      uint16_t type = (uint16_t)((p[0] << 8) | p[1]);
      uint16_t len = (uint16_t)((p[2] << 8) | p[3]);
      // key_share data: client_shares length (2), group (2), key length (2), key (32)
      if (type == 0x0033 && len >= 2 + 2 + 2 + 32) memcpy(client_pub.data(), p + 10, 32);
      p += 4 + len;
    }
  }

  g_flights++;

  // Step 2: the server key pair and the shared secret.
  std::vector<uint8_t> server_priv(in.begin() + 8, in.begin() + 40), server_pub(32), shared(32);
  tinytls::X25519 x25519;
  if (!x25519.publicKey(server_priv.data(), server_pub.data())) return;
  if (!x25519.scalarmult(shared.data(), server_priv.data(), client_pub.data())) return;

  // Step 3: ServerHello (plaintext record) echoing the session id.
  std::vector<uint8_t> sh;
  sh.push_back(0x03);
  sh.push_back(0x03);
  sh.insert(sh.end(), in.begin() + 40, in.begin() + 72);       // server random
  sh.push_back(32);
  sh.insert(sh.end(), session_id, session_id + 32);
  sh.push_back((uint8_t)(cipher >> 8));
  sh.push_back((uint8_t)cipher);
  sh.push_back(0);
  const uint8_t sh_ext[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,              // supported_versions
                            0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};  // key_share header
  std::vector<uint8_t> sh_exts(sh_ext, sh_ext + sizeof(sh_ext));
  sh_exts.insert(sh_exts.end(), server_pub.begin(), server_pub.end());
  sh.push_back((uint8_t)(sh_exts.size() >> 8));
  sh.push_back((uint8_t)sh_exts.size());
  sh.insert(sh.end(), sh_exts.begin(), sh_exts.end());
  std::vector<uint8_t> server_hello = handshakeMessage(2, sh);

  std::vector<uint8_t> wire;
  appendRecord(wire, 22, server_hello.data(), server_hello.size());
  if (corrupt_flight) wire[in[9] % wire.size()] ^= in[10] | 1;

  // Step 4: key schedule (server side, mirrors RFC 8446 section 7.1).
  tinytls::Sha256 transcript;
  transcript.update(client_hello.data(), client_hello.size());
  transcript.update(server_hello.data(), server_hello.size());
  uint8_t th_sh[32], empty[32], zeros[32] = {0}, early[32], derived[32], hs[32], c_hs[32], s_hs[32];
  tinytls::Sha256 copy = transcript;
  copy.finish(th_sh);
  tinytls::Sha256 empty_hash;
  empty_hash.digest(nullptr, 0, empty);
  tinytls::Hkdf hk;
  hk.extract(nullptr, 0, zeros, 32, early);
  hk.deriveSecret(early, "derived", empty, derived);
  hk.extract(derived, 32, shared.data(), 32, hs);
  hk.deriveSecret(hs, "s hs traffic", th_sh, s_hs);
  hk.deriveSecret(hs, "c hs traffic", th_sh, c_hs);
  tinytls::TrafficKeys server_keys;
  if (!server_keys.install(cipher, s_hs)) return;

  // Step 5: the encrypted flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
  std::vector<uint8_t> ee = handshakeMessage(8, std::vector<uint8_t>{0, 0});
  std::vector<uint8_t> cert_body;
  cert_body.push_back(0);  // certificate_request_context
  std::vector<uint8_t> list;
  const size_t n_certs = corpus.certificates.size();
  for (int k = 0; k < 2 && n_certs > 0; k++) {
    const std::vector<uint8_t> &der = (in[11 + k] & 1 || k == 0) ? corpus.certificates[(in[12 + k] % n_certs)]
                                                                 : in;
    list.push_back((uint8_t)(der.size() >> 16));
    list.push_back((uint8_t)(der.size() >> 8));
    list.push_back((uint8_t)der.size());
    list.insert(list.end(), der.begin(), der.end());
    list.push_back(0);
    list.push_back(0);
  }
  if (n_certs == 0) {  // no corpus: the raw input is the certificate
    list.push_back(0);
    list.push_back(0);
    list.push_back(0);
  }
  cert_body.push_back((uint8_t)(list.size() >> 16));
  cert_body.push_back((uint8_t)(list.size() >> 8));
  cert_body.push_back((uint8_t)list.size());
  cert_body.insert(cert_body.end(), list.begin(), list.end());
  std::vector<uint8_t> certificate = handshakeMessage(11, cert_body);

  std::vector<uint8_t> cv_body = {(uint8_t)(scheme >> 8), (uint8_t)scheme, 0, 64};
  cv_body.insert(cv_body.end(), in.begin() + 16, in.begin() + 16 + 64);  // fuzzed signature
  std::vector<uint8_t> certificate_verify = handshakeMessage(15, cv_body);

  std::vector<uint8_t> flight_hs;
  flight_hs.insert(flight_hs.end(), ee.begin(), ee.end());
  flight_hs.insert(flight_hs.end(), certificate.begin(), certificate.end());
  flight_hs.insert(flight_hs.end(), certificate_verify.begin(), certificate_verify.end());
  transcript.update(ee.data(), ee.size());
  transcript.update(certificate.data(), certificate.size());
  transcript.update(certificate_verify.data(), certificate_verify.size());
  uint8_t th_cv[32], fk_s[32], fin_mac[32];
  tinytls::Sha256 copy2 = transcript;
  copy2.finish(th_cv);
  hk.expandLabel(s_hs, "finished", nullptr, 0, fk_s, 32);
  tinytls::Hmac hm(fk_s, 32);
  hm.update(th_cv, 32);
  hm.finish(fin_mac);
  std::vector<uint8_t> finished = handshakeMessage(20, std::vector<uint8_t>(fin_mac, fin_mac + 32));

  // Each handshake message goes in its own encrypted record, as a real server does.
  appendEncrypted(wire, server_keys, 22, ee);
  appendEncrypted(wire, server_keys, 22, certificate);
  appendEncrypted(wire, server_keys, 22, certificate_verify);
  appendEncrypted(wire, server_keys, 22, finished);
  (void)flight_hs;
  if (corrupt_flight) wire[wire.size() - 1 - (in[13] % 32)] ^= 0x10;
  net.feed(wire);

  // Step 6: finish the handshake (bounded: the server sends everything at once).
  for (int i = 0; i < 16; i++) {
    rc = session.handshake();
    if (rc != tinytls::Error::WantRead && rc != tinytls::Error::WantWrite) break;
  }
  if (!session.handshakeComplete()) return;
  g_completions++;

  // Step 7: post-handshake input: raw bytes as records (rejected by the AEAD, or ignored).
  std::vector<uint8_t> garbage(in.begin() + 64, in.end());
  net.feed(garbage);
  uint8_t buf[256];
  for (int i = 0; i < 8; i++) {
    if (session.read(buf, sizeof(buf)) < 0 && session.peerClosed()) break;
    session.available();
  }
}

}  // namespace fuzz

namespace fuzz {

unsigned long handshakeFlights() { return g_flights; }
unsigned long handshakeCompletions() { return g_completions; }

}  // namespace fuzz
