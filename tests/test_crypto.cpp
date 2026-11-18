// Known-answer tests for the TinyTLS crypto primitives.
// Vectors: FIPS 180-4, RFC 4231, RFC 5869, FIPS 197, McGrew/Viega GCM,
// RFC 8439 (ChaCha20, Poly1305, AEAD), RFC 7748 (X25519).
#include "test_main.h"
#include "TinyTLS.h"

using namespace tinytls;
using namespace tinytls_test;

namespace {

std::string sha_hex(const std::string &msg) {
  uint8_t out[32];
  Sha256 h;
  h.digest((const uint8_t *)msg.data(), msg.size(), out);
  return hex(out, 32);
}

}  // namespace

TT_TEST(sha256_known_answers) {
  TT_CHECK(sha_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  TT_CHECK(sha_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  TT_CHECK(sha_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TT_TEST(sha256_incremental_matches_oneshot) {
  std::string msg(1000, 'x');
  for (size_t i = 0; i < msg.size(); i++) msg[i] = (char)(i * 7);
  uint8_t one[32], inc[32];
  Sha256 a;
  a.digest((const uint8_t *)msg.data(), msg.size(), one);
  Sha256 h;
  size_t pos = 0, step = 1;
  while (pos < msg.size()) {
    size_t n = step < msg.size() - pos ? step : msg.size() - pos;
    h.update((const uint8_t *)msg.data() + pos, n);
    pos += n;
    step = step % 97 + 1;
  }
  h.finish(inc);
  TT_CHECK(memcmp(one, inc, 32) == 0);
}

TT_TEST(hmac_sha256_rfc4231) {
  uint8_t out[32];
  std::vector<uint8_t> key(20, 0x0b);
  Hmac h(key.data(), key.size());
  const char *data = "Hi There";
  h.update((const uint8_t *)data, 8);
  h.finish(out);
  TT_CHECK_EQ_HEX(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  const char *k2 = "Jefe";
  const char *d2 = "what do ya want for nothing?";
  Hmac h2((const uint8_t *)k2, 4);
  h2.update((const uint8_t *)d2, strlen(d2));
  h2.finish(out);
  TT_CHECK_EQ_HEX(out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TT_TEST(hkdf_rfc5869_case1) {
  auto ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  auto salt = unhex("000102030405060708090a0b0c");
  auto info = unhex("f0f1f2f3f4f5f6f7f8f9");
  uint8_t prk[32], okm[42];
  Hkdf hk;
  hk.extract(salt.data(), salt.size(), ikm.data(), ikm.size(), prk);
  TT_CHECK_EQ_HEX(prk, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
  TT_CHECK(hk.expand(prk, info.data(), info.size(), okm, sizeof(okm)));
  TT_CHECK_EQ_HEX(okm, 42,
                  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

TT_TEST(aes_fips197_vectors) {
  auto key128 = unhex("000102030405060708090a0b0c0d0e0f");
  auto key256 = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  auto pt = unhex("00112233445566778899aabbccddeeff");
  uint8_t out[16];
  Aes aes;
  TT_CHECK(aes.setKey(key128.data(), 128));
  aes.encryptBlock(pt.data(), out);
  TT_CHECK_EQ_HEX(out, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
  TT_CHECK(aes.setKey(key256.data(), 256));
  aes.encryptBlock(pt.data(), out);
  TT_CHECK_EQ_HEX(out, 16, "8ea2b7ca516745bfeafc49904b496089");
}

TT_TEST(gcm_known_answers) {
  Gcm g;
  std::vector<uint8_t> zero16(16, 0), zero12(12, 0), out(16), tag(16);
  TT_CHECK(g.setKey(zero16.data(), 128));
  // Test case 1: empty plaintext.
  TT_CHECK(g.encrypt(zero12.data(), 12, nullptr, 0, nullptr, 0, nullptr, tag.data()));
  TT_CHECK_EQ_HEX(tag.data(), 16, "58e2fccefa7e3061367f1d57a4e7455a");
  // Test case 2: one zero block.
  TT_CHECK(g.encrypt(zero12.data(), 12, nullptr, 0, zero16.data(), 16, out.data(), tag.data()));
  TT_CHECK_EQ_HEX(out.data(), 16, "0388dace60b6a392f328c2b971b2fe78");
  TT_CHECK_EQ_HEX(tag.data(), 16, "ab6e47d42cec13bdf53a67b21257bddf");
  // Decrypt in place and verify the tag.
  TT_CHECK(g.decrypt(zero12.data(), 12, nullptr, 0, out.data(), 16, tag.data(), out.data()) == Error::Ok);
  TT_CHECK_EQ_HEX(out.data(), 16, "00000000000000000000000000000000");
  // A flipped tag bit is rejected and the output wiped.
  out[0] = 1;
  tag[0] ^= 1;
  std::vector<uint8_t> ct(16, 0x55);
  TT_CHECK(g.decrypt(zero12.data(), 12, nullptr, 0, ct.data(), 16, tag.data(), out.data()) ==
           Error::AuthenticationFailed);
  TT_CHECK(out[0] == 0);
}

TT_TEST(gcm_aes256_roundtrip_with_aad) {
  std::vector<uint8_t> key(32, 0x42), iv(12, 0x24), aad(13, 0x7), pt(77);
  for (size_t i = 0; i < pt.size(); i++) pt[i] = (uint8_t)i;
  std::vector<uint8_t> ct(pt.size()), back(pt.size()), tag(16);
  Gcm g;
  TT_CHECK(g.setKey(key.data(), 256));
  TT_CHECK(g.encrypt(iv.data(), 12, aad.data(), aad.size(), pt.data(), pt.size(), ct.data(), tag.data()));
  TT_CHECK(ct != pt);
  TT_CHECK(g.decrypt(iv.data(), 12, aad.data(), aad.size(), ct.data(), ct.size(), tag.data(), back.data()) ==
           Error::Ok);
  TT_CHECK(back == pt);
}

TT_TEST(chacha20_rfc8439_block) {
  auto key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  auto nonce = unhex("000000090000004a00000000");
  uint8_t zeros[64] = {0}, ks[64];
  ChaCha20 c;
  c.crypt(key.data(), nonce.data(), 1, 64, zeros, ks);
  TT_CHECK_EQ_HEX(ks, 16, "10f1e7e4d13b5915500fdd1fa32071c4");
}

TT_TEST(poly1305_rfc8439) {
  auto key = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  const char *msg = "Cryptographic Forum Research Group";
  uint8_t mac[16];
  Poly1305 p;
  p.mac(key.data(), (const uint8_t *)msg, strlen(msg), mac);
  TT_CHECK_EQ_HEX(mac, 16, "a8061dc1305136c6c22b8baf0c0127a9");
}

TT_TEST(chachapoly_rfc8439_aead) {
  auto key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  auto nonce = unhex("070000004041424344454647");
  auto aad = unhex("50515253c0c1c2c3c4c5c6c7");
  const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                   "for the future, sunscreen would be it.";
  size_t n = strlen(pt);
  std::vector<uint8_t> ct(n), back(n);
  uint8_t tag[16];
  ChaCha20Poly1305 c;
  c.setKey(key.data());
  c.encrypt(nonce.data(), aad.data(), aad.size(), (const uint8_t *)pt, n, ct.data(), tag);
  TT_CHECK_EQ_HEX(tag, 16, "1ae10b594f09e26a7e902ecbd0600691");
  TT_CHECK(c.decrypt(nonce.data(), aad.data(), aad.size(), ct.data(), n, tag, back.data()) == Error::Ok);
  TT_CHECK(memcmp(back.data(), pt, n) == 0);
  tag[3] ^= 0x80;
  TT_CHECK(c.decrypt(nonce.data(), aad.data(), aad.size(), ct.data(), n, tag, back.data()) ==
           Error::AuthenticationFailed);
}

TT_TEST(x25519_rfc7748_vectors) {
  auto scalar = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
  auto u = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
  uint8_t out[32];
  X25519 x;
  TT_CHECK(x.scalarmult(out, scalar.data(), u.data()));
  TT_CHECK_EQ_HEX(out, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

  // Diffie-Hellman exchange (RFC 7748 section 6.1).
  auto a_priv = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  auto b_priv = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  uint8_t a_pub[32], b_pub[32], shared1[32], shared2[32];
  TT_CHECK(x.publicKey(a_priv.data(), a_pub));
  TT_CHECK_EQ_HEX(a_pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  TT_CHECK(x.publicKey(b_priv.data(), b_pub));
  TT_CHECK_EQ_HEX(b_pub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  TT_CHECK(x.scalarmult(shared1, a_priv.data(), b_pub));
  TT_CHECK(x.scalarmult(shared2, b_priv.data(), a_pub));
  TT_CHECK(memcmp(shared1, shared2, 32) == 0);
  TT_CHECK_EQ_HEX(shared1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}

TT_TEST(drbg_produces_distinct_output) {
  Entropy entropy;
  Drbg drbg;
  uint8_t dummy[4];
  TT_CHECK(!drbg.random(dummy, sizeof(dummy)));  // unseeded must fail
  TT_CHECK(drbg.seed(entropy));
  uint8_t a[64], b[64];
  TT_CHECK(drbg.random(a, sizeof(a)));
  TT_CHECK(drbg.random(b, sizeof(b)));
  TT_CHECK(memcmp(a, b, sizeof(a)) != 0);
}

TT_TEST(heap_array_placement_falls_back_to_ram) {
  // A PSRAM request is served from RAM when the platform has no PSRAM.
  HeapArray<uint8_t> ram(64);
  HeapArray<uint8_t> psram(64, Placement::Psram);
  TT_CHECK(ram.size() == 64 && psram.size() == 64);
  TT_CHECK(!ram.inPsram());
  TT_CHECK(!psram.inPsram());
  bool zero = true;
  for (size_t i = 0; i < psram.size(); i++) zero = zero && psram[i] == 0;
  TT_CHECK(zero);
  psram[10] = 7;
  TT_CHECK(psram.data()[10] == 7);
}
