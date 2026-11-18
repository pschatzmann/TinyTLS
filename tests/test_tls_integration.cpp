// End-to-end TLS 1.3 tests against `openssl s_server`. Each test starts the server
// on a free localhost port and stops it afterwards. Sockets are non-blocking, so
// the WantRead / WantWrite resumption is exercised too.
#include "test_main.h"
#include "TinyTLS.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#ifndef TINYTLS_TEST_CERT
#error "TINYTLS_TEST_CERT / TINYTLS_TEST_KEY must be defined by CMake"
#endif
#ifndef TINYTLS_TEST_PKI
#error "TINYTLS_TEST_PKI must be defined by CMake"
#endif

using namespace tinytls;
using namespace tinytls_test;

namespace {

int pickFreePort() {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(s, (sockaddr *)&a, sizeof(a));
  socklen_t l = sizeof(a);
  getsockname(s, (sockaddr *)&a, &l);
  int port = ntohs(a.sin_port);
  close(s);
  return port;
}

/** Runs `openssl s_server -rev` as a child process. */
class OpenSslServer {
 public:
  OpenSslServer(int port, const char *ciphersuites, const char *cert, const char *key,
                const char *chain)
      : port_(port) {
    pid_ = fork();
    if (pid_ == 0) {
      std::string p = std::to_string(port);
      int devnull = open("/dev/null", O_WRONLY);
      dup2(devnull, 1);
      dup2(devnull, 2);
      std::vector<const char *> args = {"openssl", "s_server", "-quiet", "-rev", "-tls1_3",
                                        "-accept", p.c_str(), "-cert", cert, "-key", key};
      if (chain) {
        args.push_back("-cert_chain");
        args.push_back(chain);
      }
      if (ciphersuites) {
        args.push_back("-ciphersuites");
        args.push_back(ciphersuites);
      }
      args.push_back(nullptr);
      execvp("openssl", const_cast<char *const *>(args.data()));
      _exit(127);
    }
  }

  /** Waits until the server accepts TCP connections. */
  bool ready() {
    for (int i = 0; i < 100; i++) {
      int s = socket(AF_INET, SOCK_STREAM, 0);
      sockaddr_in a{};
      a.sin_family = AF_INET;
      a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      a.sin_port = htons(port_);
      bool ok = connect(s, (sockaddr *)&a, sizeof(a)) == 0;
      close(s);
      if (ok) return true;
      usleep(50 * 1000);
    }
    return false;
  }

  ~OpenSslServer() {
    if (pid_ > 0) {
      kill(pid_, SIGTERM);
      waitpid(pid_, nullptr, 0);
    }
  }

 private:
  int port_;
  pid_t pid_ = -1;
};

/** Non-blocking TCP client satisfying the NetClient interface used by ClientTransport. */
class PosixSocket {
 public:
  ~PosixSocket() { stop(); }

  bool connect(const char *host, uint16_t port) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string p = std::to_string(port);
    if (getaddrinfo(host, p.c_str(), &hints, &res) != 0 || !res) return false;
    fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    bool ok = fd_ >= 0 && ::connect(fd_, res->ai_addr, res->ai_addrlen) == 0;
    freeaddrinfo(res);
    if (!ok) {
      stop();
      return false;
    }
    fcntl(fd_, F_SETFL, O_NONBLOCK);
    eof_ = false;
    return true;
  }

  size_t write(const uint8_t *buf, size_t len) {
    if (fd_ < 0) return 0;
    ssize_t r = send(fd_, buf, len, MSG_NOSIGNAL);
    return r > 0 ? (size_t)r : 0;
  }

  int read(uint8_t *buf, size_t len) {
    if (fd_ < 0) return -1;
    ssize_t r = recv(fd_, buf, len, 0);
    if (r == 0) eof_ = true;
    return r > 0 ? (int)r : -1;
  }

  int available() {
    if (fd_ < 0) return 0;
    int n = 0;
    ioctl(fd_, FIONREAD, &n);
    if (n == 0) {
      char c;
      if (recv(fd_, &c, 1, MSG_PEEK) == 0) eof_ = true;
    }
    return n;
  }

  bool connected() { return fd_ >= 0 && !eof_; }

  void stop() {
    if (fd_ >= 0) close(fd_);
    fd_ = -1;
  }

 private:
  int fd_ = -1;
  bool eof_ = false;
};

uint32_t steadyMs() {
  using namespace std::chrono;
  return (uint32_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void idleSleep() { usleep(1000); }

int64_t unixNow() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

int64_t timeIn2100() { return 4102444800; }  // after the 30-day test leaf expires

std::string reversed(std::string s) { return std::string(s.rbegin(), s.rend()); }

std::string pkiFile(const char *name) { return std::string(TINYTLS_TEST_PKI) + "/" + name; }

std::vector<uint8_t> readFile(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
}

std::unique_ptr<CertificateStore> loadStore(const char *name) {
  std::unique_ptr<CertificateStore> store(new CertificateStore());
  auto data = readFile(pkiFile(name));
  TT_CHECK(store->addPem(data.data(), data.size()) == Error::Ok);
  return store;
}

struct Outcome {
  Error handshake = Error::Ok;
  uint32_t flags = 0;
  std::string echoed;
  std::string version;
  std::string cipher;
};

/**
 * Runs one session with TinyTLS: handshake, optional payload echo.
 * The trust store and time source may be null.
 */
Outcome runSession(int port, const char *host, VerifyMode mode, const CertificateStore *trust,
                   TimeFn time, const std::string &payload) {
  Outcome out;
  PosixSocket net;
  ClientTransport<PosixSocket> transport(net);
  TinyTLS tls;
  tls.attach(transport);
  tls.setVerifyMode(mode);
  tls.setTrustStore(trust);
  tls.setTimeSource(time);
  tls.setClock(steadyMs);
  tls.setIdleCallback(idleSleep);
  if (!tls.connect(host, (uint16_t)port)) {
    out.handshake = tls.lastError();
  }
  out.flags = tls.verifyResult();
  if (tls.connected()) {
    out.version = tls.version();
    out.cipher = tls.cipherSuite();
    size_t off = 0;
    uint32_t start = steadyMs();
    while (off < payload.size() && steadyMs() - start < 5000) {
      size_t n = tls.write((const uint8_t *)payload.data() + off, payload.size() - off);
      if (n > 0) {
        off += n;
      } else {
        idleSleep();
      }
    }
    uint8_t buf[4096];
    start = steadyMs();
    while (out.echoed.size() < payload.size() && steadyMs() - start < 5000) {
      int n = tls.read(buf, sizeof(buf));
      if (n > 0) {
        out.echoed.append((const char *)buf, (size_t)n);
      } else {
        idleSleep();
      }
    }
    tls.stop();
  }
  return out;
}

}  // namespace

TT_TEST(tls13_aes128_gcm_handshake_and_echo) {
  int port = pickFreePort();
  OpenSslServer server(port, "TLS_AES_128_GCM_SHA256", TINYTLS_TEST_CERT, TINYTLS_TEST_KEY, nullptr);
  TT_CHECK(server.ready());
  Outcome r = runSession(port, "localhost", VerifyMode::None, nullptr, nullptr, "hello\n");
  TT_CHECK(r.handshake == Error::Ok);
  TT_CHECK(r.version == "TLSv1.3");
  TT_CHECK(r.cipher == "TLS1-3-AES-128-GCM-SHA256");
  TT_CHECK(r.echoed.find("olleh") != std::string::npos);
}

TT_TEST(tls13_chacha20_poly1305_handshake_and_echo) {
  int port = pickFreePort();
  OpenSslServer server(port, "TLS_CHACHA20_POLY1305_SHA256", TINYTLS_TEST_CERT, TINYTLS_TEST_KEY, nullptr);
  TT_CHECK(server.ready());
  Outcome r = runSession(port, "localhost", VerifyMode::None, nullptr, nullptr, "chacha test\n");
  TT_CHECK(r.handshake == Error::Ok);
  TT_CHECK(r.cipher == "TLS1-3-CHACHA20-POLY1305-SHA256");
  TT_CHECK(r.echoed.find(reversed("chacha test")) != std::string::npos);
}

TT_TEST(tls13_large_payload_spans_many_records) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, TINYTLS_TEST_CERT, TINYTLS_TEST_KEY, nullptr);
  TT_CHECK(server.ready());
  std::string line;
  for (int i = 0; i < 40000; i++) line.push_back((char)('a' + i % 26));
  line.push_back('\n');
  Outcome r = runSession(port, "localhost", VerifyMode::None, nullptr, nullptr, line);
  TT_CHECK(r.handshake == Error::Ok);
  // openssl s_server -rev reverses its input in 16384-byte chunks (one TLS record each)
  // and adds its own line breaks. Compare the content with the line breaks removed.
  std::string content;
  for (char c : r.echoed) {
    if (c != '\n' && c != '\r') content.push_back(c);
  }
  std::string body = line.substr(0, line.size() - 1);
  std::string expected;
  for (size_t i = 0; i < body.size(); i += 16384) expected += reversed(body.substr(i, 16384));
  TT_CHECK(content == expected);
}

TT_TEST(tls13_default_authmode_fails_closed) {
  // Without a trust store, the default Required mode must refuse the server.
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, TINYTLS_TEST_CERT, TINYTLS_TEST_KEY, nullptr);
  TT_CHECK(server.ready());
  Outcome r = runSession(port, "localhost", VerifyMode::Required, nullptr, unixNow, "x\n");
  TT_CHECK(r.handshake == Error::CertificateVerifyFailed);
  TT_CHECK(r.echoed.empty());
}

TT_TEST(client_api_secure_client_connect_write_read) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, TINYTLS_TEST_CERT, TINYTLS_TEST_KEY, nullptr);
  TT_CHECK(server.ready());

  SecureClient<PosixSocket> client;
  client.setVerifyMode(VerifyMode::None);
  client.setClock(steadyMs);
  client.setIdleCallback(idleSleep);
  TT_CHECK(client.connect("localhost", (uint16_t)port));
  TT_CHECK(client.connected());
  TT_CHECK(std::string(client.version()) == "TLSv1.3");

  const std::string msg = "hello client\n";
  TT_CHECK(client.write((const uint8_t *)msg.data(), msg.size()) == msg.size());
  std::string got;
  uint32_t start = steadyMs();
  while (got.find("tneilc olleh") == std::string::npos && steadyMs() - start < 5000) {
    if (client.available() > 0) {
      uint8_t buf[256];
      int n = client.read(buf, sizeof(buf));
      if (n > 0) got.append((const char *)buf, (size_t)n);
    } else {
      idleSleep();
    }
  }
  TT_CHECK(got.find("tneilc olleh") != std::string::npos);
  client.stop();
  TT_CHECK(!client.connected());
}

TT_TEST(client_api_secure_client_default_verify_fails_closed) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, TINYTLS_TEST_CERT, TINYTLS_TEST_KEY, nullptr);
  TT_CHECK(server.ready());
  SecureClient<PosixSocket> client;  // default: VerifyMode::Required
  client.setClock(steadyMs);
  client.setIdleCallback(idleSleep);
  TT_CHECK(!client.connect("localhost", (uint16_t)port));
  TT_CHECK(client.lastError() == Error::CertificateVerifyFailed);
  TT_CHECK(!client.connected());
}

TT_TEST(tinytls_class_attach_to_transport) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, TINYTLS_TEST_CERT, TINYTLS_TEST_KEY, nullptr);
  TT_CHECK(server.ready());
  PosixSocket net;
  ClientTransport<PosixSocket> transport(net);
  TinyTLS tls;
  tls.attach(transport);
  tls.setVerifyMode(VerifyMode::None);
  tls.setClock(steadyMs);
  tls.setIdleCallback(idleSleep);
  TT_CHECK(tls.connect("localhost", (uint16_t)port));
  const std::string msg = "attached\n";
  TT_CHECK(tls.write((const uint8_t *)msg.data(), msg.size()) == msg.size());
  std::string got;
  uint32_t start = steadyMs();
  while (got.find("dehcatta") == std::string::npos && steadyMs() - start < 5000) {
    uint8_t buf[256];
    int n = tls.read(buf, sizeof(buf));
    if (n > 0) got.append((const char *)buf, (size_t)n);
    else idleSleep();
  }
  TT_CHECK(got.find("dehcatta") != std::string::npos);
  tls.stop();
}

TT_TEST(pki_ec_chain_validated_over_tls13) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, pkiFile("ec_leaf.pem").c_str(), pkiFile("ec_leaf.key").c_str(),
                       pkiFile("ec_int.pem").c_str());
  TT_CHECK(server.ready());
  auto trust = loadStore("ec_root.pem");
  Outcome r = runSession(port, "localhost", VerifyMode::Required, trust.get(), unixNow, "pki\n");
  TT_CHECK(r.handshake == Error::Ok);
  TT_CHECK(r.flags == 0);
  TT_CHECK(r.echoed.find("ikp") != std::string::npos);
}

TT_TEST(pki_rsa_chain_validated_over_tls13) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, pkiFile("rsa_leaf.pem").c_str(), pkiFile("rsa_leaf.key").c_str(), nullptr);
  TT_CHECK(server.ready());
  auto trust = loadStore("rsa_root.pem");
  Outcome r = runSession(port, "localhost", VerifyMode::Required, trust.get(), unixNow, "pki\n");
  TT_CHECK(r.handshake == Error::Ok);
  TT_CHECK(r.flags == 0);
}

TT_TEST(pki_untrusted_chain_rejected_over_tls13) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, pkiFile("ec_leaf.pem").c_str(), pkiFile("ec_leaf.key").c_str(),
                       pkiFile("ec_int.pem").c_str());
  TT_CHECK(server.ready());
  auto evil = loadStore("evil_root.pem");
  Outcome r = runSession(port, "localhost", VerifyMode::Required, evil.get(), unixNow, "x\n");
  TT_CHECK(r.handshake == Error::CertificateVerifyFailed);
  TT_CHECK(r.flags & VerifyNotTrusted);
}

TT_TEST(pki_hostname_mismatch_rejected_over_tls13) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, pkiFile("ec_leaf.pem").c_str(), pkiFile("ec_leaf.key").c_str(),
                       pkiFile("ec_int.pem").c_str());
  TT_CHECK(server.ready());
  auto trust = loadStore("ec_root.pem");
  // The certificate has DNS names only, so an IP address does not match.
  Outcome r = runSession(port, "127.0.0.1", VerifyMode::Required, trust.get(), unixNow, "x\n");
  TT_CHECK(r.handshake == Error::CertificateVerifyFailed);
  TT_CHECK(r.flags & VerifyNameMismatch);
}

TT_TEST(pki_expired_certificate_rejected_over_tls13) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, pkiFile("ec_leaf.pem").c_str(), pkiFile("ec_leaf.key").c_str(),
                       pkiFile("ec_int.pem").c_str());
  TT_CHECK(server.ready());
  auto trust = loadStore("ec_root.pem");
  Outcome r = runSession(port, "localhost", VerifyMode::Required, trust.get(), timeIn2100, "x\n");
  TT_CHECK(r.handshake == Error::CertificateVerifyFailed);
  TT_CHECK(r.flags & VerifyExpired);
}

TT_TEST(pki_without_time_source_fails_closed) {
  int port = pickFreePort();
  OpenSslServer server(port, nullptr, pkiFile("ec_leaf.pem").c_str(), pkiFile("ec_leaf.key").c_str(),
                       pkiFile("ec_int.pem").c_str());
  TT_CHECK(server.ready());
  auto trust = loadStore("ec_root.pem");
  Outcome r = runSession(port, "localhost", VerifyMode::Required, trust.get(), nullptr, "x\n");
  TT_CHECK(r.handshake == Error::CertificateVerifyFailed);
  TT_CHECK(r.flags & VerifyTimeUnchecked);
}
