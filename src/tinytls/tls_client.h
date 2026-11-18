/**
 * @file tls_client.h
 * Adapter for Arduino-style network clients and the SecureClient convenience class.
 */
#pragma once

#include "tinytls.h"

/**
 * Adapter that presents an Arduino-style client as a Transport.
 *
 * Any type with connect(host, port), write(), read(), available(), connected() and
 * stop() can be wrapped; WiFiClient and EthernetClient satisfy this. The adapter
 * holds a reference, so the client must outlive it.
 *
 * @code
 * WiFiClient net;
 * ClientTransport<WiFiClient> transport(net);
 * @endcode
 */
template <typename NetClient>
class ClientTransport : public tinytls::Transport {
 public:
  /** Wraps a client object. */
  explicit ClientTransport(NetClient &net) : net_(net) {}

  bool connect(const char *host, uint16_t port) override { return net_.connect(host, port); }
  size_t write(const uint8_t *buf, size_t len) override { return net_.write(buf, len); }
  int read(uint8_t *buf, size_t len) override { return net_.read(buf, len); }
  int available() override { return net_.available(); }
  bool connected() override { return net_.connected(); }
  void stop() override { net_.stop(); }

  /** The wrapped client. */
  NetClient &client() { return net_; }

 private:
  NetClient &net_;
};

/**
 * A TLS client that owns its network client, in the style of WiFiClientSecure.
 *
 * SecureClient creates the transport, the TinyTLS object and the network client
 * itself, so an application needs only one object. Every method forwards to the
 * TinyTLS instance, which tls() exposes for advanced configuration.
 *
 * @code
 * SecureClient<WiFiClient> client;
 * client.setTrustStore(&roots);
 * if (client.connect("example.com", 443)) { // ... }
 * @endcode
 *
 * @tparam NetClient Network client type with the methods listed for ClientTransport.
 */
template <typename NetClient>
class SecureClient {
 public:
  /** Creates the client and attaches its transport. */
  SecureClient() : transport_(net_) { tls_.attach(transport_); }

  SecureClient(const SecureClient &) = delete;
  SecureClient &operator=(const SecureClient &) = delete;

  /** See TinyTLS::setVerifyMode(). */
  void setVerifyMode(tinytls::VerifyMode mode) { tls_.setVerifyMode(mode); }
  /** See TinyTLS::setTrustStore(). */
  void setTrustStore(const tinytls::CertificateStore *store) { tls_.setTrustStore(store); }
  /** See TinyTLS::setTimeSource(). */
  void setTimeSource(tinytls::TimeFn time) { tls_.setTimeSource(time); }
  /** See TinyTLS::setTimeout(). */
  void setTimeout(uint32_t ms) { tls_.setTimeout(ms); }
  /** See TinyTLS::setClock(). */
  void setClock(TinyTLS::ClockFn clock) { tls_.setClock(clock); }
  /** See TinyTLS::setIdleCallback(). */
  void setIdleCallback(TinyTLS::IdleFn idle) { tls_.setIdleCallback(idle); }
  /** See TinyTLS::connect(). */
  bool connect(const char *host, uint16_t port) { return tls_.connect(host, port); }
  /** See TinyTLS::stop(). */
  void stop() { tls_.stop(); }
  /** See TinyTLS::connected(). */
  bool connected() { return tls_.connected(); }
  /** Same as connected(). */
  operator bool() { return tls_.connected(); }
  /** See TinyTLS::write(). */
  size_t write(const uint8_t *buf, size_t len) { return tls_.write(buf, len); }
  /** See TinyTLS::write(). */
  size_t write(uint8_t b) { return tls_.write(b); }
  /** See TinyTLS::available(). */
  int available() { return tls_.available(); }
  /** See TinyTLS::read(). */
  int read(uint8_t *buf, size_t len) { return tls_.read(buf, len); }
  /** See TinyTLS::read(). */
  int read() { return tls_.read(); }
  /** See TinyTLS::lastError(). */
  tinytls::Error lastError() const { return tls_.lastError(); }
  /** See TinyTLS::verifyResult(). */
  uint32_t verifyResult() const { return tls_.verifyResult(); }
  /** See TinyTLS::version(). */
  const char *version() const { return tls_.version(); }
  /** See TinyTLS::cipherSuite(). */
  const char *cipherSuite() const { return tls_.cipherSuite(); }
  /** See TinyTLS::errorText(). */
  const char *errorText() const { return tls_.errorText(); }
  /** The embedded network client. */
  NetClient &client() { return net_; }
  /** The embedded TinyTLS object. */
  TinyTLS &tls() { return tls_; }

 private:
  NetClient net_;
  ClientTransport<NetClient> transport_;
  TinyTLS tls_;
};
