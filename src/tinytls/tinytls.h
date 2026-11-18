/**
 * @file tinytls.h
 * TinyTLS: the TLS 1.3 client class. Owns the entropy pool, the random
 * generator, the configuration and the session; runs over an attached Transport.
 */
#pragma once

#include "config.h"
#include "drbg.h"
#include "entropy.h"
#include "session.h"
#include "transport.h"
#include "x509.h"

/**
 * TLS 1.3 client class for Arduino and desktop C++.
 *
 * TinyTLS owns the entropy pool, the random generator, the configuration and the
 * session. The application attaches a transport once, configures verification, and
 * then calls connect(), write(), read(), available() and stop(). The class is not
 * copyable, because the session keeps pointers into it.
 *
 * Certificate verification is on by default (VerifyMode::Required). It needs a
 * trust store, and a time source is needed for expiry checks. Without a time source
 * the handshake fails closed and verifyResult() reports VerifyTimeUnchecked.
 * VerifyMode::None encrypts the connection without authenticating the server.
 *
 * Timeouts need a clock (setClock()). Idle waiting is handled by an optional
 * callback (setIdleCallback()), for example yield() or delay(1).
 *
 * @code
 * WiFiClient net;
 * ClientTransport<WiFiClient> transport(net);
 * TinyTLS tls;
 * tls.attach(transport);
 * tls.setTrustStore(&roots);
 * tls.setTimeSource(now_unix);
 * if (tls.connect("example.com", 443)) {
 *   tls.write(request, request_len);
 *   while (tls.connected()) {
 *     while (tls.available() > 0) Serial.write(tls.read());
 *   }
 *   tls.stop();
 * }
 * @endcode
 */
class TinyTLS {
 public:
  /** Monotonic clock in milliseconds, used for the handshake and write timeouts. */
  typedef uint32_t (*ClockFn)();
  /** Called while waiting for the network, for example yield() or delay(1). */
  typedef void (*IdleFn)();

  /** Creates a client. The random generator is seeded from the platform entropy source. */
  TinyTLS() : session_(new tinytls::Session()), mode_(tinytls::VerifyMode::Required), trust_(nullptr), time_(nullptr),
              clock_(nullptr), idle_(nullptr), timeout_ms_(15000), last_error_(tinytls::Error::Ok),
              transport_(nullptr) {
    if (!drbg_.seed(entropy_)) last_error_ = tinytls::Error::EntropyFailed;
  }

  /** Stops the connection, wipes all key material and frees the session. */
  ~TinyTLS() {
    stop();
    delete session_;
  }

  TinyTLS(const TinyTLS &) = delete;
  TinyTLS &operator=(const TinyTLS &) = delete;

  /** Attaches the transport. The transport must outlive this object or the next attach(). */
  void attach(tinytls::Transport &transport) { transport_ = &transport; }

  /** Sets the certificate verification mode. The default is Required. */
  void setVerifyMode(tinytls::VerifyMode mode) { mode_ = mode; }

  /** Sets the trust store for server validation. It must outlive the connection. */
  void setTrustStore(const tinytls::CertificateStore *store) { trust_ = store; }

  /** Sets the time source (Unix seconds). Without one, validity periods are not checked. */
  void setTimeSource(tinytls::TimeFn time) { time_ = time; }

  /** Sets the handshake and write timeout in milliseconds. Needs setClock(). */
  void setTimeout(uint32_t ms) { timeout_ms_ = ms; }

  /** Sets the monotonic clock. */
  void setClock(ClockFn clock) { clock_ = clock; }

  /** Sets the callback run while waiting for the network. */
  void setIdleCallback(IdleFn idle) { idle_ = idle; }

  /** Connects to host:port and runs the TLS handshake. Returns true on success. */
  bool connect(const char *host, uint16_t port) {
    stop();
    session_->reset();
    last_error_ = tinytls::Error::Ok;
    if (transport_ == nullptr || !session_->setHostname(host)) {
      last_error_ = tinytls::Error::BadInput;
      return false;
    }
    session_->bind(transport_, &drbg_);
    session_->configure(mode_, trust_, time_);
    if (!transport_->connect(host, port)) {
      last_error_ = tinytls::Error::ConnectionClosed;
      return false;
    }
    uint32_t start = clock_ ? clock_() : 0;
    tinytls::Error rc;
    while ((rc = session_->handshake()) != tinytls::Error::Ok) {
      if (rc != tinytls::Error::WantRead && rc != tinytls::Error::WantWrite) break;
      if (timedOut(start)) {
        rc = tinytls::Error::ConnectionClosed;
        break;
      }
      idle();
    }
    if (rc != tinytls::Error::Ok) {
      last_error_ = rc;
      transport_->stop();
      return false;
    }
    return true;
  }

  /** Sends close_notify (best effort) and closes the transport. */
  void stop() {
    if (transport_ == nullptr) return;
    if (session_->handshakeComplete() && transport_->connected()) session_->closeNotify();
    transport_->stop();
  }

  /** True while the handshake is complete, the peer has not closed, and the transport is connected. */
  bool connected() {
    return transport_ != nullptr && session_->handshakeComplete() && !session_->peerClosed() &&
           transport_->connected();
  }

  /** Writes len bytes. Returns the number sent, which is less than len on error or timeout. */
  size_t write(const uint8_t *buf, size_t len) {
    size_t sent = 0;
    uint32_t start = clock_ ? clock_() : 0;
    while (sent < len) {
      int rc = session_->write(buf + sent, len - sent);
      if (rc > 0) {
        sent += (size_t)rc;
        start = clock_ ? clock_() : 0;
      } else if (rc == tinytls::code(tinytls::Error::WantWrite)) {
        if (timedOut(start)) break;
        idle();
      } else {
        last_error_ = static_cast<tinytls::Error>(rc);
        break;
      }
    }
    return sent;
  }

  /** Writes one byte. */
  size_t write(uint8_t b) { return write(&b, 1); }

  /** Number of decrypted bytes ready to read. Never blocks. */
  int available() { return session_->available(); }

  /** Reads up to len bytes. Returns -1 when no data is available. */
  int read(uint8_t *buf, size_t len) {
    if (available() <= 0) return -1;
    int rc = session_->read(buf, len);
    if (rc > 0) return rc;
    if (rc != tinytls::code(tinytls::Error::WantRead)) last_error_ = static_cast<tinytls::Error>(rc);
    return -1;
  }

  /** Reads one byte. Returns -1 when no data is available. */
  int read() {
    uint8_t b;
    return read(&b, 1) == 1 ? b : -1;
  }

  /** The last error (Error::Ok if none). */
  tinytls::Error lastError() const { return last_error_; }

  /** Human-readable text for lastError(). */
  const char *errorText() const { return tinytls::errorString(last_error_); }

  /** Verification flags for the server certificate (tinytls::VerifyFlag bits). */
  uint32_t verifyResult() const { return session_->verifyFlags(); }

  /** Negotiated protocol version, for example "TLSv1.3". */
  const char *version() const { return session_->version(); }

  /** Negotiated cipher suite name. */
  const char *cipherSuite() const { return session_->cipherSuite(); }

 private:
  bool timedOut(uint32_t start) const {
    return clock_ && timeout_ms_ && (uint32_t)(clock_() - start) >= timeout_ms_;
  }

  void idle() {
    if (idle_) idle_();
  }

  tinytls::Entropy entropy_;
  tinytls::Drbg drbg_;
  tinytls::Session *session_;  ///< Heap-allocated: the session buffers are large.
  tinytls::VerifyMode mode_;
  const tinytls::CertificateStore *trust_;
  tinytls::TimeFn time_;
  ClockFn clock_;
  IdleFn idle_;
  uint32_t timeout_ms_;
  tinytls::Error last_error_;
  tinytls::Transport *transport_;
};
