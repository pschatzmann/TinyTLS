/**
 * @file transport.h
 * Abstract byte transport used by the TLS session.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace tinytls {

/**
 * @brief Abstract byte transport used by the TLS session.
 *
 * A transport represents a TCP-like connection and must not block. write() accepts
 * what the network can take and returns 0 when it cannot accept more right now.
 * read() returns -1 when no data is available. Implement this interface directly,
 * or wrap an existing client type with ClientTransport.
 *
 * The session never owns the transport; the caller keeps it alive while the
 * connection is in use.
 */
class Transport {
 public:
  virtual ~Transport() {}

  /** Opens the connection to host:port. Returns true on success. */
  virtual bool connect(const char *host, uint16_t port) = 0;

  /** Writes up to len bytes and returns the number accepted (0 if not writable now). */
  virtual size_t write(const uint8_t *buf, size_t len) = 0;

  /** Reads up to len bytes and returns the number read, or -1 if none is available. */
  virtual int read(uint8_t *buf, size_t len) = 0;

  /** Number of bytes that can be read without blocking. */
  virtual int available() = 0;

  /** True while the connection is open. */
  virtual bool connected() = 0;

  /** Closes the connection. */
  virtual void stop() = 0;
};

}  // namespace tinytls
