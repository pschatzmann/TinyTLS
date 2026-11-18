# Usage

This page shows how to use TinyTLS in a sketch or C++ project. Certificate
validation is covered in [Security](security.md).

## SecureClient

`SecureClient<NetClient>` owns the network client and the TLS session, and it
works like `WiFiClientSecure`:

```cpp
#include <TinyTLS.h>

SecureClient<WiFiClient> client;
client.setVerifyMode(VerifyMode::None);   // see Security before using this in production
if (client.connect("example.com", 443)) {
  client.write((const uint8_t *)"GET / HTTP/1.0\r\n\r\n", 18);
  while (client.connected()) {
    while (client.available() > 0) Serial.write(client.read());
  }
  client.stop();
}
```

Call `setClock()` to enable the handshake timeout.

The transport is any type with `connect(host, port)`, `write`, `read`,
`available`, `connected` and `stop`. Arduino `WiFiClient` and `EthernetClient`
work directly.

## TinyTLS

`TinyTLS` is the non-template core class. It owns the entropy pool, the random
generator, the configuration and the session. It runs over any transport you
attach to it:

```cpp
#include <TinyTLS.h>

WiFiClient net;
ClientTransport<WiFiClient> transport(net);
TinyTLS tls;
tls.attach(transport);
tls.setVerifyMode(VerifyMode::None);
if (tls.connect("example.com", 443)) {
  tls.write((const uint8_t *)"GET / HTTP/1.0\r\n\r\n", 18);
  while (tls.connected()) {
    while (tls.available() > 0) Serial.write(tls.read());
  }
  tls.stop();
}
```

`SecureClient<N>` is a typed wrapper around `TinyTLS` with an embedded transport.

## Certificate validation

```cpp
#include <TinyTLS.h>

static const char kRootPem[] = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n";
static int64_t now_unix() { return (int64_t)time(nullptr); }  // needs NTP or RTC time

CertificateStore roots;                    // uses PSRAM when available
roots.addPem(kRootPem, sizeof(kRootPem) - 1);

WiFiClient net;
ClientTransport<WiFiClient> transport(net);
TinyTLS tls;
tls.attach(transport);
tls.setTrustStore(&roots);
tls.setTimeSource(now_unix);               // validity checks need the current time
if (tls.connect("example.com", 443)) { /* write, read, stop as above */ }
if (tls.lastError() == Error::CertificateVerifyFailed) {
  uint32_t flags = tls.verifyResult();     // VerifyFlag bits explain the failure
}
```

The default mode is `VerifyMode::Required`. See [Security](security.md) for the
rules that apply. The complete sketch is `examples/TLSClientValidated`, which syncs
the time over NTP and reports the verification flags on failure.

## Errors

Functions return `tinytls::Error` values or byte counts. `Error::Ok` is zero, and
the other codes are negative. `errorString(err)` gives a text description, and
`lastError()` returns the last error of a connection. Typical codes:

| Error | Meaning |
|-------|---------|
| `WantRead`, `WantWrite` | No data or no room yet; retry later (internal) |
| `CertificateVerifyFailed` | The server failed validation; see `verifyResult()` |
| `ConnectionClosed` | The transport closed, or the handshake timed out |
| `BadInput` | Missing setup, such as no transport attached |
| `AlertReceived`, `PeerCloseNotify` | The peer sent a fatal alert or close_notify |
