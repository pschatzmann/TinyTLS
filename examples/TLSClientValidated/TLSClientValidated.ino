/*
 * TinyTLS example: HTTPS GET with server certificate validation (ESP32).
 *
 * The server certificate chain is checked against a trusted root certificate,
 * the host name is matched against the certificate, and the validity period is
 * checked against the current time from NTP. The default mode is
 * VerifyMode::Required, so the connection is refused if any check fails.
 *
 * Before running:
 *   1. Replace kRootPem with the PEM text of the root (or intermediate) CA that
 *      issued the server certificate. Export it from a browser or with openssl,
 *      for example: openssl s_client -connect example.com:443 -showcerts
 *   2. Set the Wi-Fi credentials.
 */
#include <WiFi.h>
#include <TinyTLS.h>
#include <time.h>

using namespace tinytls;

const char *ssid = "your-ssid";
const char *password = "your-password";
const char *host = "example.com";

// Trusted CA certificate in PEM format. Replace this placeholder.
static const char kRootPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "REPLACE THIS PLACEHOLDER WITH YOUR CA CERTIFICATE\n"
    "-----END CERTIFICATE-----\n";

CertificateStore roots;  // trust anchors; uses PSRAM when the board has it
SecureClient<WiFiClient> client;

/** Current Unix time from NTP, or -1 if the clock is not set yet. */
int64_t unixTime() {
  time_t now = time(nullptr);
  return now > 1700000000 ? (int64_t)now : -1;
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) delay(200);

  // Synchronise the clock: validity periods cannot be checked without it.
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  while (unixTime() < 0) delay(200);

  // Load the trust anchor. The sketch stops if the PEM text is not valid.
  if (roots.addPem((const uint8_t *)kRootPem, sizeof(kRootPem) - 1) != Error::Ok) {
    Serial.println("Trust store: invalid PEM. Replace kRootPem with a real CA certificate.");
    return;
  }

  client.setTrustStore(&roots);
  client.setTimeSource(unixTime);
  client.setVerifyMode(VerifyMode::Required);  // the default; stated for clarity
  client.setTimeout(15000);
  client.setClock([]() -> uint32_t { return millis(); });
  client.setIdleCallback([]() { delay(1); });

  if (!client.connect(host, 443)) {
    Serial.printf("Connect failed: %s\n", client.errorText());
    if (client.lastError() == Error::CertificateVerifyFailed) {
      uint32_t flags = client.verifyResult();
      if (flags & VerifyNameMismatch) Serial.println("  host name does not match the certificate");
      if (flags & VerifyNotTrusted) Serial.println("  chain does not lead to the trusted CA");
      if (flags & VerifyExpired) Serial.println("  certificate has expired");
      if (flags & VerifyFuture) Serial.println("  certificate is not yet valid");
      if (flags & VerifyBadSignature) Serial.println("  a signature does not verify");
      if (flags & VerifyBadCertificate) Serial.println("  a certificate is malformed");
    }
    return;
  }
  Serial.printf("Validated connection with %s / %s\n", client.version(), client.cipherSuite());

  const char *request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
  client.write((const uint8_t *)request, strlen(request));

  uint32_t last = millis();
  while (client.connected() && millis() - last < 5000) {
    while (client.available() > 0) {
      Serial.write(client.read());
      last = millis();
    }
    delay(1);
  }
  client.stop();
}

void loop() {}
