/*
 * TinyTLS example: HTTPS GET over TLS 1.3 with the high-level SecureClient API.
 *
 * SecureClient<WiFiClient> works like WiFiClientSecure: connect(), write(),
 * read(), available(), connected() and stop().
 *
 * This example uses VerifyMode::None for brevity: the connection is encrypted but
 * the server is not authenticated. For validation (the default is Required):
 *   1. Load the trusted root certificate(s) from PEM text into a CertificateStore.
 *   2. Call setTrustStore(&roots) and setTimeSource() with the current Unix time
 *      (for example after NTP synchronisation). Without a time source the
 *      handshake fails, because the validity period cannot be checked.
 *   3. Use VerifyMode::Required (or leave the mode unchanged).
 */
#include <WiFi.h>
#include <TinyTLS.h>

const char *ssid = "your-ssid";
const char *password = "your-password";
const char *host = "example.com";

SecureClient<WiFiClient> client;

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) delay(200);

  client.setVerifyMode(tinytls::VerifyMode::None);  // no validation in this example; see the note above
  client.setTimeout(15000);
  client.setClock([]() -> uint32_t { return millis(); });
  client.setIdleCallback([]() { delay(1); });

  if (!client.connect(host, 443)) {
    Serial.printf("Connect failed: %s\n", client.errorText());
    return;
  }
  Serial.printf("Connected with %s / %s\n", client.version(), client.cipherSuite());

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
