# Design and layout

## Layout

```
src/TinyTLS.h             umbrella header
src/tinytls/              one header per component
examples/TLSClient/       HTTPS GET example (SecureClient)
tests/                    known-answer, X.509, TLS and fuzz tests
docs/                     this documentation
Doxyfile                  Doxygen configuration
```

## Principles

- **Header-only, C++11.** The library types live in the `tinytls` namespace.
  `TinyTLS`, `ClientTransport` and `SecureClient` are the only names outside it.
- **Classes, no static methods.** Each component is an object with instance
  methods. Main classes: `Sha256`, `Hmac`, `Hkdf`, `Aes`, `Gcm`, `ChaCha20`,
  `Poly1305`, `ChaCha20Poly1305`, `X25519`, `Entropy`, `Drbg`, `BigInt`,
  `Montgomery`, `EcdsaP256`, `RsaPublicKey`, `DerReader`, `Base64`, `PublicKey`,
  `Certificate`, `CertificateStore`, `ChainVerifier`, `Transport`, `Session`.
- **Large buffers on the heap**, small objects on the stack (see [Platforms](platforms.md)).
- **Configuration macros** keep the `TINYTLS_` prefix, because they are global.

## API reference

Each class is documented in its header. Generate the reference with Doxygen:

```bash
doxygen Doxyfile      # output in docs/html
```
