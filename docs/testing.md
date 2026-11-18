# Testing and fuzzing

## Build and run the tests

Tests use CMake and CTest. The end-to-end tests need the `openssl` command. It
serves as the reference TLS 1.3 server, and it creates the test PKI (an ECDSA and
an RSA chain, plus signed messages) at configure time.

```bash
cmake -S . -B build
cmake --build build
cd build && ctest --output-on-failure
```

Set `-DTINYTLS_BUILD_TESTS=OFF` to skip the tests.

## Fuzzing

`tests/fuzz/` contains a mutation fuzzer, `tinytls_fuzz`. It starts from the test
PKI and from random bytes, and it applies random mutations. The run is
deterministic for a given seed. The targets are:

| Target | What it fuzzes |
|--------|----------------|
| `certificate` | `Certificate::parse` and the accessors |
| `public_key` | `PublicKey::parse` and signature verification |
| `store` | `CertificateStore::add` (PEM and DER) and chain verification |
| `base64` | the PEM body decoder |
| `der_reader` | DER element iteration |
| `rsa` | RSA PKCS#1 v1.5 and PSS verification |
| `ecdsa` | ECDSA P-256 verification |
| `tls_handshake` | a real `Session` against a scripted server: ServerHello, encrypted flight, certificate chain, CertificateVerify and Finished |

Run it directly, or as the `fuzz_parsers` CTest entry:

```bash
build/tests/tinytls_fuzz [iterations] [seed] [target]
```

For memory and undefined-behaviour checks, build with sanitizers:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g"
cmake --build build-asan
build-asan/tests/tinytls_fuzz 20000 1
```

Logs from test runs belong in `tests/logs/`, which is git-ignored.
