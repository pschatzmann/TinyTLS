# Platforms and memory

## Memory placement

Large, rarely accessed buffers go to PSRAM when the board has it. Small and
frequently used data stays in internal RAM:

| Data | Size | Placement |
|------|------|-----------|
| TLS record buffers (rx, tx, handshake) | about 49.7 KB per session | PSRAM |
| Server certificate chain (6 entries) | about 3 KB | PSRAM |
| Trust store (4 certificates) | about 14 KB | PSRAM |
| PEM decode buffer (only while loading) | 3 KB | PSRAM |
| `Session` object, `TinyTLS` object | about 2.9 KB and 0.6 KB | internal RAM |
| Big-integer limbs, ECDSA and RSA workspaces | 0.2 to 1 KB, many per handshake | internal RAM |
| Key-schedule, entropy and label scratch | 0.2 to 0.5 KB | internal RAM |

On ESP32, PSRAM is requested with `heap_caps_malloc(MALLOC_CAP_SPIRAM)`. If no
PSRAM is present, the allocation falls back to RAM. For other boards (for example
Raspberry Pi Pico with PSRAM), define `TINYTLS_PSRAM_ALLOC(n)` and
`TINYTLS_PSRAM_FREE(p)`, or set `TINYTLS_USE_PSRAM 0` to keep everything in RAM.
The PSRAM branch is compiled but has not been run on hardware. It only takes effect
when the board is configured with PSRAM enabled.

## Stack use

The largest call frame in the signature code is about 512 bytes. This was measured
with `-Os -fstack-usage` on a 64-bit host; 32-bit targets use less.

## Allocation failure

Allocation failure aborts, because the library uses plain `new` and `malloc`.
Make sure the heap has room for one session before connecting. Destroying the
`TinyTLS` object, or letting its `SecureClient` go out of scope, frees the memory.

## Entropy

The default source is the ESP32 hardware RNG on ESP32. On other Arduino boards it
is a weak timing-based fallback. Register a hardware source with
`Entropy::addSource()` before using TinyTLS in production.

## Speed

AES-GCM uses a bit-serial GHASH. It is compact, but slow on small MCUs.

## Compiled targets

The example sketch builds without warnings for ESP32-S3 (esp32:esp32 core 3.3.12),
Raspberry Pi Pico (rp2040:rp2040 6.3.2) and Arduino Nano 33 BLE (nRF52840). It has
not been run on hardware.
