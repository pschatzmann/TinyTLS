/**
 * @file heap.h
 * Heap arrays with a placement hint (internal RAM or PSRAM).
 *
 * Small, frequently used data should stay in internal RAM, which is fast.
 * Large buffers that are touched rarely (session record buffers, certificate
 * storage) can use PSRAM when the board has it. On ESP32 this uses
 * heap_caps_malloc(MALLOC_CAP_SPIRAM); if no PSRAM is available the allocation
 * falls back to RAM. Other platforms use malloc(). Override the PSRAM
 * allocator with TINYTLS_PSRAM_ALLOC(n) and TINYTLS_PSRAM_FREE(p), for example
 * for Raspberry Pi Pico boards with PSRAM.
 */
#pragma once

#include <new>
#include <stdlib.h>
#include <string.h>
#include "config.h"

#if TINYTLS_USE_PSRAM && !defined(TINYTLS_PSRAM_ALLOC)
#include <esp_heap_caps.h>
#define TINYTLS_PSRAM_ALLOC(n) heap_caps_malloc((n), MALLOC_CAP_SPIRAM)
#define TINYTLS_PSRAM_FREE(p) heap_caps_free(p)
#endif

namespace tinytls {

/** Where a HeapArray is allocated. */
enum class Placement {
  Ram,   ///< Internal RAM (fast; use for small or frequently used data).
  Psram  ///< PSRAM when available, otherwise RAM (use for large, rarely used buffers).
};

/**
 * Zero-initialised array on the heap. Not copyable. The contents are wiped
 * when the array is destroyed, so secrets do not linger in freed memory.
 */
template <typename T>
class HeapArray {
 public:
  /** Allocates n value-initialised elements at the requested placement. */
  explicit HeapArray(size_t n, Placement where = Placement::Ram) : p_(nullptr), n_(n), psram_(false) {
    void *raw = nullptr;
    if (where == Placement::Psram) {
      raw = psramAlloc(n * sizeof(T));
      psram_ = raw != nullptr;
    }
    if (raw == nullptr) raw = ramAlloc(n * sizeof(T));
    if (raw == nullptr) abort();  // out of memory
    p_ = static_cast<T *>(raw);
    for (size_t i = 0; i < n_; i++) new (p_ + i) T();
  }

  /** Wipes, destroys and frees the elements. */
  ~HeapArray() {
    if (p_ == nullptr) return;
    wipe();
    for (size_t i = n_; i-- > 0;) p_[i].~T();
    if (psram_) {
      psramFree(p_);
    } else {
      ramFree(p_);
    }
  }

  HeapArray(const HeapArray &) = delete;
  HeapArray &operator=(const HeapArray &) = delete;

  /** Element access. */
  T &operator[](size_t i) { return p_[i]; }
  /** Element access. */
  const T &operator[](size_t i) const { return p_[i]; }
  /** Pointer to the first element. */
  T *data() { return p_; }
  /** Pointer to the first element. */
  const T *data() const { return p_; }
  /** Number of elements. */
  size_t size() const { return n_; }
  /** True when the storage is in PSRAM. */
  bool inPsram() const { return psram_; }

  /** Sets every element to zero (bytes; the elements are overwritten). */
  void wipe() { memset((void *)p_, 0, n_ * sizeof(T)); }

 private:
  void *ramAlloc(size_t n) const { return malloc(n ? n : 1); }
  void ramFree(void *p) const { free(p); }

  void *psramAlloc(size_t n) const {
#ifdef TINYTLS_PSRAM_ALLOC
    return TINYTLS_PSRAM_ALLOC(n ? n : 1);
#else
    (void)n;
    return nullptr;  // no PSRAM on this platform: use RAM
#endif
  }
  void psramFree(void *p) const {
#ifdef TINYTLS_PSRAM_FREE
    TINYTLS_PSRAM_FREE(p);
#else
    free(p);
#endif
  }

  T *p_;
  size_t n_;
  bool psram_;
};

}  // namespace tinytls
