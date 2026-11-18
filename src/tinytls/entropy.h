/**
 * @file entropy.h
 * Entropy pool that mixes several entropy sources with SHA-256.
 *
 * The default platform source is registered by the constructor:
 *   - ESP32:          hardware RNG (esp_fill_random)
 *   - other Arduino:  WEAK fallback (micros() and floating ADC noise). Register
 *                     a stronger source with addSource() for production use.
 *   - desktop/tests:  std::random_device
 */
#pragma once

#include <string.h>
#include "config.h"
#include "heap.h"
#include "sha256.h"

#if defined(ARDUINO)
#include <Arduino.h>
#if defined(ESP32)
#include <esp_system.h>
#endif
#else
#include <memory>
#include <random>
#endif

namespace tinytls {

/**
 * @brief Interface for a source of entropy.
 *
 * Implement poll() to supply random bytes from hardware, a sensor or application
 * data, and register the source with Entropy::addSource(). The source must
 * outlive the Entropy pool that uses it.
 *
 * @code
 * class AdcSource : public tinytls::EntropySource {
 *  public:
 *   bool poll(uint8_t *out, size_t len, size_t *olen) override { // ... return true; }
 * };
 * @endcode
 */
class EntropySource {
 public:
  virtual ~EntropySource() {}

  /** Writes up to len bytes to out and reports the count in olen. Returns true on success. */
  virtual bool poll(uint8_t *out, size_t len, size_t *olen) = 0;
};

/**
 * @brief Entropy source backed by the platform random number generator.
 *
 * Behaviour per platform:
 * - ESP32 (Arduino): the hardware RNG through esp_fill_random().
 * - Other Arduino boards: a WEAK fallback that mixes micros() and floating analog
 *   pin noise. Add a stronger source with Entropy::addSource() before generating
 *   keys in production.
 * - Desktop and tests: std::random_device.
 *
 * The Entropy pool owns one instance and registers it automatically.
 */
class PlatformEntropySource : public EntropySource {
 public:
  bool poll(uint8_t *output, size_t len, size_t *olen) override {
#if defined(ARDUINO) && defined(ESP32)
    esp_fill_random(output, len);
#elif defined(ARDUINO)
    for (size_t i = 0; i < len; i++) {
      uint32_t t = micros();
      uint32_t noise = (uint32_t)analogRead(A0) ^ ((uint32_t)analogRead(A1) << 10);
      state_ ^= t + 0x9E3779B9u + (state_ << 6) + (state_ >> 2) + noise;
      state_ ^= state_ << 13;
      state_ ^= state_ >> 17;
      state_ ^= state_ << 5;
      output[i] = (uint8_t)(state_ >> 11);
    }
#else
    for (size_t i = 0; i < len; i++) output[i] = (uint8_t)(*rd_)();
#endif
    if (olen) *olen = len;
    return true;
  }

 private:
#if defined(ARDUINO)
  // ESP32 uses esp_fill_random() and needs no state. Other Arduino boards use this weak fallback.
  uint32_t state_ = 0x9E3779B9u;
#else
  std::unique_ptr<std::random_device> rd_{new std::random_device()};  ///< Heap-allocated.
#endif
};

/**
 * @brief Entropy pool that mixes several sources through SHA-256.
 *
 * The pool registers the platform source when it is created. Each getBytes()
 * call gathers from every source, then expands the pool with a counter and
 * ratchets it forward, so earlier outputs cannot be recomputed from later state.
 * Up to MaxSources sources can be registered.
 *
 * The pool is the input of Drbg::seed(); applications rarely use it directly.
 *
 * @note The class is not copyable, because the pool keeps pointers to its
 * sources. Sources registered with addSource() must outlive the pool.
 */
class Entropy {
 public:
  /** Creates a pool with the platform source registered. */
  Entropy() : pool_(), counter_(0), platform_(), sources_(), count_(0), scratch_(MaxBlock), msg_(), block_(), next_() {
    addSource(&platform_, 32);
  }

  /** Wipes the pool. */
  ~Entropy() { memset(pool_, 0, sizeof(pool_)); }

  Entropy(const Entropy &) = delete;
  Entropy &operator=(const Entropy &) = delete;

  /**
   * Registers an additional source. The object must outlive the pool.
   * Returns false when MaxSources sources are already registered.
   */
  bool addSource(EntropySource *source, size_t threshold = 32) {
    if (count_ >= MaxSources || source == nullptr) return false;
    sources_[count_].source = source;
    sources_[count_].threshold = threshold;
    count_++;
    return true;
  }

  /** Fills out with entropy-derived bytes. Returns false if every source failed. */
  bool getBytes(uint8_t *out, size_t len) {
    if (!gather()) return false;
    size_t done = 0;
    while (done < len) {
      memcpy(msg_, pool_, 32);
      for (int i = 0; i < 8; i++) msg_[32 + i] = (uint8_t)(counter_ >> (56 - 8 * i));
      counter_++;
      hash_.digest(msg_, sizeof(msg_), block_);
      size_t n = len - done < 32 ? len - done : 32;
      memcpy(out + done, block_, n);
      done += n;
      // Ratchet the pool so earlier outputs cannot be recomputed.
      memcpy(next_, pool_, 32);
      memcpy(next_ + 32, block_, 32);
      hash_.digest(next_, sizeof(next_), pool_);
      memset(block_, 0, sizeof(block_));
      memset(msg_, 0, sizeof(msg_));
      memset(next_, 0, sizeof(next_));
    }
    return true;
  }

  static constexpr size_t MaxSources = 8;  ///< Maximum number of registered sources.

 private:
  static constexpr size_t MaxBlock = 256;  ///< Largest amount requested from one source.

  struct Source {
    EntropySource *source;
    size_t threshold;
  };

  bool gather() {
    hash_.reset();
    hash_.update(pool_, sizeof(pool_));
    bool any = false;
    for (size_t i = 0; i < count_; i++) {
      uint8_t *buf = scratch_.data();
      size_t want = sources_[i].threshold ? sources_[i].threshold : 32;
      if (want > MaxBlock) want = MaxBlock;
      size_t olen = 0;
      if (sources_[i].source->poll(buf, want, &olen)) {
        if (olen > MaxBlock) olen = MaxBlock;
        hash_.update(buf, olen);
        any = true;
      }
      scratch_.wipe();
    }
    if (!any) return false;
    hash_.finish(pool_);
    return true;
  }

  uint8_t pool_[32];
  uint64_t counter_;
  PlatformEntropySource platform_;
  Source sources_[MaxSources];
  size_t count_;
  HeapArray<uint8_t> scratch_;  ///< Gather buffer (heap, not stack).
  Sha256 hash_;                 ///< Reused hash state.
  uint8_t msg_[40];             ///< Counter block for getBytes().
  uint8_t block_[32];           ///< Output block for getBytes().
  uint8_t next_[64];            ///< Ratchet input for getBytes().
};

}  // namespace tinytls
