// Minimal self-contained test harness (no external dependencies).
#pragma once

#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

namespace tinytls_test {

struct TestCase {
  const char *name;
  void (*fn)();
};

inline std::vector<TestCase> &registry() {
  static std::vector<TestCase> r;
  return r;
}

inline int &failures() {
  static int f = 0;
  return f;
}

struct Registrar {
  Registrar(const char *name, void (*fn)()) { registry().push_back({name, fn}); }
};

inline std::string hex(const unsigned char *p, size_t n) {
  static const char *d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 15]);
  }
  return s;
}

inline std::vector<unsigned char> unhex(const char *h) {
  std::vector<unsigned char> out;
  auto v = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
    out.push_back((unsigned char)(v(h[i]) * 16 + v(h[i + 1])));
  }
  return out;
}

}  // namespace tinytls_test

#define TT_TEST(name)                                              \
  static void name();                                              \
  static tinytls_test::Registrar name##_reg(#name, &name);         \
  static void name()

#define TT_CHECK(cond)                                                          \
  do {                                                                          \
    if (!(cond)) {                                                              \
      fprintf(stderr, "  CHECK failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
      tinytls_test::failures()++;                                               \
    }                                                                           \
  } while (0)

#define TT_CHECK_EQ_HEX(actual_ptr, actual_len, expected_hex)                   \
  do {                                                                          \
    std::string got_ = tinytls_test::hex((actual_ptr), (actual_len));           \
    std::string exp_ = (expected_hex);                                          \
    if (got_ != exp_) {                                                         \
      fprintf(stderr, "  HEX mismatch (%s:%d)\n    got %s\n    exp %s\n",      \
              __FILE__, __LINE__, got_.c_str(), exp_.c_str());                  \
      tinytls_test::failures()++;                                               \
    }                                                                           \
  } while (0)
