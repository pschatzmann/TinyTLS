// Test runner. Usage: tinytls_tests [include-substring] [exclude-substring]
#include "test_main.h"

int main(int argc, char **argv) {
  const std::string include = argc > 1 ? argv[1] : "";
  const std::string exclude = argc > 2 ? argv[2] : "";
  int ran = 0;
  for (auto &t : tinytls_test::registry()) {
    std::string name = t.name;
    if (name.find(include) == std::string::npos) continue;
    if (!exclude.empty() && name.find(exclude) != std::string::npos) continue;
    int before = tinytls_test::failures();
    fprintf(stderr, "[ RUN  ] %s\n", t.name);
    t.fn();
    bool ok = tinytls_test::failures() == before;
    fprintf(stderr, "[ %s ] %s\n", ok ? "  OK " : "FAIL ", t.name);
    ran++;
  }
  fprintf(stderr, "%d tests, %d failed checks\n", ran, tinytls_test::failures());
  return tinytls_test::failures() == 0 && ran > 0 ? 0 : 1;
}
