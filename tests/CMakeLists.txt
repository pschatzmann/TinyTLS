# Unit tests (known-answer vectors) and end-to-end TLS 1.3 tests.
# The end-to-end tests need the `openssl` command line tool, which is used both
# as the reference TLS 1.3 server and to create a throwaway test certificate.

set(TINYTLS_TEST_SOURCES test_main.cpp test_crypto.cpp)

find_program(OPENSSL_EXECUTABLE openssl)
if(OPENSSL_EXECUTABLE)
  set(TEST_DIR ${CMAKE_CURRENT_BINARY_DIR}/certs)
  file(MAKE_DIRECTORY ${TEST_DIR})
  execute_process(
    COMMAND ${OPENSSL_EXECUTABLE} req -x509 -newkey ec
            -pkeyopt ec_paramgen_curve:prime256v1 -nodes
            -keyout ${TEST_DIR}/key.pem -out ${TEST_DIR}/cert.pem
            -days 2 -subj "/CN=localhost"
    RESULT_VARIABLE CERT_RESULT
    OUTPUT_QUIET ERROR_QUIET)
  # PKI and signed messages for the X.509 and signature tests.
  set(TEST_PKI ${CMAKE_CURRENT_BINARY_DIR}/pki)
  execute_process(
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/make_test_pki.sh ${TEST_PKI}
    RESULT_VARIABLE PKI_RESULT
    OUTPUT_QUIET ERROR_QUIET)
  if(PKI_RESULT EQUAL 0)
    list(APPEND TINYTLS_TEST_SOURCES test_x509.cpp)
    set(TINYTLS_TEST_PKI_DIR ${TEST_PKI})
  endif()
  if(CERT_RESULT EQUAL 0)
    list(APPEND TINYTLS_TEST_SOURCES test_tls_integration.cpp)
    set(TINYTLS_TEST_CERT ${TEST_DIR}/cert.pem)
    set(TINYTLS_TEST_KEY ${TEST_DIR}/key.pem)
  else()
    message(WARNING "openssl could not create a test certificate; TLS integration tests disabled")
  endif()
else()
  message(WARNING "openssl not found; TLS integration tests disabled")
endif()

add_executable(tinytls_tests ${TINYTLS_TEST_SOURCES})
target_link_libraries(tinytls_tests PRIVATE TinyTLS::TinyTLS)
target_compile_options(tinytls_tests PRIVATE -Wall -Wextra -Werror)
if(DEFINED TINYTLS_TEST_CERT)
  target_compile_definitions(tinytls_tests PRIVATE
    TINYTLS_TEST_CERT="${TINYTLS_TEST_CERT}"
    TINYTLS_TEST_KEY="${TINYTLS_TEST_KEY}")
endif()
if(DEFINED TINYTLS_TEST_PKI_DIR)
  target_compile_definitions(tinytls_tests PRIVATE TINYTLS_TEST_PKI="${TINYTLS_TEST_PKI_DIR}")
endif()

# Fuzz driver: parsers and verifiers under random mutation (see tests/fuzz).
add_executable(tinytls_fuzz fuzz/fuzz_main.cpp fuzz/fuzz_targets.cpp)
target_include_directories(tinytls_fuzz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/fuzz)
target_link_libraries(tinytls_fuzz PRIVATE TinyTLS::TinyTLS)
target_compile_options(tinytls_fuzz PRIVATE -Wall -Wextra -Werror)
if(DEFINED TINYTLS_TEST_PKI_DIR)
  target_compile_definitions(tinytls_fuzz PRIVATE TINYTLS_TEST_PKI="${TINYTLS_TEST_PKI_DIR}")
  add_test(NAME fuzz_parsers COMMAND tinytls_fuzz 2000 1)
endif()

add_test(NAME unit_crypto COMMAND tinytls_tests "" "tls13_")
if(DEFINED TINYTLS_TEST_PKI_DIR)
  add_test(NAME x509 COMMAND tinytls_tests "x509_")
endif()
if(DEFINED TINYTLS_TEST_CERT)
  add_test(NAME tls13_openssl COMMAND tinytls_tests "tls13_")
endif()
