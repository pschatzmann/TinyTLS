cmake_minimum_required(VERSION 3.14)
project(TinyTLS VERSION 0.1.0 LANGUAGES CXX)

# Header-only library target. Consumers link against TinyTLS::TinyTLS.
add_library(TinyTLS INTERFACE)
add_library(TinyTLS::TinyTLS ALIAS TinyTLS)
target_include_directories(TinyTLS INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:include>)
target_compile_features(TinyTLS INTERFACE cxx_std_11)

option(TINYTLS_BUILD_TESTS "Build the TinyTLS test suite" ON)
if(TINYTLS_BUILD_TESTS)
  include(CTest)
  if(BUILD_TESTING)
    add_subdirectory(tests)
  endif()
endif()

include(GNUInstallDirs)
install(DIRECTORY src/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")
install(TARGETS TinyTLS EXPORT TinyTLSTargets)
install(EXPORT TinyTLSTargets NAMESPACE TinyTLS::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TinyTLS)
