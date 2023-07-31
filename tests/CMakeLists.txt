# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(${PROJECT_SOURCE_DIR}/cmake/get_testcase_name.cmake)

option(ENABLE_FULL_LIBCXX_TESTS
       "Build all libcxx tests and include in test list" OFF)
if (ENABLE_FULL_LIBCXX_TESTS)
  message("ENABLE_FULL_LIBCXX_TESTS set - building all libcxx tests")
else ()
  message("ENABLE_FULL_LIBCXX_TESTS not set - building some libcxx tests")
endif ()

option(ENABLE_FULL_STRESS_TESTS
       "Build all stress tests and include in test list" OFF)
if (ENABLE_FULL_STRESS_TESTS)
  message("ENABLE_FULL_STRESS_TESTS set - building all stress tests")
else ()
  message("ENABLE_FULL_STRESS_TESTS not set - building some stress tests")
endif ()

option(LVI_MITIGATION_SKIP_TESTS "Skip all tests with LVI mitigation" OFF)
if (LVI_MITIGATION MATCHES ControlFlow AND LVI_MITIGATION_SKIP_TESTS)
  message("LVI_MITIGATION_SKIP_TESTS set - skip all tests with LVI mitigation")
endif ()

if (OE_SGX AND UNIX)
  option(ENABLE_ZERO_BASE_TESTS
         "Build 0-base enclave tests and include in test list" ON)
  if (ENABLE_ZERO_BASE_TESTS)
    message("ENABLE_ZERO_BASE_TESTS set - building all 0-base enclave tests")
  else ()
    message(
      "ENABLE_ZERO_BASE_TESTS not set - not building 0-base enclave tests")
  endif ()
endif ()

option(ENABLE_SYMCRYPT_OPENSSL_TESTS "Test OpenSSL with SymCrypt engine" ON)
if (ENABLE_SYMCRYPT_OPENSSL_TESTS)
  message(
    "ENABLE_SYMCRYPT_OPENSSL_TESTS set - test OpenSSL with both default settings and SymCrypt engine"
  )
else ()
  message(
    "ENABLE_SYMCRYPT_OPENSSL_TESTS not set - test OpenSSL with only default settings"
  )
endif ()

# Define the `OE_SGX` macro used by the oeedger8r on the SGX build.
if (OE_SGX)
  set(DEFINE_OE_SGX "-DOE_SGX")
endif ()

if (CODE_COVERAGE)
  set(DEFINE_OE_CODE_COVERAGE "-DOE_CODE_COVERAGE")
else ()
  set(DEFINE_OE_CODE_COVERAGE "")
endif ()

if (UNIX)
  # On Linux prefer python3 since python may not be available.
  find_program(PYTHON NAMES python3 python)
else ()
  # On Windows and other systems, use the available python executable.
  set(PYTHON "python")
endif ()

# Disable because this test would fail with code coverage
if (NOT CODE_COVERAGE)
  add_subdirectory(log)
endif ()

if (WIN32)
  add_subdirectory(win_paths)
endif ()

if (OE_SGX)
  # Include newly added SGX-specific tests
  # The task to restructure existing tests is tracked
  # in https://github.com/openenclave/openenclave/issues/4281
  add_subdirectory(sgx)
endif ()

if (OE_SGX)

  if (COMPILER_SUPPORTS_SNMALLOC)
    if (NOT USE_SNMALLOC)
      # Do not build that test if we are already using snmalloc for all other tests
      add_subdirectory(snmalloc)
    endif ()
  else ()
    message("The C++ compiler cannot compile snmalloc. Skipping snmalloc test.")
  endif ()

  if (USE_DEBUG_MALLOC)
    add_subdirectory(debug_malloc)
  endif ()
endif ()

if (UNIX
    OR ADD_WINDOWS_ENCLAVE_TESTS
    OR USE_CLANGW)
  if (OE_SGX)
    if (BUILD_ENCLAVES)
      # Disable the memory test for the scenario of building the enclave in Linux and running
      # it on Windows because of the mismatch on the enclave heap size configuration.
      # Also disable the memory test with snmalloc for now because it calls dlmallinfo
      if (NOT USE_SNMALLOC)
        add_subdirectory(memory)
      endif ()
      # Disable tls_e2e on RHEL. For some reasons it may hang on RHEL.
      # https://github.com/openenclave/openenclave/issues/3508
      find_file(REDHAT_FOUND redhat-release redhat-release.conf PATHS /etc)
      if (NOT REDHAT_FOUND)
        add_subdirectory(tls_e2e)
      endif ()
    endif ()

    add_subdirectory(intel_qve_thread_test)

    # The tests in create-rapid fail when enabling code coverage analysis.
    # The failure happens if the first enclave process terminates, the
    # host fs that libgcov requires in the subsequent enclave processes
    # can no longer be used.
    if (NOT CODE_COVERAGE)
      add_subdirectory(create-rapid)
    endif ()

    if (WITH_EEID)
      add_subdirectory(eeid_plugin)
    endif ()

    if (BUILD_OPENSSL)
    endif ()
  endif ()

endif ()

if (UNIX)
  if (OE_SGX)
    add_subdirectory(cmake_name_conflict)
    # The tests in child_process fail when enabling code coverage analysis.
    # The failure happens if a child process terminates after the parent
    # process does. At this point, the host fs that libgcov requires can no
    # longer be used.
    if (NOT CODE_COVERAGE)
      add_subdirectory(child_process)
    endif ()
    if (ENABLE_ZERO_BASE_TESTS)
      # 0-base enclave creation is currently available only in SGX and UNIX
      # platforms.
      add_subdirectory(sgx_zerobase) # Disabled until PSW update
    endif ()
  endif ()
  add_subdirectory(libc)
endif ()
