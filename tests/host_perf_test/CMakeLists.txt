# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_test(
  NAME tests/test_host_perf
  COMMAND $<TARGET_FILE:test_host_perf>
          ${CMAKE_CURRENT_SOURCE_DIR}/data/tdx_quote.bin tdx 2 2
  WORKING_DIRECTORY $<TARGET_FILE_DIR:test_host_perf>)
