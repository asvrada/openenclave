# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(test_host_perf host.cpp)

# Copy bad test data
configure_file(../data/tdx_quote.bin ${CMAKE_CURRENT_BINARY_DIR}/tdx_quote.bin
               COPYONLY)

target_link_libraries(test_host_perf oehostverify)
