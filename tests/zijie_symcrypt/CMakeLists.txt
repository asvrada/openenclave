# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(NAME "zijie_symcrypt")
set(LIBSYMCRYPT ${CMAKE_CURRENT_SOURCE_DIR}/libsymcrypt.so.103)

add_subdirectory(host)
add_subdirectory(enc)

add_enclave_test(tests/${NAME} ${NAME}_host ${NAME}_enc)
