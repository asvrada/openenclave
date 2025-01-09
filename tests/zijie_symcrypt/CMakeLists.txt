# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(NAME "zijie_symcrypt")
# /home/zijie/code/fork_oe/tests/zijie_symcrypt/libsymcrypt.so.103
set(LIBSYMCRYPT ${CMAKE_CURRENT_SOURCE_DIR}/libsymcrypt.so.103)

add_subdirectory(host)
add_subdirectory(enc)

add_enclave_test(tests/${NAME} ${NAME}_host ${NAME}_enc)
