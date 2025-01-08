# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(HOST_BIN ${NAME}_host)
set(EDL_FILE ../${NAME}.edl)

add_custom_command(
  OUTPUT ${NAME}_u.h ${NAME}_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(${HOST_BIN} host.c ${NAME}_u.c)

target_include_directories(${HOST_BIN} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${HOST_BIN} oehost)
