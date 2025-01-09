# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(ENC_BIN ${NAME}_enc)
set(EDL_FILE ../${NAME}.edl)

add_custom_command(
  OUTPUT ${NAME}_t.h ${NAME}_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  ${ENC_BIN}
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/${NAME}_t.c)

enclave_include_directories(${ENC_BIN} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(
  ${ENC_BIN}
  oelibc
  oeenclave
  oesymcryptprovider
  oecryptoopenssl_3
  ${LIBSYMCRYPT}
  oelibcxx
  oehostsock
  oehostresolver)
message("LIBSYMCRYPT: ${LIBSYMCRYPT}")
