# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

EDL_USE_HOST_ENTROPY =

ifneq (,$(findstring symcrypt,$(OE_CRYPTO_LIB)))
	EDL_USE_HOST_ENTROPY = -DEDL_USE_HOST_ENTROPY
endif

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_server.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx \
		$(EDL_USE_HOST_ENTROPY)
	$(CC) -c $(CFLAGS) tls_server_u.c
	$(CXX) -c $(CXXFLAGS) host.cpp
	$(CXX) -o tls_server_host host.o tls_server_u.o $(LDFLAGS)

clean:
	rm -f tls_server_host* *.o tls_server_u.* tls_server_args.h
