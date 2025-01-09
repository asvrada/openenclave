#ifndef OSSL_INTERNAL_DEPRECATED_H
#define OSSL_INTERNAL_DEPRECATED_H
#pragma once

#include <openssl/configuration.h>

#undef OPENSSL_NO_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/macros.h>

#endif
