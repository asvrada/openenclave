// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_u.h"

#define TEST_EC_KEY 0
#define TEST_RSA_KEY 1

// This is the identity validation callback. An TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection reqest
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    OE_TRACE_INFO(
        "identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        OE_TRACE_ERROR(
            "identity.security_version check failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.  In a real scenario,
    // custom id checking should be done here
    OE_TRACE_INFO("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

void run_test(oe_enclave_t* enclave, int test_type)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ecall_result;
    unsigned char* cert = NULL;
    size_t cert_size = 0;

    OE_TRACE_INFO(
        "Host: get tls certificate signed with %s key from an enclave \n",
        test_type == TEST_RSA_KEY ? "a RSA" : "an EC");
    if (test_type == TEST_EC_KEY)
    {
        result = get_tls_cert_signed_with_ec_key(
            enclave, &ecall_result, &cert, &cert_size);
    }
    else if (test_type == TEST_RSA_KEY)
    {
        result = get_tls_cert_signed_with_rsa_key(
            enclave, &ecall_result, &cert, &cert_size);
    }

    if ((result != OE_OK) || (ecall_result != OE_OK))
        oe_put_err(
            "get_tls_cert_signed_with_%s_key() failed: result=%u",
            test_type == TEST_RSA_KEY ? "rsa" : "ec",
            result);

    fflush(stdout);

    {
        // for testing purpose, output the whole cer in DER format
        char filename[80];
        FILE* file = NULL;

        sprintf(
            filename,
            "./cert_%s.der",
            test_type == TEST_RSA_KEY ? "rsa" : "ec");
        OE_TRACE_INFO(
            "Host: Log quote embedded certificate to file: [%s]\n", filename);
        file = fopen(filename, "wb");
        fwrite(cert, 1, cert_size, file);
        fclose(file);
    }

    // validate cert
    OE_TRACE_INFO("Host: Verifying tls certificate\n");
    OE_TRACE_INFO("Host: cert = %p cert_size = %d\n", cert, cert_size);
    result = oe_verify_attestation_certificate(
        cert, cert_size, enclave_identity_verifier, NULL);
    OE_TRACE_INFO(
        "Host: Verifying the certificate from a host ... %s\n",
        result == OE_OK ? "Success" : "Fail");
    fflush(stdout);
    OE_TEST(result == OE_OK);

    OE_TRACE_INFO("free cert 0xx%p\n", cert);
    free(cert);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    // oe_result_t ecall_result;
    oe_enclave_t* enclave = NULL;
    // unsigned char* cert = NULL;
    // size_t cert_size = 0;

    if (argc != 2)
    {
        OE_TRACE_ERROR("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    if ((result = oe_create_tls_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    run_test(enclave, TEST_EC_KEY);
    run_test(enclave, TEST_RSA_KEY);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);
    OE_TRACE_INFO("=== passed all tests (tls)\n");
    return 0;
}
