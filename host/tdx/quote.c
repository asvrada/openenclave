// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "quote.h"
#include <openenclave/internal/raise.h>
#include "../sgx/sgxquote.h" /* Depend on the same quote provider as SGX */

oe_result_t tdx_verify_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const uint8_t* p_quote,
    uint32_t quote_size,
    const uint8_t* p_endorsements,
    uint32_t endorsements_size,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void** p_supplemental_data,
    uint32_t* p_supplemental_data_size_out)
{
    // delegate input validation to host/sgx/sgxquote.c:oe_tdx_verify_quote
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* supplemental_data = NULL;
    uint32_t supplemental_data_size = 0;

    if (p_supplemental_data && !p_supplemental_data_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Query the exact supplemental data size and allocate a buffer */
    if (p_supplemental_data)
    {
        uint32_t version = 0;

        OE_CHECK(oe_tdx_get_supplemental_data_size(
            p_quote, quote_size, &version, &supplemental_data_size));

        // TODO: check size != 0

        supplemental_data = (uint8_t*)oe_malloc(supplemental_data_size);
        if (supplemental_data == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        memset(supplemental_data, 0, supplemental_data_size);
    }

    result = oe_tdx_verify_quote(
        format_id,
        opt_params,
        opt_params_size,
        p_quote,
        quote_size,
        p_endorsements,
        endorsements_size,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        qve_report_info_size,
        supplemental_data,
        supplemental_data_size);

    if (p_qve_report_info != NULL)
    {
        OE_TRACE_INFO(
            "SGX DCAP QvE-based TDX quote verification is used, res: %s\n",
            oe_result_str(result));
    }
    else
    {
        OE_TRACE_INFO(
            "SGX DCAP QVL-based TDX quote verification is used, res: %s\n",
            oe_result_str(result));
    }

    /* Transfer ownership of the allocated buffer to the caller on success. */
    if (result == OE_OK && p_supplemental_data)
    {
        *p_supplemental_data = supplemental_data;
        *p_supplemental_data_size_out = supplemental_data_size;
        supplemental_data = NULL;
    }

done:
    oe_free(supplemental_data);

    return result;
}
