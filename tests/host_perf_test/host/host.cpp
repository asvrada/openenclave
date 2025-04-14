// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mutex>
#include <thread>
#include <vector>

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>

#include "../../../common/sgx/quote.h"
#include "../../../host/sgx/sgxquoteprovider.h"

#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <io.h>
#else
#error "Unsupported OS platform"
#endif

std::mutex _mutex;

static const oe_uuid_t _sgx_quote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _tdx_quote_uuid = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};

typedef struct _input_params
{
    const char* evidence_filename;
    const oe_uuid_t* evidence_format;
    int thread_count;
    int duration;
} input_params_t;

static input_params_t _params;

static int _parse_args(int argc, const char* argv[])
{
    // parse 4 required arguments
    if (argc != 5)
    {
        printf(
            "Usage: %s <evidence file> <evidence format> "
            "<number of enclave thread> <duration (sec)>\n",
            argv[0]);
        return -1;
    }

    // parse 1 argument, the evidence file
    const char* evidence_path = argv[1];
    if (strlen(evidence_path) == 0)
    {
        printf("Invalid tdx evidence path: %s\n", evidence_path);
        return -1;
    }
    _params.evidence_filename = evidence_path;

    // parse 2 argument, the format of evidence
    const char* evidence_format = argv[2];
    if (strncmp(evidence_format, "sgx", 3) == 0)
    {
        _params.evidence_format = &_sgx_quote_uuid;
    }
    else if (strncmp(evidence_format, "tdx", 3) == 0)
    {
        _params.evidence_format = &_tdx_quote_uuid;
    }
    else
    {
        printf("Invalid evidence format: %s\n", evidence_format);
        return -1;
    }

    // parse 3 argument, the number of threads
    int num_thread = atoi(argv[3]);
    if (num_thread <= 0)
    {
        printf("Invalid number of thread: %d\n", num_thread);
        return -1;
    }
    _params.thread_count = num_thread;

    // parse 4 argument, the number of threads
    int duration = atoi(argv[4]);
    if (duration <= 0)
    {
        printf("Invalid duration: %d\n", duration);
        return -1;
    }
    _params.duration = duration;

    return 0;
}

static size_t _get_filesize(FILE* fp)
{
    size_t size = 0;
    fseek(fp, 0, SEEK_END);
    size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    return size;
}

static bool _read_binary_file(
    const char* filename,
    uint8_t** data_ptr,
    size_t* size_ptr)
{
    size_t size = 0;
    uint8_t* data = NULL;
    size_t bytes_read = 0;
    bool result = false;
    FILE* fp = NULL;
#ifdef _WIN32
    if (fopen_s(&fp, filename, "rb") != 0)
#else
    if (!(fp = fopen(filename, "rb")))
#endif
    {
        fprintf(stderr, "Failed to open: %s\n", filename);
        goto exit;
    }

    *data_ptr = NULL;
    *size_ptr = 0;

    // Find file size
    size = _get_filesize(fp);
    if (size == 0)
    {
        fprintf(stderr, "Empty file: %s\n", filename);
        goto exit;
    }

    data = (uint8_t*)malloc(size);
    if (data == NULL)
    {
        fprintf(
            stderr,
            "Failed to allocate memory of size %lu\n",
            (unsigned long)size);
        goto exit;
    }

    bytes_read = fread(data, sizeof(uint8_t), size, fp);
    if (bytes_read != size)
    {
        fprintf(stderr, "Failed to read file: %s\n", filename);
        goto exit;
    }

    result = true;

exit:
    if (fp)
    {
        fclose(fp);
    }

    if (!result)
    {
        if (data != NULL)
        {
            free(data);
            data = NULL;
        }
        bytes_read = 0;
    }

    *data_ptr = data;
    *size_ptr = bytes_read;

    return result;
}

static oe_result_t _verify_evidence(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size,
    uint8_t* endorsements,
    size_t endorsements_size)
{
    oe_result_t result = OE_FAILURE;

    result = oe_verify_evidence(
        format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        NULL,
        0,
        NULL,
        NULL);

    return result;
}

// Entry point for each thread
static int loop_verify(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size,
    uint8_t* endorsements,
    size_t endorsements_size,
    int duration)
{
    int count_local = 0;

    time_t start, now;
    time(&start);
    time(&now);

    while (difftime(now, start) < duration)
    {
        oe_result_t result = _verify_evidence(
            format_id,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size);

        if (result != OE_OK)
        {
            printf(
                "Failed to verify evidence. result=%u (%s)\n",
                result,
                oe_result_str(result));
            break;
        }

        count_local += 1;
        time(&now);
    }

    return count_local;
}

static void thread_entry(
    size_t i,
    uint8_t* evidence,
    size_t evidence_size,
    int* count_global)
{
    int count = loop_verify(
        _params.evidence_format,
        evidence,
        evidence_size,
        NULL,
        0,
        _params.duration);

    printf(
        "Thread %zu finished, OPS %.1f (%d in %d sec)\n",
        i,
        (count / (double)_params.duration),
        count,
        _params.duration);

    // aggregate result
    std::lock_guard<std::mutex> guard(_mutex);
    *count_global += count;
}

int main(int argc, const char* argv[])
{
    oe_result_t result_oe = OE_UNEXPECTED;
    int ret_code = 0;

    uint8_t* evidence = nullptr;
    size_t evidence_size = 0;

    // number of request made in enclave
    int count_global = 0;

    if (_parse_args(argc, argv) != 0)
    {
        printf("Parse arguments failed\n");
        ret_code = 1;
        goto done;
    }

    // Read evidence file
    if (!_read_binary_file(
            _params.evidence_filename, &evidence, &evidence_size))
    {
        printf("Failed to read evidence file\n");
        ret_code = 1;
        goto done;
    }

    // Read endorsement file
    // TODO

    // Init SGX and TDX verifier
    assert(oe_verifier_initialize() == OE_OK);
    assert(oe_tdx_verifier_initialize() == OE_OK);

    // Generate threads
    {
        std::vector<std::thread> threads((size_t)_params.thread_count);
        for (size_t i = 0; i < threads.size(); i++)
        {
            printf("Creating thread %zu\n", i);
            threads[i] = std::thread(
                thread_entry, i, evidence, evidence_size, &count_global);
        }

        for (size_t i = 0; i < threads.size(); ++i)
        {
            threads[i].join();
        }

        printf(
            "Overall OPS %.1f (%d in %d sec)\n",
            (count_global / (double)_params.duration),
            count_global,
            _params.duration);
    }

done:
    oe_verifier_shutdown();
    oe_tdx_verifier_shutdown();

    if (evidence)
    {
        free(evidence);
    }

    // Skip if ret_code is 2
    if (result_oe != OE_OK && ret_code == 0)
    {
        ret_code = 1;
    }

    return ret_code;
}
