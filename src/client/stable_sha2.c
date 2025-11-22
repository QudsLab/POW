#include "stable_sha2.h"
#include <string.h>

int stable_sha2_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len) {
    if (!input || !expected || expected_len != 64) return -1;  // SHA-512 outputs 64 bytes
    return (memcmp(input, expected, 64) == 0) ? 0 : -1;
}

