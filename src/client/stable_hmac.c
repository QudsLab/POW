#include "stable_hmac.h"
#include <string.h>

int stable_hmac_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len) {
    if (!input || !expected || expected_len != 32) return -1;
    return (memcmp(input, expected, 32) == 0) ? 0 : -1;
}

