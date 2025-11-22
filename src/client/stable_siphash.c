#include "stable_siphash.h"
#include <string.h>

int stable_siphash_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len) {
    if (!input || !expected || expected_len != 8) return -1;
    return (memcmp(input, expected, 8) == 0) ? 0 : -1;
}

