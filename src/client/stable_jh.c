#include "stable_jh.h"
#include <string.h>

int stable_jh_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len) {
    if (!input || !expected || expected_len != 64) return -1;
    return (memcmp(input, expected, 64) == 0) ? 0 : -1;
}

