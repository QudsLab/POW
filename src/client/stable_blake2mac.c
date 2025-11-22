#include "stable_blake2mac.h"
#include <string.h>

int stable_blake2mac_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len) {
    if (!input || !expected || expected_len != 16) return -1;
    return (memcmp(input, expected, 16) == 0) ? 0 : -1;
}

