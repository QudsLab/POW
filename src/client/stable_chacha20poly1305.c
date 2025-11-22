#include "stable_chacha20poly1305.h"
#include <string.h>

int stable_chacha20poly1305_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len) {
    if (!input || !expected || input_len != expected_len) return -1;
    return (memcmp(input, expected, expected_len) == 0) ? 0 : -1;
}

