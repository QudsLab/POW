#include "stable_bcrypt.h"
#include <string.h>

int stable_bcrypt_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len) {
    if (!input || !expected || expected_len < 60) return -1;
    return (memcmp(input, expected, expected_len) == 0) ? 0 : -1;
}

