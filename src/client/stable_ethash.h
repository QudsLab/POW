#ifndef STABLE_ethash_CLIENT_H
#define STABLE_ethash_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int stable_ethash_verify_client(const uint8_t* input, size_t input_len, const uint8_t* expected, size_t expected_len);

#ifdef __cplusplus
}
#endif

#endif

