#ifndef STABLE_SHA2_SERVER_H
#define STABLE_SHA2_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int stable_sha2_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif
