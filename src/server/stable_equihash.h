#ifndef STABLE_EQUIHASH_SERVER_H
#define STABLE_EQUIHASH_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int stable_equihash_hash_server(const uint8_t* input, size_t input_len, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif
