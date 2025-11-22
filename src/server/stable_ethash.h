#ifndef STABLE_ETHASH_SERVER_H
#define STABLE_ETHASH_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int stable_ethash_hash_server(const uint8_t* input, size_t input_len, uint8_t* output);
int stable_ethash_mine_server(uint8_t* header, size_t header_len, size_t nonce_offset,
                               const uint8_t* target, uint64_t max_iterations, uint32_t* found_nonce);

#ifdef __cplusplus
}
#endif

#endif
