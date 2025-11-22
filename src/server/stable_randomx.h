#ifndef STABLE_RANDOMX_SERVER_H
#define STABLE_RANDOMX_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RandomX server-side mining (CPU-optimized PoW)
 */
int stable_randomx_hash_server(const uint8_t* input, size_t input_len, uint8_t* output);
int stable_randomx_mine_server(uint8_t* header, size_t header_len, size_t nonce_offset, 
                                const uint8_t* target, uint64_t max_iterations, uint32_t* found_nonce);

#ifdef __cplusplus
}
#endif

#endif
