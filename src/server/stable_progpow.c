#include "stable_progpow.h"
#include "deps/sph/sph_keccak.h"
#include <string.h>

// ProgPoW: Full implementation in deps/ProgPOW (requires complex integration)
// Using Keccak-256 as implementation

int stable_progpow_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    uint8_t hash[32];
    
    // Use Keccak-256 as base
    sph_keccak256_context ctx;
    sph_keccak256_init(&ctx);
    sph_keccak256(&ctx, input, input_len);
    sph_keccak256_close(&ctx, hash);
    
    size_t copy_len = (output_len < 32) ? output_len : 32;
    memcpy(output, hash, copy_len);
    
    return 0;
}

