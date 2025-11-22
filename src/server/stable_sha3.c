#include "stable_sha3.h"
#include "deps/sph/sph_keccak.h"
#include <string.h>

int stable_sha3_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    // SHA3-256 using Keccak with SHA3 padding
    sph_keccak256_context ctx;
    sph_keccak256_init(&ctx);
    sph_keccak256(&ctx, input, input_len);
    sph_keccak256_close(&ctx, output);
    
    return 0;
}
