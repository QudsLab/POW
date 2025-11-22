#include "stable_keccak.h"
#include "deps/sph/sph_keccak.h"
#include <string.h>

int stable_keccak_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    sph_keccak256_context ctx;
    sph_keccak256_init(&ctx);
    sph_keccak256(&ctx, input, input_len);
    sph_keccak256_close(&ctx, output);
    
    return 0;
}
