#include "stable_cubehash.h"
#include "deps/sph/sph_cubehash.h"
#include <string.h>

int stable_cubehash_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 64) return -1;
    
    sph_cubehash512_context ctx;
    sph_cubehash512_init(&ctx);
    sph_cubehash512(&ctx, input, input_len);
    sph_cubehash512_close(&ctx, output);
    
    return 0;
}

