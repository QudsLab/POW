#include "stable_whirlpool.h"
#include "deps/sph/sph_whirlpool.h"
#include <string.h>

int stable_whirlpool_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 64) return -1;
    
    sph_whirlpool_context ctx;
    sph_whirlpool_init(&ctx);
    sph_whirlpool(&ctx, input, input_len);
    sph_whirlpool_close(&ctx, output);
    
    return 0;
}

