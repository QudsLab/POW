#include "stable_jh.h"
#include "deps/sph/sph_jh.h"
#include <string.h>

int stable_jh_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 64) return -1;
    
    sph_jh512_context ctx;
    sph_jh512_init(&ctx);
    sph_jh512(&ctx, input, input_len);
    sph_jh512_close(&ctx, output);
    
    return 0;
}

