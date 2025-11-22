#include "stable_ripemd.h"
#include "deps/sph/sph_ripemd.h"
#include <string.h>

int stable_ripemd_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 20) return -1;
    
    sph_ripemd160_context ctx;
    sph_ripemd160_init(&ctx);
    sph_ripemd160(&ctx, input, input_len);
    sph_ripemd160_close(&ctx, output);
    
    return 0;
}
