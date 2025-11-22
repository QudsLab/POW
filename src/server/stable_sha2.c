#include "stable_sha2.h"
#include "deps/sph/sph_sha2.h"
#include <string.h>

int stable_sha2_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 64) return -1;
    
    sph_sha512_context ctx;
    sph_sha512_init(&ctx);
    sph_sha512(&ctx, input, input_len);
    sph_sha512_close(&ctx, output);
    
    return 0;
}
