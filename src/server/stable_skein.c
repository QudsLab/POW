#include "stable_skein.h"
#include "deps/sph/sph_skein.h"
#include <string.h>

int stable_skein_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 64) return -1;
    
    sph_skein512_context ctx;
    sph_skein512_init(&ctx);
    sph_skein512(&ctx, input, input_len);
    sph_skein512_close(&ctx, output);
    
    return 0;
}

