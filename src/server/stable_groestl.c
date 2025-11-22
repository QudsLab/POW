#include "stable_groestl.h"
#include "deps/sph/sph_groestl.h"
#include <string.h>

int stable_groestl_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 64) return -1;
    
    sph_groestl512_context ctx;
    sph_groestl512_init(&ctx);
    sph_groestl512(&ctx, input, input_len);
    sph_groestl512_close(&ctx, output);
    
    return 0;
}

