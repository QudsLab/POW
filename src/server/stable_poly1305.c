#include "stable_poly1305.h"
#include "deps/poly1305/poly1305.h"
#include <string.h>

int stable_poly1305_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 16) return -1;
    
    uint8_t key[32] = {0}; // Default key
    poly1305_auth(input, input_len, key, output);
    
    return 0;
}
