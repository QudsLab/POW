#include "stable_blake3.h"
#include "deps/blake3_simple/blake3_simple.h"
#include <string.h>

int stable_blake3_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    blake3_hash(input, input_len, output);
    
    return 0;
}