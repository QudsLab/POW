#include "stable_blake2.h"
#include "deps/blake2/blake2.h"
#include <string.h>

int stable_blake2_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 64) return -1;
    
    // Use BLAKE2b-512
    return blake2b(output, 64, input, input_len, NULL, 0);
}
