#include "stable_blake2mac.h"
#include "deps/blake2/blake2.h"
#include <string.h>

int stable_blake2mac_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    // Use BLAKE2s-256 as MAC
    uint8_t key[32] = {0}; // Default key
    return blake2s(output, 32, input, input_len, key, 32);
}

