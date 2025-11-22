#include "stable_kmac.h"
#include "deps/kmac/kmac.h"
#include <string.h>

int stable_kmac_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    uint8_t key[32] = {0}; // Default key
    const uint8_t custom[] = "";
    
    kmac256(key, 32, input, input_len, custom, 0, output, output_len);
    
    return 0;
}
