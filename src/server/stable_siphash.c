#include "stable_siphash.h"
#include "deps/siphash/siphash.h"
#include <string.h>

int stable_siphash_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 8) return -1;
    
    // SipHash-2-4 with default key (zeros)
    uint8_t key[16] = {0};
    siphash(input, input_len, key, output, 8);
    
    return 0;
}
