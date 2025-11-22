#include "stable_hmac.h"
#include "deps/hmac/hmac.h"
#include <string.h>

int stable_hmac_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    uint8_t key[32] = {0}; // Default key
    hmac_sha256(key, 32, input, input_len, output);
    
    return 0;
}
