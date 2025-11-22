#include "stable_gmac.h"
#include "deps/gmac/gmac.h"
#include <string.h>

int stable_gmac_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 16) return -1;
    
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    gmac_auth(key, 32, iv, 12, input, input_len, output, output_len);
    
    return 0;
}
