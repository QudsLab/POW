#include "stable_aesgcm.h"
#include "deps/aead/aead.h"
#include <string.h>

int stable_aesgcm_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < input_len + 16) return -1;
    
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t tag[32];
    aes_gcm_encrypt(key, iv, input, input_len, NULL, 0, output, tag);
    memcpy(output + input_len, tag, 16);
    
    return 0;
}