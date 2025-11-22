// KMAC256 implementation using Keccak
#include "kmac.h"
#include "sph_keccak.h"
#include <string.h>

static void encode_string(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len) {
    if (in_len < 256) {
        out[0] = 1;
        out[1] = in_len * 8;
        memcpy(out + 2, in, in_len);
        *out_len = in_len + 2;
    } else {
        *out_len = 0;
    }
}

void kmac256(const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len,
             const uint8_t *custom, size_t custom_len,
             uint8_t *output, size_t output_len) {
    sph_keccak256_context ctx;
    uint8_t rate_buffer[136] = {0};
    uint8_t encoded_key[256];
    size_t encoded_key_len;
    uint8_t encoded_custom[256];
    size_t encoded_custom_len;
    
    const uint8_t kmac_name[] = "KMAC";
    uint8_t encoded_name[8];
    size_t encoded_name_len;
    
    encode_string(encoded_name, &encoded_name_len, kmac_name, 4);
    encode_string(encoded_custom, &encoded_custom_len, custom, custom_len);
    encode_string(encoded_key, &encoded_key_len, key, key_len);
    
    sph_keccak256_init(&ctx);
    sph_keccak256(&ctx, encoded_name, encoded_name_len);
    sph_keccak256(&ctx, encoded_custom, encoded_custom_len);
    sph_keccak256(&ctx, encoded_key, encoded_key_len);
    sph_keccak256(&ctx, data, data_len);
    sph_keccak256_close(&ctx, output);
}
