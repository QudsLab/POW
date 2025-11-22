// HMAC-SHA256 implementation using SPH
#include "hmac.h"
#include <string.h>

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out) {
    sph_sha256_context ctx;
    uint8_t k[64];
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    
    memset(k, 0, 64);
    if (key_len <= 64) {
        memcpy(k, key, key_len);
    } else {
        sph_sha256_init(&ctx);
        sph_sha256(&ctx, key, key_len);
        sph_sha256_close(&ctx, k);
    }
    
    for (int i = 0; i < 64; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }
    
    sph_sha256_init(&ctx);
    sph_sha256(&ctx, k_ipad, 64);
    sph_sha256(&ctx, data, data_len);
    sph_sha256_close(&ctx, out);
    
    uint8_t temp[32];
    memcpy(temp, out, 32);
    
    sph_sha256_init(&ctx);
    sph_sha256(&ctx, k_opad, 64);
    sph_sha256(&ctx, temp, 32);
    sph_sha256_close(&ctx, out);
}

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out) {
    sph_sha512_context ctx;
    uint8_t k[128];
    uint8_t k_ipad[128];
    uint8_t k_opad[128];
    
    memset(k, 0, 128);
    if (key_len <= 128) {
        memcpy(k, key, key_len);
    } else {
        sph_sha512_init(&ctx);
        sph_sha512(&ctx, key, key_len);
        sph_sha512_close(&ctx, k);
    }
    
    for (int i = 0; i < 128; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }
    
    sph_sha512_init(&ctx);
    sph_sha512(&ctx, k_ipad, 128);
    sph_sha512(&ctx, data, data_len);
    sph_sha512_close(&ctx, out);
    
    uint8_t temp[64];
    memcpy(temp, out, 64);
    
    sph_sha512_init(&ctx);
    sph_sha512(&ctx, k_opad, 128);
    sph_sha512(&ctx, temp, 64);
    sph_sha512_close(&ctx, out);
}
