// Simple PBKDF2-HMAC-SHA256 implementation in C
#include "pbkdf2.h"
#include <string.h>

// Simple HMAC-SHA256 using SPH
static void hmac_sha256(const uint8_t *key, size_t key_len,
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

void pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t *out, size_t out_len) {
    uint8_t block[32];
    uint8_t temp[32];
    uint8_t salt_block[256];
    
    if (salt_len > 252) salt_len = 252;
    memcpy(salt_block, salt, salt_len);
    
    size_t blocks = (out_len + 31) / 32;
    
    for (uint32_t block_num = 1; block_num <= blocks; block_num++) {
        salt_block[salt_len] = (block_num >> 24) & 0xff;
        salt_block[salt_len + 1] = (block_num >> 16) & 0xff;
        salt_block[salt_len + 2] = (block_num >> 8) & 0xff;
        salt_block[salt_len + 3] = block_num & 0xff;
        
        hmac_sha256(password, password_len, salt_block, salt_len + 4, block);
        memcpy(temp, block, 32);
        
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha256(password, password_len, temp, 32, temp);
            for (int j = 0; j < 32; j++) {
                block[j] ^= temp[j];
            }
        }
        
        size_t offset = (block_num - 1) * 32;
        size_t copy_len = (offset + 32 <= out_len) ? 32 : (out_len - offset);
        memcpy(out + offset, block, copy_len);
    }
}
