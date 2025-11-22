// Simplified GMAC implementation using simulated AES-GMAC
#include "gmac.h"
#include "sph_sha2.h"
#include <string.h>

// Simplified GMAC - uses SHA256 as placeholder for AES-GMAC
void gmac_auth(const uint8_t *key, size_t key_len,
               const uint8_t *iv, size_t iv_len,
               const uint8_t *data, size_t data_len,
               uint8_t *tag, size_t tag_len) {
    // Simplified version - use HMAC-like construction with SHA256
    sph_sha256_context ctx;
    sph_sha256_init(&ctx);
    
    if (key) sph_sha256(&ctx, key, key_len);
    if (iv) sph_sha256(&ctx, iv, iv_len);
    if (data) sph_sha256(&ctx, data, data_len);
    
    uint8_t hash[32];
    sph_sha256_close(&ctx, hash);
    
    memcpy(tag, hash, (tag_len < 32) ? tag_len : 32);
}
