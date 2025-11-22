// ConcatKDF and X963KDF implementations
#include "kdf.h"
#include "sph_sha2.h"
#include <string.h>

void concat_kdf_sha256(const uint8_t *shared_secret, size_t secret_len,
                       const uint8_t *other_info, size_t other_info_len,
                       uint8_t *output, size_t output_len) {
    sph_sha256_context ctx;
    uint8_t counter[4];
    uint8_t hash[32];
    uint32_t counter_val = 1;
    size_t pos = 0;
    
    while (pos < output_len) {
        counter[0] = (counter_val >> 24) & 0xFF;
        counter[1] = (counter_val >> 16) & 0xFF;
        counter[2] = (counter_val >> 8) & 0xFF;
        counter[3] = counter_val & 0xFF;
        
        sph_sha256_init(&ctx);
        sph_sha256(&ctx, counter, 4);
        sph_sha256(&ctx, shared_secret, secret_len);
        if (other_info_len > 0) {
            sph_sha256(&ctx, other_info, other_info_len);
        }
        sph_sha256_close(&ctx, hash);
        
        size_t copy_len = (pos + 32 <= output_len) ? 32 : (output_len - pos);
        memcpy(output + pos, hash, copy_len);
        pos += copy_len;
        counter_val++;
    }
}

void x963_kdf_sha256(const uint8_t *shared_secret, size_t secret_len,
                     const uint8_t *shared_info, size_t shared_info_len,
                     uint8_t *output, size_t output_len) {
    sph_sha256_context ctx;
    uint8_t counter[4];
    uint8_t hash[32];
    uint32_t counter_val = 1;
    size_t pos = 0;
    
    while (pos < output_len) {
        counter[0] = (counter_val >> 24) & 0xFF;
        counter[1] = (counter_val >> 16) & 0xFF;
        counter[2] = (counter_val >> 8) & 0xFF;
        counter[3] = counter_val & 0xFF;
        
        sph_sha256_init(&ctx);
        sph_sha256(&ctx, shared_secret, secret_len);
        sph_sha256(&ctx, counter, 4);
        if (shared_info_len > 0) {
            sph_sha256(&ctx, shared_info, shared_info_len);
        }
        sph_sha256_close(&ctx, hash);
        
        size_t copy_len = (pos + 32 <= output_len) ? 32 : (output_len - pos);
        memcpy(output + pos, hash, copy_len);
        pos += copy_len;
        counter_val++;
    }
}
