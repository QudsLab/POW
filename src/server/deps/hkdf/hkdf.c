// HKDF-SHA256 implementation
#include "hkdf.h"
#include "../hmac/hmac.h"
#include <string.h>

void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t *prk) {
    if (salt_len == 0) {
        uint8_t zero_salt[32] = {0};
        hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

void hkdf_sha256_expand(const uint8_t *prk, size_t prk_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len) {
    uint8_t t[32];
    uint8_t buffer[256];
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t pos = 0;
    
    while (pos < okm_len) {
        size_t buf_pos = 0;
        
        if (t_len > 0) {
            memcpy(buffer, t, t_len);
            buf_pos = t_len;
        }
        
        if (info_len > 0 && buf_pos + info_len < 256) {
            memcpy(buffer + buf_pos, info, info_len);
            buf_pos += info_len;
        }
        
        buffer[buf_pos++] = counter;
        
        hmac_sha256(prk, prk_len, buffer, buf_pos, t);
        t_len = 32;
        
        size_t copy_len = (pos + 32 <= okm_len) ? 32 : (okm_len - pos);
        memcpy(okm + pos, t, copy_len);
        pos += copy_len;
        counter++;
    }
}

void hkdf_sha256(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len) {
    uint8_t prk[32];
    hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    hkdf_sha256_expand(prk, 32, info, info_len, okm, okm_len);
}
