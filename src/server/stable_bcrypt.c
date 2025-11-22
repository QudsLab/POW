#include "stable_bcrypt.h"
#include "deps/sph/sph_sha2.h"
#include <string.h>
#include <stdio.h>

// Full parameter interface for bcrypt
int stable_bcrypt_hash_server(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t cost_factor,
    uint8_t* output, size_t output_len
) {
    if (!password || !salt || !output || output_len < 60) return -1;
    if (salt_len < 16) return -2;
    
    // Use provided cost or default
    if (cost_factor == 0) cost_factor = 4;
    if (cost_factor > 12) cost_factor = 12; // Safety limit
    
    // Simplified bcrypt using SHA-256
    sph_sha256_context ctx;
    sph_sha256_init(&ctx);
    
    // Hash password with salt and cost iterations
    for (uint32_t i = 0; i < (1 << cost_factor); i++) {
        sph_sha256(&ctx, password, password_len);
        sph_sha256(&ctx, salt, salt_len < 16 ? salt_len : 16);
    }
    
    uint8_t hash[32];
    sph_sha256_close(&ctx, hash);
    
    // Format as bcrypt-style string
    snprintf((char*)output, output_len, "$2a$%02u$", cost_factor);
    for (size_t i = 0; i < 22 && 7 + i < output_len - 1; i++) {
        output[7 + i] = 'A' + (hash[i] % 26);
    }
    
    return 0;
}
