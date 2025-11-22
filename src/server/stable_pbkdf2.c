#include "stable_pbkdf2.h"
#include "deps/pbkdf2/pbkdf2.h"
#include <string.h>

// Full parameter interface
int stable_pbkdf2_hash_server(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t* output, size_t output_len
) {
    if (!password || !salt || !output) return -1;
    if (salt_len < 8) return -2;
    
    // Use provided iterations or default
    if (iterations == 0) iterations = 1000;
    if (iterations > 100000) iterations = 100000; // Safety limit
    
    pbkdf2_hmac_sha256(password, password_len, salt, salt_len, iterations, output, output_len);
    return 0;
}
