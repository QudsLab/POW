#include "stable_argon2.h"
#include "deps/argon2/argon2.h"
#include <string.h>

// Simplified 4-parameter interface for Argon2
int stable_argon2_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    // Derive salt from input (first 16 bytes or padded)
    uint8_t salt[16];
    if (input_len >= 16) {
        memcpy(salt, input, 16);
    } else {
        memset(salt, 0, 16);
        if (input_len > 0) memcpy(salt, input, input_len);
    }
    
    // Use reasonable parameters for testing: t_cost=2, m_cost=256KB, parallelism=1
    int result = argon2id_hash_raw(
        2,                   // t_cost (time cost)
        256,                 // m_cost (memory cost in KB)
        1,                   // parallelism
        input,               // pwd
        input_len,           // pwdlen
        salt,                // salt
        16,                  // saltlen
        output,              // hash
        output_len           // hashlen
    );
    
    return (result == ARGON2_OK) ? 0 : -1;
}
