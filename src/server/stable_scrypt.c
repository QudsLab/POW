#include "stable_scrypt.h"
#include "deps/scrypt/libscrypt.h"
#include <string.h>

// Full parameter interface for scrypt
int stable_scrypt_hash_server(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t n_cost, uint32_t r_cost, uint32_t p_cost,
    uint8_t* output, size_t output_len
) {
    if (!password || !salt || !output || output_len < 32) return -1;
    if (salt_len < 8) return -2;
    
    // Use provided parameters or defaults
    if (n_cost == 0) n_cost = 1024;
    if (r_cost == 0) r_cost = 8;
    if (p_cost == 0) p_cost = 1;
    
    int result = libscrypt_scrypt(
        password, password_len,
        salt, salt_len,
        n_cost, r_cost, p_cost,
        output, output_len
    );
    
    return (result == 0) ? 0 : -2;
}
