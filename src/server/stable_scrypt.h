#ifndef STABLE_SCRYPT_SERVER_H
#define STABLE_SCRYPT_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Scrypt server-side password hashing (simplified 4-parameter interface)
 */
int stable_scrypt_hash_server(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t n_cost, uint32_t r_cost, uint32_t p_cost,
    uint8_t* output, size_t output_len
);

#ifdef __cplusplus
}
#endif

#endif // STABLE_SCRYPT_SERVER_H
