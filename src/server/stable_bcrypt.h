#ifndef STABLE_BCRYPT_SERVER_H
#define STABLE_BCRYPT_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bcrypt server-side password hashing (simplified 4-parameter interface)
 */
int stable_bcrypt_hash_server(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t cost_factor,
    uint8_t* output, size_t output_len
);

#ifdef __cplusplus
}
#endif

#endif
