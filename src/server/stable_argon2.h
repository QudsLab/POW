#ifndef STABLE_ARGON2_SERVER_H
#define STABLE_ARGON2_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Argon2 server-side password hashing (full parameter interface)
 * Heavy computation for password generation
 */
int stable_argon2_hash_server(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t* output, size_t output_len
);

#ifdef __cplusplus
}
#endif

#endif // STABLE_ARGON2_SERVER_H
