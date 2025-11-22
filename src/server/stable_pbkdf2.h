#ifndef STABLE_PBKDF2_SERVER_H
#define STABLE_PBKDF2_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int stable_pbkdf2_hash_server(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t* output, size_t output_len
);

#ifdef __cplusplus
}
#endif

#endif
