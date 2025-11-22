#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

void chacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t *ad, size_t ad_len,
                                uint8_t *ciphertext, uint8_t *tag);

#endif
