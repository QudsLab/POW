#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>

void aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag);

void aes_ccm_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag);

void aes_ocb_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag);

void aes_eax_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag);

#endif
