// Simplified AES-AEAD modes (placeholder using SHA256)
#include "aead.h"
#include "sph_sha2.h"
#include <string.h>

void aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag) {
    sph_sha256_context ctx;
    sph_sha256_init(&ctx);
    sph_sha256(&ctx, key, 32);
    sph_sha256(&ctx, iv, 12);
    if (ad) sph_sha256(&ctx, ad, ad_len);
    if (plaintext) {
        sph_sha256(&ctx, plaintext, plaintext_len);
        memcpy(ciphertext, plaintext, plaintext_len);
    }
    sph_sha256_close(&ctx, tag);
}

void aes_ccm_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag) {
    aes_gcm_encrypt(key, nonce, plaintext, plaintext_len, ad, ad_len, ciphertext, tag);
}

void aes_ocb_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag) {
    aes_gcm_encrypt(key, nonce, plaintext, plaintext_len, ad, ad_len, ciphertext, tag);
}

void aes_eax_encrypt(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *ad, size_t ad_len,
                     uint8_t *ciphertext, uint8_t *tag) {
    aes_gcm_encrypt(key, nonce, plaintext, plaintext_len, ad, ad_len, ciphertext, tag);
}
