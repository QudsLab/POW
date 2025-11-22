// Simplified ChaCha20-Poly1305 AEAD (placeholder using SHA256)
#include "chacha20poly1305.h"
#include "sph_sha2.h"
#include <string.h>

void chacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t *ad, size_t ad_len,
                                uint8_t *ciphertext, uint8_t *tag) {
    // Placeholder implementation
    sph_sha256_context ctx;
    sph_sha256_init(&ctx);
    if (key) sph_sha256(&ctx, key, 32);
    if (nonce) sph_sha256(&ctx, nonce, 12);
    if (ad) sph_sha256(&ctx, ad, ad_len);
    if (plaintext) {
        sph_sha256(&ctx, plaintext, plaintext_len);
        memcpy(ciphertext, plaintext, plaintext_len);
    }
    sph_sha256_close(&ctx, tag);
}
