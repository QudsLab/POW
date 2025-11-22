#include "stable_client_api.h"
#include <string.h>
#include <stdio.h>

// Include all client algorithm headers
#include "stable_argon2.h"
#include "stable_scrypt.h"
#include "stable_bcrypt.h"
#include "stable_pbkdf2.h"
#include "stable_sha2.h"
#include "stable_sha3.h"
#include "stable_blake2.h"
#include "stable_blake3.h"
#include "stable_keccak.h"
#include "stable_ripemd.h"
#include "stable_whirlpool.h"
#include "stable_hkdf.h"
#include "stable_x963kdf.h"
#include "stable_concatkdf.h"
#include "stable_sha256d.h"
#include "stable_ethash.h"
#include "stable_equihash.h"
#include "stable_randomx.h"
#include "stable_x11.h"
#include "stable_x13.h"
#include "stable_x16r.h"
#include "stable_lyra2rev2.h"
#include "stable_lyra2z.h"
#include "stable_progpow.h"
#include "stable_hmac.h"
#include "stable_poly1305.h"
#include "stable_blake2mac.h"
#include "stable_kmac.h"
#include "stable_gmac.h"
#include "stable_chacha20poly1305.h"
#include "stable_aesgcm.h"
#include "stable_aesccm.h"
#include "stable_aesocb.h"
#include "stable_aeseax.h"
#include "stable_siphash.h"
#include "stable_cubehash.h"
#include "stable_groestl.h"
#include "stable_skein.h"
#include "stable_jh.h"

static char last_error[256] = {0};

const char* stable_client_version(void) {
    return "1.0.0-stable-client";
}

const char* stable_client_get_error(void) {
    return last_error;
}

const char* stable_client_get_name(stable_algorithm_t algo) {
    switch (algo) {
        case STABLE_ARGON2: return "argon2";
        case STABLE_SCRYPT: return "scrypt";
        case STABLE_BCRYPT: return "bcrypt";
        case STABLE_PBKDF2: return "pbkdf2";
        case STABLE_SHA2: return "sha2";
        case STABLE_SHA3: return "sha3";
        case STABLE_BLAKE2: return "blake2";
        case STABLE_BLAKE3: return "blake3";
        case STABLE_KECCAK: return "keccak";
        case STABLE_RIPEMD: return "ripemd";
        case STABLE_WHIRLPOOL: return "whirlpool";
        case STABLE_HKDF: return "hkdf";
        case STABLE_X963KDF: return "x963kdf";
        case STABLE_CONCATKDF: return "concatkdf";
        case STABLE_SHA256D: return "sha256d";
        case STABLE_ETHASH: return "ethash";
        case STABLE_EQUIHASH: return "equihash";
        case STABLE_RANDOMX: return "randomx";
        case STABLE_X11: return "x11";
        case STABLE_X13: return "x13";
        case STABLE_X16R: return "x16r";
        case STABLE_LYRA2REV2: return "lyra2rev2";
        case STABLE_LYRA2Z: return "lyra2z";
        case STABLE_PROGPOW: return "progpow";
        case STABLE_HMAC: return "hmac";
        case STABLE_POLY1305: return "poly1305";
        case STABLE_BLAKE2MAC: return "blake2mac";
        case STABLE_KMAC: return "kmac";
        case STABLE_GMAC: return "gmac";
        case STABLE_CHACHA20POLY1305: return "chacha20poly1305";
        case STABLE_AESGCM: return "aesgcm";
        case STABLE_AESCCM: return "aesccm";
        case STABLE_AESOCB: return "aesocb";
        case STABLE_AESEAX: return "aeseax";
        case STABLE_SIPHASH: return "siphash";
        case STABLE_CUBEHASH: return "cubehash";
        case STABLE_GROESTL: return "groestl";
        case STABLE_SKEIN: return "skein";
        case STABLE_JH: return "jh";
        default: return "unknown";
    }
}

stable_category_t stable_client_get_category(stable_algorithm_t algo) {
    if (algo >= STABLE_ARGON2 && algo <= STABLE_PBKDF2)
        return STABLE_CAT_PASSWORD_HASHING;
    if (algo >= STABLE_SHA2 && algo <= STABLE_WHIRLPOOL)
        return STABLE_CAT_CRYPTOGRAPHIC_HASHING;
    if (algo >= STABLE_HKDF && algo <= STABLE_CONCATKDF)
        return STABLE_CAT_KEY_DERIVATION;
    if (algo >= STABLE_SHA256D && algo <= STABLE_PROGPOW)
        return STABLE_CAT_PROOF_OF_WORK;
    if (algo >= STABLE_HMAC && algo <= STABLE_GMAC)
        return STABLE_CAT_MESSAGE_AUTHENTICATION;
    if (algo >= STABLE_CHACHA20POLY1305 && algo <= STABLE_AESEAX)
        return STABLE_CAT_AUTHENTICATED_ENCRYPTION;
    if (algo >= STABLE_SIPHASH && algo <= STABLE_JH)
        return STABLE_CAT_SPECIALIZED;
    return (stable_category_t)0;
}

size_t stable_client_get_output_size(stable_algorithm_t algo) {
    switch (algo) {
        case STABLE_ARGON2:
        case STABLE_SCRYPT:
        case STABLE_BCRYPT:
        case STABLE_PBKDF2:
        case STABLE_SHA3:
        case STABLE_BLAKE2:
        case STABLE_BLAKE3:
        case STABLE_KECCAK:
        case STABLE_SHA256D:
            return 32;
        case STABLE_SHA2:  // SHA-512
            return 64;
        case STABLE_RIPEMD:
            return 20;
        case STABLE_WHIRLPOOL:
            return 64;
        default:
            return 32;
    }
}

int stable_client_hash_verify(stable_algorithm_t algo, const uint8_t* input, size_t input_len,
                              const uint8_t* expected_hash, size_t hash_len) {
    if (!input || !expected_hash) {
        snprintf(last_error, sizeof(last_error), "Invalid parameters");
        return STABLE_ERROR_INVALID_PARAM;
    }
    
    // Lightweight verification - call algorithm-specific verify functions
    switch (algo) {
        case STABLE_SHA2:
            return stable_sha2_verify_client(input, input_len, expected_hash, hash_len);
        case STABLE_SHA3:
            return stable_sha3_verify_client(input, input_len, expected_hash, hash_len);
        case STABLE_SHA256D:
            return stable_sha256d_verify_client(input, input_len, expected_hash, hash_len);
        default:
            snprintf(last_error, sizeof(last_error), "Algorithm not supported for verification");
            return STABLE_ERROR_NOT_IMPLEMENTED;
    }
}

int stable_client_password_verify(stable_algorithm_t algo, const uint8_t* password, size_t password_len,
                                  const uint8_t* hash, size_t hash_len, const uint8_t* salt, size_t salt_len,
                                  uint32_t iterations, uint32_t memory_kb, uint32_t parallelism) {
    if (!password || !hash || !salt) {
        snprintf(last_error, sizeof(last_error), "Invalid parameters");
        return STABLE_ERROR_INVALID_PARAM;
    }
    
    // Lightweight password verification
    switch (algo) {
        case STABLE_ARGON2:
            return stable_argon2_verify_client(password, password_len, hash, hash_len);
        case STABLE_SCRYPT:
            return stable_scrypt_verify_client(password, password_len, hash, hash_len);
        case STABLE_BCRYPT:
            return stable_bcrypt_verify_client(password, password_len, hash, hash_len);
        case STABLE_PBKDF2:
            return stable_pbkdf2_verify_client(password, password_len, hash, hash_len);
        default:
            snprintf(last_error, sizeof(last_error), "Not a password hashing algorithm");
            return STABLE_ERROR_INVALID_PARAM;
    }
}

int stable_client_pow_verify(stable_algorithm_t algo, const uint8_t* hash, size_t hash_len,
                             const uint8_t* target, size_t target_len) {
    if (!hash || !target) {
        snprintf(last_error, sizeof(last_error), "Invalid parameters");
        return STABLE_ERROR_INVALID_PARAM;
    }
    
    // Verify hash meets target (compare as big-endian)
    for (int i = (int)hash_len - 1; i >= 0; i--) {
        if (hash[i] < target[i]) {
            return STABLE_SUCCESS;
        } else if (hash[i] > target[i]) {
            snprintf(last_error, sizeof(last_error), "Hash does not meet target");
            return -1;
        }
    }
    
    return STABLE_SUCCESS;
}

int stable_client_pow_verify_header(stable_algorithm_t algo, const uint8_t* header, size_t header_len,
                                    const uint8_t* target, size_t target_len) {
    if (!header || !target) {
        snprintf(last_error, sizeof(last_error), "Invalid parameters");
        return STABLE_ERROR_INVALID_PARAM;
    }
    
    // Lightweight header verification
    switch (algo) {
        case STABLE_SHA256D:
            return stable_sha256d_verify_client(header, header_len, target, target_len);
        case STABLE_RANDOMX:
            return stable_randomx_verify_client(header, header_len, target, target_len);
        case STABLE_ETHASH:
            return stable_ethash_verify_client(header, header_len, target, target_len);
        default:
            snprintf(last_error, sizeof(last_error), "Algorithm not supported for PoW verification");
            return STABLE_ERROR_NOT_IMPLEMENTED;
    }
}

int stable_client_mac_verify(stable_algorithm_t algo, const uint8_t* key, size_t key_len,
                             const uint8_t* message, size_t message_len,
                             const uint8_t* mac, size_t mac_len) {
    if (!key || !message || !mac) {
        snprintf(last_error, sizeof(last_error), "Invalid parameters");
        return STABLE_ERROR_INVALID_PARAM;
    }
    
    // Lightweight MAC verification
    switch (algo) {
        case STABLE_HMAC:
            return stable_hmac_verify_client(message, message_len, mac, mac_len);
        case STABLE_POLY1305:
            return stable_poly1305_verify_client(message, message_len, mac, mac_len);
        default:
            snprintf(last_error, sizeof(last_error), "Algorithm not supported for MAC verification");
            return STABLE_ERROR_NOT_IMPLEMENTED;
    }
}

int stable_client_aead_verify_decrypt(stable_algorithm_t algo, const uint8_t* key, size_t key_len,
                                      const uint8_t* nonce, size_t nonce_len, const uint8_t* aad, size_t aad_len,
                                      const uint8_t* ciphertext, size_t ciphertext_len,
                                      const uint8_t* tag, size_t tag_len,
                                      uint8_t* plaintext, size_t plaintext_len) {
    if (!key || !ciphertext || !tag || !plaintext) {
        snprintf(last_error, sizeof(last_error), "Invalid parameters");
        return STABLE_ERROR_INVALID_PARAM;
    }
    
    // Client-side AEAD verification: lightweight decryption check
    switch (algo) {
        case STABLE_CHACHA20POLY1305:
            return stable_chacha20poly1305_verify_client(ciphertext, ciphertext_len, tag, tag_len);
        case STABLE_AESGCM:
            return stable_aesgcm_verify_client(ciphertext, ciphertext_len, tag, tag_len);
        case STABLE_AESCCM:
            return stable_aesccm_verify_client(ciphertext, ciphertext_len, tag, tag_len);
        case STABLE_AESOCB:
            return stable_aesocb_verify_client(ciphertext, ciphertext_len, tag, tag_len);
        case STABLE_AESEAX:
            return stable_aeseax_verify_client(ciphertext, ciphertext_len, tag, tag_len);
        default:
            snprintf(last_error, sizeof(last_error), "Algorithm not supported for AEAD");
            return STABLE_ERROR_NOT_IMPLEMENTED;
    }
}
