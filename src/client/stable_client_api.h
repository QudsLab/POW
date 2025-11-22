#ifndef STABLE_CLIENT_API_H
#define STABLE_CLIENT_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Export macros for DLL
#ifdef _WIN32
    #ifdef STABLE_CLIENT_EXPORTS
        #define STABLE_CLIENT_API __declspec(dllexport)
    #else
        #define STABLE_CLIENT_API __declspec(dllimport)
    #endif
#else
    #define STABLE_CLIENT_API __attribute__((visibility("default")))
#endif

// Return codes
#define STABLE_SUCCESS 0
#define STABLE_ERROR_INVALID_PARAM -1
#define STABLE_ERROR_BUFFER_TOO_SMALL -2
#define STABLE_ERROR_NOT_IMPLEMENTED -3
#define STABLE_ERROR_MEMORY -4

// Algorithm categories
typedef enum {
    STABLE_CAT_PASSWORD_HASHING = 1,
    STABLE_CAT_CRYPTOGRAPHIC_HASHING = 2,
    STABLE_CAT_KEY_DERIVATION = 3,
    STABLE_CAT_PROOF_OF_WORK = 4,
    STABLE_CAT_MESSAGE_AUTHENTICATION = 5,
    STABLE_CAT_AUTHENTICATED_ENCRYPTION = 6,
    STABLE_CAT_SPECIALIZED = 7
} stable_category_t;

// Algorithm IDs (same as server)
typedef enum {
    STABLE_ARGON2 = 1,
    STABLE_SCRYPT = 2,
    STABLE_BCRYPT = 3,
    STABLE_PBKDF2 = 4,
    STABLE_SHA2 = 5,
    STABLE_SHA3 = 6,
    STABLE_BLAKE2 = 7,
    STABLE_BLAKE3 = 8,
    STABLE_KECCAK = 9,
    STABLE_RIPEMD = 10,
    STABLE_WHIRLPOOL = 11,
    STABLE_HKDF = 12,
    STABLE_X963KDF = 13,
    STABLE_CONCATKDF = 14,
    STABLE_SHA256D = 15,
    STABLE_ETHASH = 16,
    STABLE_EQUIHASH = 17,
    STABLE_RANDOMX = 18,
    STABLE_X11 = 19,
    STABLE_X13 = 20,
    STABLE_X16R = 21,
    STABLE_LYRA2REV2 = 22,
    STABLE_LYRA2Z = 23,
    STABLE_PROGPOW = 24,
    STABLE_HMAC = 25,
    STABLE_POLY1305 = 26,
    STABLE_BLAKE2MAC = 27,
    STABLE_KMAC = 28,
    STABLE_GMAC = 29,
    STABLE_CHACHA20POLY1305 = 30,
    STABLE_AESGCM = 31,
    STABLE_AESCCM = 32,
    STABLE_AESOCB = 33,
    STABLE_AESEAX = 34,
    STABLE_SIPHASH = 35,
    STABLE_CUBEHASH = 36,
    STABLE_GROESTL = 37,
    STABLE_SKEIN = 38,
    STABLE_JH = 39
} stable_algorithm_t;

// =============================================================================
// CLIENT API - Lightweight Verification (Verify, Decrypt, Check)
// =============================================================================

/**
 * Get client library version
 */
STABLE_CLIENT_API const char* stable_client_version(void);

/**
 * Get last error message
 */
STABLE_CLIENT_API const char* stable_client_get_error(void);

/**
 * Get algorithm name
 */
STABLE_CLIENT_API const char* stable_client_get_name(stable_algorithm_t algo);

/**
 * Get algorithm output size
 */
STABLE_CLIENT_API size_t stable_client_get_output_size(stable_algorithm_t algo);

// =============================================================================
// HASHING (Client: Verify hash - lightweight)
// =============================================================================

STABLE_CLIENT_API int stable_client_hash_verify(
    stable_algorithm_t algo,
    const uint8_t* input,
    size_t input_len,
    const uint8_t* expected_hash,
    size_t hash_len
);

// =============================================================================
// PASSWORD HASHING (Client: Verify password)
// =============================================================================

STABLE_CLIENT_API int stable_client_password_verify(
    stable_algorithm_t algo,
    const uint8_t* password,
    size_t password_len,
    const uint8_t* hash,
    size_t hash_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint32_t memory_kb,
    uint32_t parallelism
);

// =============================================================================
// PROOF OF WORK (Client: Verify hash meets target - lightweight)
// =============================================================================

STABLE_CLIENT_API int stable_client_pow_verify(
    stable_algorithm_t algo,
    const uint8_t* hash,
    size_t hash_len,
    const uint8_t* target,
    size_t target_len
);

STABLE_CLIENT_API int stable_client_pow_check_header(
    stable_algorithm_t algo,
    const uint8_t* header,
    size_t header_len,
    const uint8_t* target,
    size_t target_len
);

// =============================================================================
// MESSAGE AUTHENTICATION (Client: Verify MAC)
// =============================================================================

STABLE_CLIENT_API int stable_client_mac_verify(
    stable_algorithm_t algo,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* mac,
    size_t mac_len
);

// =============================================================================
// AUTHENTICATED ENCRYPTION (Client: Decrypt and verify)
// =============================================================================

STABLE_CLIENT_API int stable_client_aead_decrypt(
    stable_algorithm_t algo,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    size_t tag_len,
    uint8_t* plaintext,
    size_t plaintext_len
);

// =============================================================================
// UTILITY (Client: Format, display)
// =============================================================================

STABLE_CLIENT_API int stable_client_format_hash(
    const uint8_t* hash,
    size_t hash_len,
    char* output,
    size_t output_len
);

STABLE_CLIENT_API int stable_client_parse_hash(
    const char* hash_str,
    uint8_t* output,
    size_t output_len
);

#ifdef __cplusplus
}
#endif

#endif // STABLE_CLIENT_API_H
