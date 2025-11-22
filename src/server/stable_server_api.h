#ifndef STABLE_SERVER_API_H
#define STABLE_SERVER_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Export macros for DLL
#ifdef _WIN32
    #ifdef STABLE_SERVER_EXPORTS
        #define STABLE_SERVER_API __declspec(dllexport)
    #else
        #define STABLE_SERVER_API __declspec(dllimport)
    #endif
#else
    #define STABLE_SERVER_API __attribute__((visibility("default")))
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

// Algorithm IDs (all 39 algorithms)
typedef enum {
    // Password Hashing (1-4)
    STABLE_ARGON2 = 1,
    STABLE_SCRYPT = 2,
    STABLE_BCRYPT = 3,
    STABLE_PBKDF2 = 4,
    
    // Cryptographic Hashing (5-11)
    STABLE_SHA2 = 5,
    STABLE_SHA3 = 6,
    STABLE_BLAKE2 = 7,
    STABLE_BLAKE3 = 8,
    STABLE_KECCAK = 9,
    STABLE_RIPEMD = 10,
    STABLE_WHIRLPOOL = 11,
    
    // Key Derivation (12-14)
    STABLE_HKDF = 12,
    STABLE_X963KDF = 13,
    STABLE_CONCATKDF = 14,
    
    // Proof of Work (15-24)
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
    
    // Message Authentication (25-29)
    STABLE_HMAC = 25,
    STABLE_POLY1305 = 26,
    STABLE_BLAKE2MAC = 27,
    STABLE_KMAC = 28,
    STABLE_GMAC = 29,
    
    // Authenticated Encryption (30-34)
    STABLE_CHACHA20POLY1305 = 30,
    STABLE_AESGCM = 31,
    STABLE_AESCCM = 32,
    STABLE_AESOCB = 33,
    STABLE_AESEAX = 34,
    
    // Specialized (35-39)
    STABLE_SIPHASH = 35,
    STABLE_CUBEHASH = 36,
    STABLE_GROESTL = 37,
    STABLE_SKEIN = 38,
    STABLE_JH = 39
} stable_algorithm_t;

// =============================================================================
// SERVER API - Heavy Computation (Mining, Key Generation, Encryption)
// =============================================================================

/**
 * Get server library version
 */
STABLE_SERVER_API const char* stable_server_version(void);

/**
 * Get last error message
 */
STABLE_SERVER_API const char* stable_server_get_error(void);

/**
 * Get algorithm name
 */
STABLE_SERVER_API const char* stable_server_get_name(stable_algorithm_t algo);

/**
 * Get algorithm category
 */
STABLE_SERVER_API stable_category_t stable_server_get_category(stable_algorithm_t algo);

/**
 * Get algorithm output size
 */
STABLE_SERVER_API size_t stable_server_get_output_size(stable_algorithm_t algo);

// =============================================================================
// HASHING (Server: Compute hash)
// =============================================================================

STABLE_SERVER_API int stable_server_hash(
    stable_algorithm_t algo,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output,
    size_t output_len
);

// =============================================================================
// PASSWORD HASHING (Server: Hash passwords)
// =============================================================================

STABLE_SERVER_API int stable_server_password_hash(
    stable_algorithm_t algo,
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint32_t memory_kb,
    uint32_t parallelism,
    uint8_t* output,
    size_t output_len
);

// =============================================================================
// KEY DERIVATION (Server: Derive keys)
// =============================================================================

STABLE_SERVER_API int stable_server_kdf_derive(
    stable_algorithm_t algo,
    const uint8_t* key_material,
    size_t key_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* output,
    size_t output_len
);

// =============================================================================
// PROOF OF WORK (Server: Mine - find valid nonce)
// =============================================================================

STABLE_SERVER_API int stable_server_pow_mine(
    stable_algorithm_t algo,
    uint8_t* header,
    size_t header_len,
    size_t nonce_offset,
    const uint8_t* target,
    size_t target_len,
    uint64_t max_iterations,
    uint32_t* found_nonce
);

STABLE_SERVER_API int stable_server_pow_hash(
    stable_algorithm_t algo,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output,
    size_t output_len
);

// =============================================================================
// MESSAGE AUTHENTICATION (Server: Compute MAC)
// =============================================================================

STABLE_SERVER_API int stable_server_mac_compute(
    stable_algorithm_t algo,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* output,
    size_t output_len
);

// =============================================================================
// AUTHENTICATED ENCRYPTION (Server: Encrypt)
// =============================================================================

STABLE_SERVER_API int stable_server_aead_encrypt(
    stable_algorithm_t algo,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* tag,
    size_t tag_len
);

#ifdef __cplusplus
}
#endif

#endif // STABLE_SERVER_API_H
