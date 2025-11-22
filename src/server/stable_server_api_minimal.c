// Minimal Server API - Only working algorithms
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define STABLE_SERVER_EXPORT __declspec(dllexport)
#else
#define STABLE_SERVER_EXPORT __attribute__((visibility("default")))
#endif

// Forward declarations for working algorithms
extern int stable_argon2_full_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t, unsigned int, unsigned int);
extern int stable_blake2_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_blake2mac_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_keccak_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_whirlpool_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_sha256d_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_siphash_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_cubehash_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_groestl_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_skein_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_jh_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_x11_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_x13_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_equihash_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_ethash_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_randomx_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_progpow_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);
extern int stable_hmac_hash_server(const char*, size_t, const char*, size_t, unsigned char*, size_t);

// Main unified API
STABLE_SERVER_EXPORT int stable_pow_hash(
    const char* algo,
    const char* input,
    size_t input_len,
    const char* salt,
    size_t salt_len,
    unsigned char* output,
    size_t output_len,
    unsigned int iterations,
    unsigned int memory_cost
) {
    if (!algo || !input || !output) return -1;

    if (strcmp(algo, "argon2") == 0 || strcmp(algo, "argon2_full") == 0) {
        return stable_argon2_full_hash_server(input, input_len, salt, salt_len, output, output_len, iterations, memory_cost);
    }
    else if (strcmp(algo, "blake2") == 0 || strcmp(algo, "blake2b") == 0) {
        return stable_blake2_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "blake2mac") == 0) {
        return stable_blake2mac_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "keccak") == 0 || strcmp(algo, "keccak256") == 0) {
        return stable_keccak_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "whirlpool") == 0) {
        return stable_whirlpool_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "sha256d") == 0 || strcmp(algo, "sha256double") == 0) {
        return stable_sha256d_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "siphash") == 0 || strcmp(algo, "siphash24") == 0) {
        return stable_siphash_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "cubehash") == 0) {
        return stable_cubehash_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "groestl") == 0) {
        return stable_groestl_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "skein") == 0 || strcmp(algo, "skein512") == 0) {
        return stable_skein_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "jh") == 0 || strcmp(algo, "jh256") == 0) {
        return stable_jh_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "x11") == 0) {
        return stable_x11_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "x13") == 0) {
        return stable_x13_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "equihash") == 0) {
        return stable_equihash_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "ethash") == 0) {
        return stable_ethash_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "randomx") == 0) {
        return stable_randomx_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "progpow") == 0) {
        return stable_progpow_hash_server(input, input_len, salt, salt_len, output, output_len);
    }
    else if (strcmp(algo, "hmac") == 0 || strcmp(algo, "hmac_sha256") == 0) {
        return stable_hmac_hash_server(input, input_len, salt, salt_len, output, output_len);
    }

    return -2; // Unknown algorithm
}
