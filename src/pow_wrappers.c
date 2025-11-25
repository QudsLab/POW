#include "pow_wrappers.h"
#include <string.h>
#include <stdlib.h>

/**
 * pow_wrappers.c - Unified wrapper implementations for all PoW algorithms
 * Routes solve/verify calls to appropriate algorithm implementations
 */

const char *pow_type_name(pow_type_e pow_type) {
    switch (pow_type) {
        case POW_BLAKE3:    return "blake3";
        case POW_SHA2:      return "sha2";
        case POW_KECCAK:    return "keccak";
        case POW_SCRYPT:    return "scrypt";
        case POW_ARGON2:    return "argon2";
        case POW_ZHASH:     return "zhash";
        default:            return NULL;
    }
}

pow_type_e pow_type_from_name(const char *name) {
    if (!name) return POW_INVALID;
    
    if (strcmp(name, "blake3") == 0)    return POW_BLAKE3;
    if (strcmp(name, "sha2") == 0)      return POW_SHA2;
    if (strcmp(name, "keccak") == 0)    return POW_KECCAK;
    if (strcmp(name, "scrypt") == 0)    return POW_SCRYPT;
    if (strcmp(name, "argon2") == 0)    return POW_ARGON2;
    if (strcmp(name, "zhash") == 0)     return POW_ZHASH;
    
    return POW_INVALID;
}

// Forward declarations for algorithm-specific functions
int cb_blake3_solve(const uint8_t *challenge, size_t challenge_len, uint8_t *out_solution, size_t *out_solution_len);
int cb_blake3_verify(const uint8_t *challenge, size_t challenge_len, const uint8_t *solution, size_t solution_len);
int cb_sha2_solve(const uint8_t *challenge, size_t challenge_len, uint8_t *out_solution, size_t *out_solution_len);
int cb_sha2_verify(const uint8_t *challenge, size_t challenge_len, const uint8_t *solution, size_t solution_len);
int cb_keccak_solve(const uint8_t *challenge, size_t challenge_len, uint8_t *out_solution, size_t *out_solution_len);
int cb_keccak_verify(const uint8_t *challenge, size_t challenge_len, const uint8_t *solution, size_t solution_len);
int mb_scrypt_solve(const uint8_t *challenge, size_t challenge_len, uint8_t *out_solution, size_t *out_solution_len);
int mb_scrypt_verify(const uint8_t *challenge, size_t challenge_len, const uint8_t *solution, size_t solution_len);
int mb_argon_solve(const uint8_t *challenge, size_t challenge_len, uint8_t *out_solution, size_t *out_solution_len);
int mb_argon_verify(const uint8_t *challenge, size_t challenge_len, const uint8_t *solution, size_t solution_len);
int hb_zhash_solve(const uint8_t *challenge, size_t challenge_len, uint8_t *out_solution, size_t *out_solution_len);
int hb_zhash_verify(const uint8_t *challenge, size_t challenge_len, const uint8_t *solution, size_t solution_len);


int pow_solve(pow_type_e pow_type,
             const uint8_t *challenge, size_t challenge_len,
             const uint8_t *params, size_t params_len,
             uint8_t *out_solution, size_t *out_solution_len) {
    if (!challenge || !out_solution || !out_solution_len) return -1;
    
    (void)params;  // Unused for now
    (void)params_len;
    
    switch (pow_type) {
        case POW_BLAKE3:
            return cb_blake3_solve(challenge, challenge_len, out_solution, out_solution_len);
        case POW_SHA2:
            return cb_sha2_solve(challenge, challenge_len, out_solution, out_solution_len);
        case POW_KECCAK:
            return cb_keccak_solve(challenge, challenge_len, out_solution, out_solution_len);
        case POW_SCRYPT:
            return mb_scrypt_solve(challenge, challenge_len, out_solution, out_solution_len);
        case POW_ARGON2:
            return mb_argon_solve(challenge, challenge_len, out_solution, out_solution_len);
        case POW_ZHASH:
            return hb_zhash_solve(challenge, challenge_len, out_solution, out_solution_len);
        default:
            return -1;  // Invalid algorithm type
    }
}


int pow_verify(pow_type_e pow_type,
              const uint8_t *challenge, size_t challenge_len,
              const uint8_t *solution, size_t solution_len,
              const uint8_t *params, size_t params_len) {
    if (!challenge || !solution) return -1;
    
    (void)params;  // Unused for now
    (void)params_len;
    
    switch (pow_type) {
        case POW_BLAKE3:
            return cb_blake3_verify(challenge, challenge_len, solution, solution_len);
        case POW_SHA2:
            return cb_sha2_verify(challenge, challenge_len, solution, solution_len);
        case POW_KECCAK:
            return cb_keccak_verify(challenge, challenge_len, solution, solution_len);
        case POW_SCRYPT:
            return mb_scrypt_verify(challenge, challenge_len, solution, solution_len);
        case POW_ARGON2:
            return mb_argon_verify(challenge, challenge_len, solution, solution_len);
        case POW_ZHASH:
            return hb_zhash_verify(challenge, challenge_len, solution, solution_len);
        default:
            return -1;  // Invalid algorithm type
    }
}

/* Stub implementations for all algorithm solvers and verifiers */

/* BLAKE3 */
// Real BLAKE3 PoW: find nonce so that blake3(challenge || nonce) meets difficulty
#include "cb_blake3/blake3.h"
#include "pow_utils.h"

int cb_blake3_solve(const uint8_t *challenge, size_t challenge_len,
                   uint8_t *out_solution, size_t *out_solution_len) {
    if (!challenge || !out_solution || !out_solution_len) return -1;
    
    size_t nonce_len = 8;
    *out_solution_len = nonce_len;
    uint32_t difficulty = 1; // 1 leading zero bit
    uint64_t max_iterations = 100000;
    
    // Brute-force search for valid nonce
    uint8_t nonce[8] = {0};
    uint8_t hash[32];
    
    for (uint64_t iter = 0; iter < max_iterations; iter++) {
        // Compute hash
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, challenge, challenge_len);
        blake3_hasher_update(&hasher, nonce, nonce_len);
        blake3_hasher_finalize(&hasher, hash, 32);
        
        // Check if meets difficulty
        if (pow_verify_hash_difficulty(hash, 32, difficulty)) {
            memcpy(out_solution, nonce, nonce_len);
            return 0; // Success
        }
        
        // Increment nonce
        for (size_t i = 0; i < nonce_len; i++) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }
    
    return -1; // No valid nonce found
}

int cb_blake3_verify(const uint8_t *challenge, size_t challenge_len,
                    const uint8_t *solution, size_t solution_len) {
    if (!challenge || !solution) return -1;
    
    // Compute BLAKE3 hash of challenge + solution
    uint8_t hash[32];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, challenge, challenge_len);
    blake3_hasher_update(&hasher, solution, solution_len);
    blake3_hasher_finalize(&hasher, hash, 32);
    
    // Check if hash meets difficulty (at least 1 leading zero bit)
    uint32_t difficulty = 1;
    int result = pow_verify_hash_difficulty(hash, 32, difficulty);
    return result; // Returns 1 if valid, 0 if not
}

/* SHA2 */
// Real SHA2 PoW: find nonce so that sha256(challenge || nonce) meets difficulty
#include "cb_sha2/sha2.h"

int cb_sha2_solve(const uint8_t *challenge, size_t challenge_len,
                 uint8_t *out_solution, size_t *out_solution_len) {
    if (!challenge || !out_solution || !out_solution_len) return -1;
    
    size_t nonce_len = 8;
    *out_solution_len = nonce_len;
    uint32_t difficulty = 1;
    uint64_t max_iterations = 100000;
    
    // Brute-force search for valid nonce
    uint8_t nonce[8] = {0};
    uint8_t hash[32];
    
    for (uint64_t iter = 0; iter < max_iterations; iter++) {
        // Compute hash
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, challenge, challenge_len);
        sha256_update(&ctx, nonce, nonce_len);
        sha256_final(&ctx, hash);
        
        // Check if meets difficulty
        if (pow_verify_hash_difficulty(hash, 32, difficulty)) {
            memcpy(out_solution, nonce, nonce_len);
            return 0; // Success
        }
        
        // Increment nonce
        for (size_t i = 0; i < nonce_len; i++) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }
    
    return -1; // No valid nonce found
}

int cb_sha2_verify(const uint8_t *challenge, size_t challenge_len,
                  const uint8_t *solution, size_t solution_len) {
    if (!challenge || !solution) return -1;
    
    // Compute SHA256 hash of challenge + solution
    uint8_t hash[32];
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, challenge, challenge_len);
    sha256_update(&ctx, solution, solution_len);
    sha256_final(&ctx, hash);
    
    // Check if hash meets difficulty (at least 1 leading zero bit)
    uint32_t difficulty = 1;
    int result = pow_verify_hash_difficulty(hash, 32, difficulty);
    return result; // Returns 1 if valid, 0 if not
}

/* KECCAK */
// Real KECCAK PoW: find nonce so that keccak256(challenge || nonce) meets difficulty
#include "cb_keccak/keccak.h"

int cb_keccak_solve(const uint8_t *challenge, size_t challenge_len,
                   uint8_t *out_solution, size_t *out_solution_len) {
    if (!challenge || !out_solution || !out_solution_len) return -1;
    
    size_t nonce_len = 8;
    *out_solution_len = nonce_len;
    uint32_t difficulty = 1;
    uint64_t max_iterations = 100000;
    
    // Brute-force search for valid nonce
    uint8_t nonce[8] = {0};
    uint8_t hash[32];
    
    for (uint64_t iter = 0; iter < max_iterations; iter++) {
        // Compute hash
        size_t total_len = challenge_len + nonce_len;
        uint8_t *input = (uint8_t*)malloc(total_len);
        if (!input) return -1;
        
        memcpy(input, challenge, challenge_len);
        memcpy(input + challenge_len, nonce, nonce_len);
        /* Ensure hash buffer is clean before hashing */
        memset(hash, 0, sizeof(hash));
        sha3_256(input, (int)total_len, hash);
        free(input);
        
        // Check if meets difficulty
        if (pow_verify_hash_difficulty(hash, 32, difficulty)) {
            memcpy(out_solution, nonce, nonce_len);
            return 0; // Success
        }
        
        // Increment nonce
        for (size_t i = 0; i < nonce_len; i++) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }
    
    return -1; // No valid nonce found
}

int cb_keccak_verify(const uint8_t *challenge, size_t challenge_len,
                    const uint8_t *solution, size_t solution_len) {
    if (!challenge || !solution) return -1;
    
    // Combine challenge and solution into a single buffer
    size_t total_len = challenge_len + solution_len;
    uint8_t *input = (uint8_t*)malloc(total_len);
    if (!input) return -1;
    
    memcpy(input, challenge, challenge_len);
    memcpy(input + challenge_len, solution, solution_len);
    
    // Ensure hash buffer is zeroed before hashing
    uint8_t hash[32];
    memset(hash, 0, sizeof(hash));
    sha3_256(input, (int)total_len, hash);
    free(input);
    
    // Use difficulty consistent with other verifiers (1 leading zero bit)
    uint32_t difficulty = 1;
    return pow_verify_hash_difficulty(hash, 32, difficulty);
}

/* SCRYPT */
// Real SCRYPT PoW: find nonce so that scrypt(challenge || nonce) meets difficulty
#include "mb_scrypt/scrypt.h"

int mb_scrypt_solve(const uint8_t *challenge, size_t challenge_len,
                   uint8_t *out_solution, size_t *out_solution_len) {
    if (!challenge || !out_solution || !out_solution_len) return -1;
    
    size_t nonce_len = 8;
    *out_solution_len = nonce_len;
    uint32_t difficulty = 1;
    uint64_t max_iterations = 10000; // Lower for slow Scrypt
    
    // Brute-force search for valid nonce
    uint8_t nonce[8] = {0};
    uint8_t hash[32];
    
    for (uint64_t iter = 0; iter < max_iterations; iter++) {
        // Compute hash
        size_t total_len = challenge_len + nonce_len;
        uint8_t *input = (uint8_t*)malloc(total_len);
        if (!input) return -1;
        
        int result;
        
        memcpy(input, challenge, challenge_len);
        memcpy(input + challenge_len, nonce, nonce_len);
        
        result = scrypt(input, total_len, input, total_len, 1024, 8, 1, hash, 32);
        free(input);
        
        if (result != 0) continue;
        
        // Check if meets difficulty
        if (pow_verify_hash_difficulty(hash, 32, difficulty)) {
            memcpy(out_solution, nonce, nonce_len);
            return 0; // Success
        }
        
        // Increment nonce
        for (size_t i = 0; i < nonce_len; i++) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }
    
    return -1; // No valid nonce found
}

int mb_scrypt_verify(const uint8_t *challenge, size_t challenge_len,
                    const uint8_t *solution, size_t solution_len) {
    if (!challenge || !solution) return -1;
    
    // Compute Scrypt hash of challenge + solution
    uint8_t hash[32];
    size_t total_len = challenge_len + solution_len;
    uint8_t *input = (uint8_t*)malloc(total_len);
    if (!input) return -1;
    
    memcpy(input, challenge, challenge_len);
    memcpy(input + challenge_len, solution, solution_len);
    
    // Scrypt params: N=1024 (low for testing), r=8, p=1
    int scrypt_result = scrypt(input, total_len, input, total_len, 1024, 8, 1, hash, 32);
    free(input);
    
    if (scrypt_result != 0) return -1;
    
    // Check if hash meets difficulty (at least 1 leading zero bit)
    uint32_t difficulty = 1;
    int result = pow_verify_hash_difficulty(hash, 32, difficulty);
    return result; // Returns 1 if valid, 0 if not
}

/* ARGON2 */
// Real ARGON2 PoW: find nonce so that argon2(challenge || nonce) meets difficulty
#include "mb_argon/argon2.h"

int mb_argon_solve(const uint8_t *challenge, size_t challenge_len,
                  uint8_t *out_solution, size_t *out_solution_len) {
    if (!challenge || !out_solution || !out_solution_len) return -1;
    
    size_t nonce_len = 8;
    *out_solution_len = nonce_len;
    uint32_t difficulty = 1;
    uint64_t max_iterations = 5000; // Lower for slow Argon2
    
    // Brute-force search for valid nonce
    uint8_t nonce[8] = {0};
    uint8_t hash[32];
    
    for (uint64_t iter = 0; iter < max_iterations; iter++) {
        // Compute hash
        size_t total_len = challenge_len + nonce_len;
        uint8_t *input = (uint8_t*)malloc(total_len);
        if (!input) return -1;
        
        memcpy(input, challenge, challenge_len);
        memcpy(input + challenge_len, nonce, nonce_len);
        
        argon2_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.out = hash;
        ctx.outlen = 32;
        ctx.pwd = input;
        ctx.pwdlen = (uint32_t)total_len;
        ctx.salt = input;
        ctx.saltlen = (uint32_t)total_len;
        ctx.t_cost = 2;
        ctx.m_cost = 4096;
        ctx.lanes = 1;
        ctx.threads = 1;
        ctx.version = ARGON2_VERSION_NUMBER;
        ctx.flags = ARGON2_DEFAULT_FLAGS;
        
        int result = argon2_ctx(&ctx, Argon2_id);
        free(input);
        
        if (result != ARGON2_OK) continue;
        
        // Check if meets difficulty
        if (pow_verify_hash_difficulty(hash, 32, difficulty)) {
            memcpy(out_solution, nonce, nonce_len);
            return 0; // Success
        }
        
        // Increment nonce
        for (size_t i = 0; i < nonce_len; i++) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }
    
    return -1; // No valid nonce found
}

int mb_argon_verify(const uint8_t *challenge, size_t challenge_len,
                   const uint8_t *solution, size_t solution_len) {
    if (!challenge || !solution) return -1;
    
    // Compute Argon2 hash of challenge + solution
    uint8_t hash[32];
    size_t total_len = challenge_len + solution_len;
    uint8_t *input = (uint8_t*)malloc(total_len);
    if (!input) return -1;
    
    memcpy(input, challenge, challenge_len);
    memcpy(input + challenge_len, solution, solution_len);
    
    // Argon2 params: t_cost=2, m_cost=4096 (low for testing), parallelism=1
    argon2_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.out = hash;
    ctx.outlen = 32;
    ctx.pwd = input;
    ctx.pwdlen = (uint32_t)total_len;
    ctx.salt = input;
    ctx.saltlen = (uint32_t)total_len;
    ctx.t_cost = 2;
    ctx.m_cost = 4096; // Lower memory for faster testing
    ctx.lanes = 1;
    ctx.threads = 1;
    ctx.version = ARGON2_VERSION_NUMBER;
    ctx.flags = ARGON2_DEFAULT_FLAGS;
    
    int argon_result = argon2_ctx(&ctx, Argon2_id);
    free(input);
    
    if (argon_result != ARGON2_OK) return -1;
    
    // Check if hash meets difficulty (at least 1 leading zero bit)
    uint32_t difficulty = 1;
    int result = pow_verify_hash_difficulty(hash, 32, difficulty);
    return result; // Returns 1 if valid, 0 if not
}

/* ZHASH */
// Real ZHASH PoW: find nonce so that zhash(challenge || nonce) meets difficulty
#include "hb_zhash/zhash.h"

int hb_zhash_solve(const uint8_t *challenge, size_t challenge_len,
                  uint8_t *out_solution, size_t *out_solution_len) {
    if (!challenge || !out_solution || !out_solution_len) return -1;
    
    size_t nonce_len = 8;
    *out_solution_len = nonce_len;
    uint32_t difficulty = 1;
    uint64_t max_iterations = 100000;
    
    // Brute-force search for valid nonce using BLAKE3
    uint8_t nonce[8] = {0};
    uint8_t hash[32];
    
    for (uint64_t iter = 0; iter < max_iterations; iter++) {
        // Compute hash
        size_t total_len = challenge_len + nonce_len;
        uint8_t *input = (uint8_t*)malloc(total_len);
        if (!input) return -1;
        
        memcpy(input, challenge, challenge_len);
        memcpy(input + challenge_len, nonce, nonce_len);
        
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, input, total_len);
        blake3_hasher_finalize(&hasher, hash, 32);
        free(input);
        
        // Check if meets difficulty
        if (pow_verify_hash_difficulty(hash, 32, difficulty)) {
            memcpy(out_solution, nonce, nonce_len);
            return 0; // Success
        }
        
        // Increment nonce
        for (size_t i = 0; i < nonce_len; i++) {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }
    }
    
    return -1; // No valid nonce found
}

int hb_zhash_verify(const uint8_t *challenge, size_t challenge_len,
                   const uint8_t *solution, size_t solution_len) {
    if (!challenge || !solution) return -1;
    
    // Note: zhash is a hash table library, not a hash function
    // Using BLAKE3 as the underlying hash for PoW verification
    uint8_t hash[32];
    size_t total_len = challenge_len + solution_len;
    uint8_t *input = (uint8_t*)malloc(total_len);
    if (!input) return -1;
    
    memcpy(input, challenge, challenge_len);
    memcpy(input + challenge_len, solution, solution_len);
    
    // Compute BLAKE3 hash
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, total_len);
    blake3_hasher_finalize(&hasher, hash, 32);
    free(input);
    
    // Check if hash meets difficulty (at least 1 leading zero bit)
    uint32_t difficulty = 1;
    int result = pow_verify_hash_difficulty(hash, 32, difficulty);
    return result; // Returns 1 if valid, 0 if not
}

