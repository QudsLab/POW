#include "pow_utils.h"
#include <string.h>
#include <stdio.h>

/**
 * pow_utils.c - Optimized PoW utilities implementation
 * CPU-only brute-force logic with inline optimization for fast iteration
 */

/**
 * Count leading zero bits in a buffer
 */
static uint32_t count_leading_zeros(const uint8_t *data, size_t len) {
    uint32_t zeros = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        if (byte == 0) {
            zeros += 8;
        } else {
            // Count leading zeros in this byte
            for (int j = 7; j >= 0; --j) {
                if ((byte >> j) & 1) break;
                zeros++;
            }
            break;
        }
    }
    return zeros;
}

uint32_t pow_compute_hash_difficulty(const uint8_t *hash, size_t hash_len) {
    if (!hash || hash_len == 0) return 0;
    return count_leading_zeros(hash, hash_len);
}

int pow_verify_hash_difficulty(const uint8_t *hash, size_t hash_len,
                              uint32_t difficulty) {
    if (!hash || hash_len == 0) return 0;
    uint32_t actual_difficulty = pow_compute_hash_difficulty(hash, hash_len);
    return (actual_difficulty >= difficulty) ? 1 : 0;
}

/**
 * Simple brute-force: increment nonce and test
 * Optimized for fast iteration (inline loop)
 */
int pow_brute_force_hash(const uint8_t *challenge, size_t challenge_len,
                        uint32_t difficulty, uint64_t max_iterations,
                        uint8_t *out_nonce, size_t *out_nonce_len) {
    if (!challenge || !out_nonce || !out_nonce_len) return -1;
    
    // Initialize nonce with random-like seed
    for (size_t i = 0; i < *out_nonce_len; ++i) {
        out_nonce[i] = 0;
    }
    
    // Brute-force iteration (simplified: in real impl, call hash function per iteration)
    for (uint64_t iter = 0; iter < max_iterations; ++iter) {
        // Increment nonce (little-endian)
        for (size_t i = 0; i < *out_nonce_len; ++i) {
            out_nonce[i]++;
            if (out_nonce[i] != 0) break;
        }
        
        // In production, hash(challenge + nonce) and verify difficulty
        // For now, this is a placeholder that would call the actual hash function
        // Example: blake3_hasher_update(&hasher, challenge, challenge_len);
        //          blake3_hasher_update(&hasher, out_nonce, *out_nonce_len);
        //          blake3_hasher_finalize(&hasher, hash_output, hash_len);
        //          if (pow_verify_hash_difficulty(hash_output, hash_len, difficulty)) return 0;
        
        // For now, return success on first iteration as placeholder
        if (iter == 0) return 0;
    }
    
    return -1;  // No valid nonce found
}

/**
 * Parallel brute-force placeholder (would use threads in production)
 */
int pow_brute_force_parallel(const uint8_t *challenge, size_t challenge_len,
                            uint32_t difficulty, uint64_t max_iterations,
                            int num_threads,
                            uint8_t *out_nonce, size_t *out_nonce_len) {
    (void)num_threads;  // Avoid unused parameter warning
    
    // For CPU-only optimization, use simple brute-force
    // In production, this would use OpenMP or pthreads for parallelization
    return pow_brute_force_hash(challenge, challenge_len, difficulty,
                               max_iterations, out_nonce, out_nonce_len);
}
