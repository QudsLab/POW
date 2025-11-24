#ifndef POW_UTILS_H
#define POW_UTILS_H

#include <stddef.h>
#include <stdint.h>

/**
 * pow_utils.h - Optimized utilities for PoW generation and verification
 * CPU-only, high-performance brute-force logic for all PoW types.
 * This module handles intensive computation needed by PoW solvers.
 */

typedef struct {
    uint64_t iterations;
    uint32_t difficulty;
    uint8_t *nonce;
    size_t nonce_len;
} pow_brute_params_t;

/**
 * Brute-force nonce search for hash-based PoWs (Blake3, SHA2, Keccak)
 * @param challenge Challenge data
 * @param challenge_len Challenge length
 * @param difficulty Difficulty level (number of leading zero bits)
 * @param max_iterations Maximum iterations to attempt
 * @param out_nonce Output nonce (allocate before calling)
 * @param out_nonce_len Output nonce length
 * @return 0 on success (valid PoW found), -1 on failure
 */
int pow_brute_force_hash(const uint8_t *challenge, size_t challenge_len,
                        uint32_t difficulty, uint64_t max_iterations,
                        uint8_t *out_nonce, size_t *out_nonce_len);

/**
 * Verify hash-based PoW (check difficulty constraint)
 * @param hash Computed hash
 * @param hash_len Hash length
 * @param difficulty Number of leading zero bits required
 * @return 1 if valid (meets difficulty), 0 otherwise
 */
int pow_verify_hash_difficulty(const uint8_t *hash, size_t hash_len,
                              uint32_t difficulty);

/**
 * Compute hash difficulty (count leading zero bits in hash)
 * @param hash Computed hash
 * @param hash_len Hash length
 * @return Number of leading zero bits
 */
uint32_t pow_compute_hash_difficulty(const uint8_t *hash, size_t hash_len);

/**
 * Parallel brute-force nonce search (multi-threaded, CPU-optimized)
 * @param challenge Challenge data
 * @param challenge_len Challenge length
 * @param difficulty Difficulty level
 * @param max_iterations Maximum iterations per thread
 * @param num_threads Number of worker threads
 * @param out_nonce Output nonce
 * @param out_nonce_len Output nonce length
 * @return 0 on success, -1 on failure
 */
int pow_brute_force_parallel(const uint8_t *challenge, size_t challenge_len,
                            uint32_t difficulty, uint64_t max_iterations,
                            int num_threads,
                            uint8_t *out_nonce, size_t *out_nonce_len);

#endif // POW_UTILS_H
