#ifndef POW_WRAPPERS_H
#define POW_WRAPPERS_H

#include <stddef.h>
#include <stdint.h>

/**
 * pow_wrappers.h - Unified wrappers for all PoW algorithms
 * Provides single interface to solve and verify all PoW types
 * CPU-only, optimized for Python/cross-language integration
 */

typedef enum {
    POW_BLAKE3 = 0,
    POW_SHA2 = 1,
    POW_KECCAK = 2,
    POW_SCRYPT = 3,
    POW_ARGON2 = 4,
    POW_ZHASH = 5,
    POW_INVALID = -1
} pow_type_e;

/**
 * Solve PoW challenge using the specified algorithm
 * @param pow_type PoW algorithm type
 * @param challenge Challenge data
 * @param challenge_len Challenge length
 * @param params Algorithm-specific parameters (serialized)
 * @param params_len Parameter buffer length
 * @param out_solution Output solution buffer
 * @param out_solution_len Output solution length
 * @return 0 on success, -1 on error
 */
int pow_solve(pow_type_e pow_type,
             const uint8_t *challenge, size_t challenge_len,
             const uint8_t *params, size_t params_len,
             uint8_t *out_solution, size_t *out_solution_len);

/**
 * Verify PoW solution
 * @param pow_type PoW algorithm type
 * @param challenge Challenge data
 * @param challenge_len Challenge length
 * @param solution Solution to verify
 * @param solution_len Solution length
 * @param params Algorithm-specific parameters (serialized)
 * @param params_len Parameter buffer length
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int pow_verify(pow_type_e pow_type,
              const uint8_t *challenge, size_t challenge_len,
              const uint8_t *solution, size_t solution_len,
              const uint8_t *params, size_t params_len);

/**
 * Get the name of a PoW type
 * @param pow_type PoW algorithm type
 * @return String name (e.g., "blake3", "sha2"), NULL if invalid
 */
const char *pow_type_name(pow_type_e pow_type);

/**
 * Get PoW type from name
 * @param name PoW algorithm name (e.g., "blake3")
 * @return pow_type_e enum value, POW_INVALID if not found
 */
pow_type_e pow_type_from_name(const char *name);

#endif // POW_WRAPPERS_H
