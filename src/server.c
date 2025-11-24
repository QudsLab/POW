
#include "server.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Forward declarations for PoW verify functions (add more as needed)
int pb_cuckaroo_verify(const pow_challenge_t *, const pow_solution_t *);
int pb_cuckarood_verify(const pow_challenge_t *, const pow_solution_t *);
int pb_cuckaroom_verify(const pow_challenge_t *, const pow_solution_t *);
int pb_cuckarooz_verify(const pow_challenge_t *, const pow_solution_t *);
int pb_cuckatoo_verify(const pow_challenge_t *, const pow_solution_t *);
int pb_cuckoo_verify(const pow_challenge_t *, const pow_solution_t *);
int cb_blake3_verify(const pow_challenge_t *, const pow_solution_t *);
int cb_keccak_verify(const pow_challenge_t *, const pow_solution_t *);
int cb_sha2_verify(const pow_challenge_t *, const pow_solution_t *);
int mb_argon_verify(const pow_challenge_t *, const pow_solution_t *);
int mb_scrypt_verify(const pow_challenge_t *, const pow_solution_t *);
int hb_zhash_verify(const pow_challenge_t *, const pow_solution_t *);

static const char *pow_types[MAX_POW_TYPES] = {
    "pb_cuckaroo",
    "pb_cuckarood",
    "pb_cuckaroom",
    "pb_cuckarooz",
    "pb_cuckatoo",
    "pb_cuckoo",
    "cb_blake3",
    "cb_keccak",
    "cb_sha2",
    "mb_argon",
    "mb_scrypt",
    "hb_zhash"
};
static const size_t pow_types_count = 12;

size_t server_list_pow_types(const char **out_types, size_t max_types) {
    size_t count = (pow_types_count < max_types) ? pow_types_count : max_types;
    for (size_t i = 0; i < count; ++i) {
        out_types[i] = pow_types[i];
    }
    return count;
}

// Modular challenge generator
int server_generate_challenge(const char *pow_type, pow_challenge_t *out_challenge) {
    if (!pow_type || !out_challenge) return -1;
    strncpy(out_challenge->pow_type, pow_type, sizeof(out_challenge->pow_type));
    out_challenge->difficulty = 1; // Example difficulty, can be dynamic
    out_challenge->challenge_len = 32;
    out_challenge->challenge_data = (uint8_t*)malloc(out_challenge->challenge_len);
    if (!out_challenge->challenge_data) return -2;
    for (size_t i = 0; i < out_challenge->challenge_len; ++i) {
        out_challenge->challenge_data[i] = (uint8_t)(rand() % 256);
    }
    // For some PoWs, you may want to call their specific challenge generator here
    return 0;
}

// Modular verification wrapper
int server_verify_solution(const pow_challenge_t *challenge, const pow_solution_t *solution) {
    if (!challenge || !solution) return -1;
    if (strncmp(challenge->pow_type, solution->pow_type, sizeof(challenge->pow_type)) != 0) return 0;
    // Dispatch to correct PoW verify function
    if (strcmp(challenge->pow_type, "pb_cuckaroo") == 0)
        return pb_cuckaroo_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "pb_cuckarood") == 0)
        return pb_cuckarood_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "pb_cuckaroom") == 0)
        return pb_cuckaroom_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "pb_cuckarooz") == 0)
        return pb_cuckarooz_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "pb_cuckatoo") == 0)
        return pb_cuckatoo_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "pb_cuckoo") == 0)
        return pb_cuckoo_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "cb_blake3") == 0)
        return cb_blake3_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "cb_keccak") == 0)
        return cb_keccak_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "cb_sha2") == 0)
        return cb_sha2_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "mb_argon") == 0)
        return mb_argon_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "mb_scrypt") == 0)
        return mb_scrypt_verify(challenge, solution);
    if (strcmp(challenge->pow_type, "hb_zhash") == 0)
        return hb_zhash_verify(challenge, solution);
    // If not found, return failure
    return 0;
}

// Add more integration as needed for new PoW types
