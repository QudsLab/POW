
#include "client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Forward declarations for PoW solve functions (add more as needed)
int pb_cuckaroo_solve(const pow_challenge_t *, pow_solution_t *);
int pb_cuckarood_solve(const pow_challenge_t *, pow_solution_t *);
int pb_cuckaroom_solve(const pow_challenge_t *, pow_solution_t *);
int pb_cuckarooz_solve(const pow_challenge_t *, pow_solution_t *);
int pb_cuckatoo_solve(const pow_challenge_t *, pow_solution_t *);
int pb_cuckoo_solve(const pow_challenge_t *, pow_solution_t *);
int cb_blake3_solve(const pow_challenge_t *, pow_solution_t *);
int cb_keccak_solve(const pow_challenge_t *, pow_solution_t *);
int cb_sha2_solve(const pow_challenge_t *, pow_solution_t *);
int mb_argon_solve(const pow_challenge_t *, pow_solution_t *);
int mb_scrypt_solve(const pow_challenge_t *, pow_solution_t *);
int hb_zhash_solve(const pow_challenge_t *, pow_solution_t *);

// Request a challenge from the server
int client_request_challenge(const char *pow_type, pow_challenge_t *out_challenge) {
    // In real use, this would be a network call
    return server_generate_challenge(pow_type, out_challenge);
}

// Modular solver wrapper
int client_solve_challenge(const pow_challenge_t *challenge, pow_solution_t *out_solution) {
    if (!challenge || !out_solution) return -1;
    if (strcmp(challenge->pow_type, "pb_cuckaroo") == 0)
        return pb_cuckaroo_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckarood") == 0)
        return pb_cuckarood_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckaroom") == 0)
        return pb_cuckaroom_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckarooz") == 0)
        return pb_cuckarooz_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckatoo") == 0)
        return pb_cuckatoo_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckoo") == 0)
        return pb_cuckoo_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "cb_blake3") == 0)
        return cb_blake3_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "cb_keccak") == 0)
        return cb_keccak_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "cb_sha2") == 0)
        return cb_sha2_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "mb_argon") == 0)
        return mb_argon_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "mb_scrypt") == 0)
        return mb_scrypt_solve(challenge, out_solution);
    if (strcmp(challenge->pow_type, "hb_zhash") == 0)
        return hb_zhash_solve(challenge, out_solution);
    // If not found, return failure
    return -2;
}

// Wrapper to handle dynamic parameters from the server
int client_handle_challenge(const char *pow_type) {
    pow_challenge_t challenge;
    pow_solution_t solution;
    if (client_request_challenge(pow_type, &challenge) != 0) {
        printf("Failed to get challenge\n");
        return -1;
    }
    if (client_solve_challenge(&challenge, &solution) != 0) {
        printf("Failed to solve challenge\n");
        free(challenge.challenge_data);
        return -2;
    }
    int verified = server_verify_solution(&challenge, &solution);
    printf("PoW type: %s, Verified: %d\n", pow_type, verified);
    free(challenge.challenge_data);
    free(solution.solution_data);
    return verified ? 0 : -3;
}
