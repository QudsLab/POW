
#include "client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Forward declarations for PoW solve functions from pow_wrappers.c
// They take raw byte arrays, not pow_challenge_t
int cb_blake3_solve(const uint8_t *challenge, size_t challenge_len,
                   uint8_t *out_solution, size_t *out_solution_len);
int cb_keccak_solve(const uint8_t *challenge, size_t challenge_len,
                   uint8_t *out_solution, size_t *out_solution_len);
int cb_sha2_solve(const uint8_t *challenge, size_t challenge_len,
                 uint8_t *out_solution, size_t *out_solution_len);
int mb_argon_solve(const uint8_t *challenge, size_t challenge_len,
                  uint8_t *out_solution, size_t *out_solution_len);
int mb_scrypt_solve(const uint8_t *challenge, size_t challenge_len,
                   uint8_t *out_solution, size_t *out_solution_len);
int hb_zhash_solve(const uint8_t *challenge, size_t challenge_len,
                  uint8_t *out_solution, size_t *out_solution_len);
int pb_cuckaroo_solve(const uint8_t *challenge, size_t challenge_len,
                     uint8_t *out_solution, size_t *out_solution_len);
int pb_cuckarood_solve(const uint8_t *challenge, size_t challenge_len,
                      uint8_t *out_solution, size_t *out_solution_len);
int pb_cuckaroom_solve(const uint8_t *challenge, size_t challenge_len,
                      uint8_t *out_solution, size_t *out_solution_len);
int pb_cuckarooz_solve(const uint8_t *challenge, size_t challenge_len,
                      uint8_t *out_solution, size_t *out_solution_len);
int pb_cuckatoo_solve(const uint8_t *challenge, size_t challenge_len,
                     uint8_t *out_solution, size_t *out_solution_len);
int pb_cuckoo_solve(const uint8_t *challenge, size_t challenge_len,
                   uint8_t *out_solution, size_t *out_solution_len);

// Wrapper function to convert pow_challenge_t to raw bytes and call the real solve
static int call_solve_function(
    int (*solve_fn)(const uint8_t*, size_t, uint8_t*, size_t*),
    const pow_challenge_t *challenge,
    pow_solution_t *out_solution)
{
    if (!challenge || !out_solution || !challenge->challenge_data) return -1;
    
    // Allocate buffer for solution
    size_t max_solution_len = 256;
    uint8_t *solution_buffer = malloc(max_solution_len);
    if (!solution_buffer) return -1;
    
    size_t solution_len = max_solution_len;
    
    // Call the real solve function with raw bytes
    int result = solve_fn(
        challenge->challenge_data,
        challenge->challenge_len,
        solution_buffer,
        &solution_len
    );
    
    if (result == 0 && solution_len > 0) {
        // Success - copy solution to output
        out_solution->solution_data = solution_buffer;
        out_solution->solution_len = solution_len;
        strncpy(out_solution->pow_type, challenge->pow_type, sizeof(out_solution->pow_type) - 1);
        out_solution->pow_type[sizeof(out_solution->pow_type) - 1] = '\0';
    } else {
        // Failure - free buffer
        free(solution_buffer);
    }
    
    return result;
}

// Request a challenge from the server
int client_request_challenge(const char *pow_type, pow_challenge_t *out_challenge) {
    // In real use, this would be a network call
    return server_generate_challenge(pow_type, out_challenge);
}

// Modular solver wrapper
int client_solve_challenge(const pow_challenge_t *challenge, pow_solution_t *out_solution) {
    if (!challenge || !out_solution) return -1;
    
    // Call appropriate solve function based on algorithm type
    if (strcmp(challenge->pow_type, "cb_blake3") == 0)
        return call_solve_function(cb_blake3_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "cb_keccak") == 0)
        return call_solve_function(cb_keccak_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "cb_sha2") == 0)
        return call_solve_function(cb_sha2_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "mb_argon") == 0)
        return call_solve_function(mb_argon_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "mb_scrypt") == 0)
        return call_solve_function(mb_scrypt_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "hb_zhash") == 0)
        return call_solve_function(hb_zhash_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckaroo") == 0)
        return call_solve_function(pb_cuckaroo_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckarood") == 0)
        return call_solve_function(pb_cuckarood_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckaroom") == 0)
        return call_solve_function(pb_cuckaroom_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckarooz") == 0)
        return call_solve_function(pb_cuckarooz_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckatoo") == 0)
        return call_solve_function(pb_cuckatoo_solve, challenge, out_solution);
    if (strcmp(challenge->pow_type, "pb_cuckoo") == 0)
        return call_solve_function(pb_cuckoo_solve, challenge, out_solution);
    
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
