
#include "client.h"
#include "pow_wrappers.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Request a challenge from the server
int client_request_challenge(const char *pow_type, pow_challenge_t *out_challenge) {
    // In real use, this would be a network call
    return server_generate_challenge(pow_type, out_challenge);
}

// Solve the challenge using the relevant PoW
int client_solve_challenge(const pow_challenge_t *challenge, pow_solution_t *out_solution) {
    if (!challenge || !out_solution || !challenge->challenge_data) return -1;
    
    // Convert pow_type string to enum
    pow_type_e type = pow_type_from_name(challenge->pow_type);
    if (type == POW_INVALID) return -2;
    
    // Allocate buffer for solution (256 bytes should be enough for most algorithms)
    size_t max_solution_len = 256;
    uint8_t *solution_buffer = (uint8_t*)malloc(max_solution_len);
    if (!solution_buffer) return -1;
    
    size_t solution_len = max_solution_len;
    
    // Call unified pow_solve function
    int result = pow_solve(
        type,
        challenge->challenge_data,
        challenge->challenge_len,
        NULL,  // No extra params for now
        0,
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
