#include "client.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * client_main.c - Client binary entry point
 * Requests challenges, solves them, submits solutions
 * CPU-only, cross-language compatible (C interface)
 */

int main(int argc, char *argv[]) {
    printf("PoW Client v1.0\n");
    printf("================\n\n");
    
    // Check if PoW type was specified
    if (argc < 2) {
        printf("Usage: client <pow_type>\n");
        printf("Example: client blake3\n\n");
        
        printf("Available PoW types:\n");
        const char *pow_types[MAX_POW_TYPES];
        size_t count = server_list_pow_types(pow_types, MAX_POW_TYPES);
        for (size_t i = 0; i < count; ++i) {
            printf("  - %s\n", pow_types[i]);
        }
        return 1;
    }
    
    const char *pow_type = argv[1];
    printf("Solving PoW challenge: %s\n\n", pow_type);
    
    // Request challenge
    pow_challenge_t challenge;
    printf("Requesting challenge from server...\n");
    
    if (client_request_challenge(pow_type, &challenge) != 0) {
        printf("Error: Failed to request challenge\n");
        return 1;
    }
    
    printf("Challenge received:\n");
    printf("  Type: %s\n", challenge.pow_type);
    printf("  Difficulty: %u\n", challenge.difficulty);
    printf("  Challenge length: %zu bytes\n\n", challenge.challenge_len);
    
    // Solve challenge
    printf("Solving challenge...\n");
    pow_solution_t solution;
    solution.solution_data = (uint8_t*)malloc(256);  // Allocate reasonable buffer
    solution.solution_len = 256;
    
    if (client_solve_challenge(&challenge, &solution) != 0) {
        printf("Error: Failed to solve challenge\n");
        free(challenge.challenge_data);
        free(solution.solution_data);
        return 1;
    }
    
    printf("Challenge solved!\n");
    printf("  Solution length: %zu bytes\n\n", solution.solution_len);
    
    // Verify solution
    printf("Verifying solution with server...\n");
    int verified = server_verify_solution(&challenge, &solution);
    
    if (verified == 1) {
        printf("SUCCESS: Solution verified!\n");
    } else if (verified == 0) {
        printf("FAILED: Solution verification failed\n");
    } else {
        printf("ERROR: Verification error\n");
    }
    
    // Cleanup
    free(challenge.challenge_data);
    free(solution.solution_data);
    
    return (verified == 1) ? 0 : 1;
}
