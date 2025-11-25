#include "server.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * server_main.c - Server binary entry point
 * Accepts PoW challenges, generates parameters, verifies solutions
 * CPU-only, cross-language compatible (C interface)
 */

int main(int argc, char *argv[]) {
    printf("PoW Server v1.0\n");
    printf("================\n\n");
    
    // List available PoW types
    const char *pow_types[MAX_POW_TYPES];
    size_t count = server_list_pow_types(pow_types, MAX_POW_TYPES);
    
    printf("Available PoW Types (%zu):\n", count);
    for (size_t i = 0; i < count; ++i) {
        printf("  [%zu] %s\n", i, pow_types[i]);
    }
    printf("\n");
    
    // Example: Generate challenge for first PoW type
    if (count > 0) {
        pow_challenge_t challenge;
        printf("Generating challenge for: %s\n", pow_types[0]);
        
        if (server_generate_challenge(pow_types[0], &challenge) == 0) {
            printf("Challenge generated successfully\n");
            printf("  Type: %s\n", challenge.pow_type);
            printf("  Difficulty: %u\n", challenge.difficulty);
            printf("  Challenge length: %zu bytes\n", challenge.challenge_len);
            
            free(challenge.challenge_data);
        } else {
            printf("Failed to generate challenge\n");
            return 1;
        }
    }
    printf("\nServer ready for cross-language integration.\n");
    printf("Compile with your language's FFI/C bindings to use.\n");
    return 0;
}
