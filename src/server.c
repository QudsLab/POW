
#include "server.h"
#include "pow_wrappers.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *pow_types[MAX_POW_TYPES] = {
    "blake3",
    "sha2",
    "keccak",
    "scrypt",
    "argon2",
    "zhash"
};
static const size_t pow_types_count = 6;

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
    strncpy(out_challenge->pow_type, pow_type, sizeof(out_challenge->pow_type) - 1);
    out_challenge->pow_type[sizeof(out_challenge->pow_type) - 1] = '\0';
    out_challenge->difficulty = 1; // Example difficulty, can be dynamic
    out_challenge->challenge_len = 32;
    out_challenge->challenge_data = (uint8_t*)malloc(out_challenge->challenge_len);
    if (!out_challenge->challenge_data) return -2;
    for (size_t i = 0; i < out_challenge->challenge_len; ++i) {
        out_challenge->challenge_data[i] = (uint8_t)(rand() % 256);
    }
    return 0;
}

// Modular verification wrapper
int server_verify_solution(const pow_challenge_t *challenge, const pow_solution_t *solution) {
    if (!challenge || !solution) return -1;
    if (strncmp(challenge->pow_type, solution->pow_type, sizeof(challenge->pow_type)) != 0) return 0;
    
    // Convert pow_type string to enum
    pow_type_e type = pow_type_from_name(challenge->pow_type);
    if (type == POW_INVALID) return 0;
    
    // Call unified pow_verify function
    int result = pow_verify(
        type,
        challenge->challenge_data,
        challenge->challenge_len,
        solution->solution_data,
        solution->solution_len,
        NULL,  // No extra params for now
        0
    );
    
    return result;
}
