
#ifndef SERVER_H
#define SERVER_H

#include <stddef.h>
#include <stdint.h>

#define MAX_POW_TYPES 16

// Structure for PoW challenge parameters
typedef struct {
    char pow_type[32]; // Name of PoW algorithm
    uint8_t *challenge_data;
    size_t challenge_len;
    uint32_t difficulty;
} pow_challenge_t;

// Structure for PoW solution
typedef struct {
    char pow_type[32];
    uint8_t *solution_data;
    size_t solution_len;
} pow_solution_t;

// List available PoW types
size_t server_list_pow_types(const char **out_types, size_t max_types);

// Generate challenge parameters for a given PoW type
int server_generate_challenge(const char *pow_type, pow_challenge_t *out_challenge);

// Verify submitted PoW solution
int server_verify_solution(const pow_challenge_t *challenge, const pow_solution_t *solution);

#endif // SERVER_H
