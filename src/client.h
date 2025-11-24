
#ifndef CLIENT_H
#define CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include "server.h"

// Request a challenge from the server
int client_request_challenge(const char *pow_type, pow_challenge_t *out_challenge);

// Solve the challenge using the relevant PoW
int client_solve_challenge(const pow_challenge_t *challenge, pow_solution_t *out_solution);

// Wrapper to handle dynamic parameters from the server
int client_handle_challenge(const char *pow_type);

#endif // CLIENT_H
