// Simple BLAKE3 implementation (placeholder using BLAKE2)
#include "blake3_simple.h"
#include "blake2.h"
#include <string.h>

void blake3_hash(const uint8_t *input, size_t input_len, uint8_t *output) {
    // Use BLAKE2b as placeholder for BLAKE3
    blake2b_state S;
    blake2b_init(&S, 32);
    blake2b_update(&S, input, input_len);
    blake2b_final(&S, output, 32);
}
