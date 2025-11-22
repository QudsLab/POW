#ifndef BLAKE3_SIMPLE_H
#define BLAKE3_SIMPLE_H

#include <stdint.h>
#include <stddef.h>

void blake3_hash(const uint8_t *input, size_t input_len, uint8_t *output);

#endif
