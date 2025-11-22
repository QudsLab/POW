#ifndef KMAC_H
#define KMAC_H

#include <stdint.h>
#include <stddef.h>

void kmac256(const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len,
             const uint8_t *custom, size_t custom_len,
             uint8_t *output, size_t output_len);

#endif
