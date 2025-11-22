#ifndef POLY1305_H
#define POLY1305_H

#include <stdint.h>
#include <stddef.h>

void poly1305_auth(const uint8_t *message, size_t message_len,
                   const uint8_t key[32], uint8_t out[16]);

#endif
