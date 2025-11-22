#ifndef GMAC_H
#define GMAC_H

#include <stdint.h>
#include <stddef.h>

void gmac_auth(const uint8_t *key, size_t key_len,
               const uint8_t *iv, size_t iv_len,
               const uint8_t *data, size_t data_len,
               uint8_t *tag, size_t tag_len);

#endif
