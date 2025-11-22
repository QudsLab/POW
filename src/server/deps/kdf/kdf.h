#ifndef KDF_H
#define KDF_H

#include <stdint.h>
#include <stddef.h>

void concat_kdf_sha256(const uint8_t *shared_secret, size_t secret_len,
                       const uint8_t *other_info, size_t other_info_len,
                       uint8_t *output, size_t output_len);

void x963_kdf_sha256(const uint8_t *shared_secret, size_t secret_len,
                     const uint8_t *shared_info, size_t shared_info_len,
                     uint8_t *output, size_t output_len);

#endif
