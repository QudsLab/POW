#ifndef STABLE_skein_SERVER_H
#define STABLE_skein_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int stable_skein_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif

