#include "stable_x963kdf.h"
#include "deps/kdf/kdf.h"
#include <string.h>

int stable_x963kdf_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output) return -1;
    
    x963_kdf_sha256(input, input_len, NULL, 0, output, output_len);
    return 0;
}
