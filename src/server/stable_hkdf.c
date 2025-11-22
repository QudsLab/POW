#include "stable_hkdf.h"
#include "deps/hkdf/hkdf.h"
#include <string.h>

int stable_hkdf_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    uint8_t salt[32] = {0}; // Default salt
    const uint8_t info[] = "info";
    
    hkdf_sha256(salt, 32, input, input_len, info, 4, output, output_len);
    
    return 0;
}
