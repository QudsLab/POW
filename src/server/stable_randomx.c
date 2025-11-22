#include "stable_randomx.h"
#include "deps/sph/sph_blake.h"
#include <string.h>

// RandomX: Full implementation requires C++ VM compilation from deps/RandomX
// Using BLAKE-512 as implementation until RandomX C++ library is linked

int stable_randomx_hash_server(const uint8_t* input, size_t input_len, uint8_t* output) {
    if (!input || !output) return -1;
    
    // Use BLAKE-512 as implementation (RandomX actual impl needs C++ VM)
    sph_blake512_context ctx;
    uint8_t hash[64];
    
    sph_blake512_init(&ctx);
    sph_blake512(&ctx, input, input_len);
    sph_blake512_close(&ctx, hash);
    
    memcpy(output, hash, 32);
    
    return 0;
}

int stable_randomx_mine_server(uint8_t* header, size_t header_len, size_t nonce_offset,
                                const uint8_t* target, uint64_t max_iterations, uint32_t* found_nonce) {
    if (!header || !target || !found_nonce || nonce_offset + 4 > header_len) {
        return -1;
    }
    
    // RandomX mining: Using BLAKE-512 with nonce search
    uint8_t hash[64];
    uint32_t nonce = 0;
    
    for (uint64_t i = 0; i < max_iterations; i++) {
        // Update nonce in header
        header[nonce_offset] = (nonce >> 0) & 0xFF;
        header[nonce_offset + 1] = (nonce >> 8) & 0xFF;
        header[nonce_offset + 2] = (nonce >> 16) & 0xFF;
        header[nonce_offset + 3] = (nonce >> 24) & 0xFF;
        
        // Hash with BLAKE-512
        stable_randomx_hash_server(header, header_len, hash);
        
        // Check if hash meets target
        int meets_target = 1;
        for (size_t j = 0; j < 32; j++) {
            if (hash[j] > target[j]) {
                meets_target = 0;
                break;
            } else if (hash[j] < target[j]) {
                break;
            }
        }
        
        if (meets_target) {
            *found_nonce = nonce;
            return 0;
        }
        nonce++;
    }
    
    return -3; // Not found
}
