#include "stable_lyra2z.h"
#include "deps/Lyra/Lyra2.h"
#include "deps/sph/sph_blake.h"
#include "deps/sph/sph_cubehash.h"
#include "deps/sph/sph_bmw.h"
#include <string.h>

int stable_lyra2z_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    uint8_t hash[32];
    
    // Lyra2Z: BLAKE -> Lyra2(8,8) -> CubeHash -> BMW
    
    // 1. BLAKE-256
    sph_blake256_context ctx_blake;
    sph_blake256_init(&ctx_blake);
    sph_blake256(&ctx_blake, input, input_len);
    sph_blake256_close(&ctx_blake, hash);
    
    // 2. Lyra2(8,8,256) - use fixed salt for deterministic output
    uint8_t salt[32];
    memset(salt, 0x80, 32);  // Fixed salt
    LYRA2(hash, 32, hash, 32, salt, 32, 1, 8, 256);
    
    // 3. CubeHash-256
    sph_cubehash256_context ctx_cube;
    sph_cubehash256_init(&ctx_cube);
    sph_cubehash256(&ctx_cube, hash, 32);
    sph_cubehash256_close(&ctx_cube, hash);
    
    // 4. BMW-256
    sph_bmw256_context ctx_bmw;
    sph_bmw256_init(&ctx_bmw);
    sph_bmw256(&ctx_bmw, hash, 32);
    sph_bmw256_close(&ctx_bmw, hash);
    
    memcpy(output, hash, 32);
    return 0;
}

