#include "stable_lyra2rev2.h"
#include "deps/Lyra/Lyra2.h"
#include "deps/sph/sph_blake.h"
#include "deps/sph/sph_keccak.h"
#include "deps/sph/sph_cubehash.h"
#include "deps/sph/sph_skein.h"
#include "deps/sph/sph_bmw.h"
#include <string.h>

int stable_lyra2rev2_hash_server(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || output_len < 32) return -1;
    
    uint8_t hash[32] = {0};  // Zero-initialize hash buffer
    
    // Lyra2REv2: BLAKE -> Keccak -> CubeHash -> Lyra2(8,8) -> Skein -> CubeHash -> BMW
    
    // 1. BLAKE-256
    sph_blake256_context ctx_blake = {0};
    sph_blake256_init(&ctx_blake);
    sph_blake256(&ctx_blake, input, input_len);
    sph_blake256_close(&ctx_blake, hash);
    
    // 2. Keccak-256
    sph_keccak256_context ctx_keccak = {0};
    sph_keccak256_init(&ctx_keccak);
    sph_keccak256(&ctx_keccak, hash, 32);
    sph_keccak256_close(&ctx_keccak, hash);
    
    // 3. CubeHash-256
    sph_cubehash256_context ctx_cube1 = {0};
    sph_cubehash256_init(&ctx_cube1);
    sph_cubehash256(&ctx_cube1, hash, 32);
    sph_cubehash256_close(&ctx_cube1, hash);
    
    // 4. Lyra2(8,8,256) - use fixed salt for deterministic output
    uint8_t salt[32] = {0};
    uint8_t lyra_input[32] = {0};
    uint8_t lyra_output[32] = {0};
    memset(salt, 0x80, 32);  // Fixed salt
    memcpy(lyra_input, hash, 32);  // Copy hash to separate input buffer
    LYRA2(lyra_output, 32, lyra_input, 32, salt, 32, 1, 8, 256);
    memcpy(hash, lyra_output, 32);
    
    // 5. Skein-256
    sph_skein256_context ctx_skein = {0};
    sph_skein256_init(&ctx_skein);
    sph_skein256(&ctx_skein, hash, 32);
    sph_skein256_close(&ctx_skein, hash);
    
    // 6. CubeHash-256
    sph_cubehash256_context ctx_cube2 = {0};
    sph_cubehash256_init(&ctx_cube2);
    sph_cubehash256(&ctx_cube2, hash, 32);
    sph_cubehash256_close(&ctx_cube2, hash);
    
    // 7. BMW-256
    sph_bmw256_context ctx_bmw = {0};
    sph_bmw256_init(&ctx_bmw);
    sph_bmw256(&ctx_bmw, hash, 32);
    sph_bmw256_close(&ctx_bmw, hash);
    
    memcpy(output, hash, 32);
    return 0;
}

