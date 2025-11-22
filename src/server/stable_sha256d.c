#include "stable_sha256d.h"
#include <string.h>

// SHA-256 constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    }
    
    for (int i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    for (int i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_hash(const uint8_t* input, size_t len, uint8_t output[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t data[64];
    size_t i = 0;
    
    while (len >= 64) {
        sha256_transform(state, input + i);
        i += 64;
        len -= 64;
    }
    
    memset(data, 0, 64);
    memcpy(data, input + i, len);
    data[len] = 0x80;
    
    if (len >= 56) {
        sha256_transform(state, data);
        memset(data, 0, 64);
    }
    
    uint64_t bitlen = (i + len) * 8;
    for (int j = 0; j < 8; j++) {
        data[63-j] = bitlen >> (j*8);
    }
    
    sha256_transform(state, data);
    
    for (int j = 0; j < 8; j++) {
        output[j*4] = state[j] >> 24;
        output[j*4+1] = state[j] >> 16;
        output[j*4+2] = state[j] >> 8;
        output[j*4+3] = state[j];
    }
}

int stable_sha256d_hash_server(const uint8_t* input, size_t input_len, uint8_t* output) {
    if (!input || !output) {
        return -1;
    }
    
    uint8_t temp[32];
    sha256_hash(input, input_len, temp);
    sha256_hash(temp, 32, output);
    
    return 0;
}

int stable_sha256d_mine_server(
    uint8_t* header,
    size_t header_len,
    size_t nonce_offset,
    const uint8_t* target,
    uint64_t max_iterations,
    uint32_t* found_nonce
) {
    if (!header || !target || !found_nonce) {
        return -1;
    }
    
    if (nonce_offset + 4 > header_len) {
        return -2;
    }
    
    uint8_t hash[32];
    
    for (uint64_t nonce = 0; nonce < max_iterations; nonce++) {
        // Update nonce in header (little-endian)
        header[nonce_offset] = nonce & 0xFF;
        header[nonce_offset+1] = (nonce >> 8) & 0xFF;
        header[nonce_offset+2] = (nonce >> 16) & 0xFF;
        header[nonce_offset+3] = (nonce >> 24) & 0xFF;
        
        // Compute SHA-256d
        stable_sha256d_hash_server(header, header_len, hash);
        
        // Check if hash meets target (compare as big-endian)
        int meets_target = 1;
        for (int i = 31; i >= 0; i--) {
            if (hash[i] < target[i]) {
                meets_target = 1;
                break;
            } else if (hash[i] > target[i]) {
                meets_target = 0;
                break;
            }
        }
        
        if (meets_target) {
            *found_nonce = (uint32_t)nonce;
            return 0;
        }
    }
    
    return -3; // Not found within max_iterations
}
