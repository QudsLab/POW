// Poly1305 implementation - DJB's reference implementation adapted
#include "poly1305.h"
#include <string.h>

static void poly1305_block(uint32_t h[5], const uint8_t *m, uint32_t r[4]) {
    uint32_t m0 = (m[0] | (m[1] << 8) | (m[2] << 16) | (m[3] << 24)) & 0x0fffffff;
    uint32_t m1 = ((m[3] >> 4) | (m[4] << 4) | (m[5] << 12) | (m[6] << 20) | (m[7] << 28)) & 0x0fffffff;
    uint32_t m2 = ((m[7] >> 4) | (m[8] << 4) | (m[9] << 12) | (m[10] << 20) | (m[11] << 28)) & 0x0fffffff;
    uint32_t m3 = ((m[11] >> 4) | (m[12] << 4) | (m[13] << 12) | (m[14] << 20) | (m[15] << 28)) & 0x0fffffff;
    uint32_t m4 = (m[15] >> 4) | 0x10000000;
    
    uint64_t d0 = (uint64_t)h[0] + m0;
    uint64_t d1 = (uint64_t)h[1] + m1 + (d0 >> 26); d0 &= 0x3ffffff;
    uint64_t d2 = (uint64_t)h[2] + m2 + (d1 >> 26); d1 &= 0x3ffffff;
    uint64_t d3 = (uint64_t)h[3] + m3 + (d2 >> 26); d2 &= 0x3ffffff;
    uint64_t d4 = (uint64_t)h[4] + m4 + (d3 >> 26); d3 &= 0x3ffffff;
    uint32_t c = (d4 >> 26); d4 &= 0x3ffffff;
    d0 += c * 5;
    d1 += d0 >> 26; d0 &= 0x3ffffff;
    
    uint64_t t0 = d0 * r[0] + d1 * (5 * r[3]) + d2 * (5 * r[2]) + d3 * (5 * r[1]) + d4 * (5 * r[0]);
    uint64_t t1 = d0 * r[1] + d1 * r[0] + d2 * (5 * r[3]) + d3 * (5 * r[2]) + d4 * (5 * r[1]);
    uint64_t t2 = d0 * r[2] + d1 * r[1] + d2 * r[0] + d3 * (5 * r[3]) + d4 * (5 * r[2]);
    uint64_t t3 = d0 * r[3] + d1 * r[2] + d2 * r[1] + d3 * r[0] + d4 * (5 * r[3]);
    uint64_t t4 = d4 * r[0];
    
    h[0] = t0 & 0x3ffffff; t1 += t0 >> 26;
    h[1] = t1 & 0x3ffffff; t2 += t1 >> 26;
    h[2] = t2 & 0x3ffffff; t3 += t2 >> 26;
    h[3] = t3 & 0x3ffffff; t4 += t3 >> 26;
    h[4] = t4 & 0x3ffffff;
    c = t4 >> 26;
    h[0] += c * 5;
    h[1] += h[0] >> 26; h[0] &= 0x3ffffff;
}

void poly1305_auth(const uint8_t *message, size_t message_len,
                   const uint8_t key[32], uint8_t out[16]) {
    uint32_t r[4];
    r[0] = (key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24)) & 0x0fffffff;
    r[1] = ((key[3] >> 4) | (key[4] << 4) | (key[5] << 12) | (key[6] << 20) | (key[7] << 28)) & 0x0ffffffc;
    r[2] = ((key[7] >> 4) | (key[8] << 4) | (key[9] << 12) | (key[10] << 20) | (key[11] << 28)) & 0x0ffffffc;
    r[3] = ((key[11] >> 4) | (key[12] << 4) | (key[13] << 12) | (key[14] << 20) | (key[15] << 28)) & 0x0ffffffc;
    
    uint32_t h[5] = {0};
    
    while (message_len >= 16) {
        poly1305_block(h, message, r);
        message += 16;
        message_len -= 16;
    }
    
    if (message_len > 0) {
        uint8_t block[16] = {0};
        memcpy(block, message, message_len);
        block[message_len] = 1;
        poly1305_block(h, block, r);
    }
    
    uint32_t c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
    
    uint32_t g[5];
    g[0] = h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = h[1] + c; c = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2] + c; c = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = h[3] + c; c = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4] + c - (1 << 26);
    
    uint32_t mask = (g[4] >> 31) - 1;
    g[0] = (g[0] & ~mask) | (h[0] & mask);
    g[1] = (g[1] & ~mask) | (h[1] & mask);
    g[2] = (g[2] & ~mask) | (h[2] & mask);
    g[3] = (g[3] & ~mask) | (h[3] & mask);
    g[4] = (g[4] & ~mask) | (h[4] & mask);
    
    uint64_t f = ((uint64_t)g[0] | ((uint64_t)g[1] << 26) | ((uint64_t)g[2] << 52));
    uint32_t s0 = key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24);
    uint32_t s1 = key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24);
    uint32_t s2 = key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24);
    uint32_t s3 = key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24);
    
    f += s0; out[0] = f; out[1] = f >> 8; out[2] = f >> 16; out[3] = f >> 24;
    f = (f >> 32) + ((uint64_t)g[3] << 14) | ((uint64_t)g[4] << 40);
    f += s1; out[4] = f; out[5] = f >> 8; out[6] = f >> 16; out[7] = f >> 24;
    f = (f >> 32);
    f += s2; out[8] = f; out[9] = f >> 8; out[10] = f >> 16; out[11] = f >> 24;
    f = (f >> 32);
    f += s3; out[12] = f; out[13] = f >> 8; out[14] = f >> 16; out[15] = f >> 24;
}
