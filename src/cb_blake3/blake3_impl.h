#ifndef BLAKE3_IMPL_H
#define BLAKE3_IMPL_H

#include "blake3.h"
#include <stddef.h>
#include <stdint.h>

// BLAKE3 IV - first 8 words of fractional parts of square roots of first 8 primes
static const uint32_t IV[8] = {
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t MSG_SCHEDULE[7][16] = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
  {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
  {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
  {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
  {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
  {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

// Utility functions
static inline uint32_t rotr32(uint32_t w, uint32_t c) {
  return (w >> c) | (w << (32 - c));
}

static inline void load32_le(const uint8_t src[4], uint32_t *dest) {
  *dest = ((uint32_t)src[0]) |
          ((uint32_t)src[1] << 8) |
          ((uint32_t)src[2] << 16) |
          ((uint32_t)src[3] << 24);
}

static inline void store32_le(uint8_t dest[4], uint32_t src) {
  dest[0] = (uint8_t)src;
  dest[1] = (uint8_t)(src >> 8);
  dest[2] = (uint8_t)(src >> 16);
  dest[3] = (uint8_t)(src >> 24);
}

static inline void load_block(const uint8_t *block, uint32_t *out) {
  for (size_t i = 0; i < 16; i++) {
    load32_le(&block[i * 4], &out[i]);
  }
}

static inline void store_cv(uint8_t *out, const uint32_t *cv) {
  for (size_t i = 0; i < 8; i++) {
    store32_le(&out[i * 4], cv[i]);
  }
}

// G function - the mixing function used in BLAKE3
static inline void g(uint32_t *state, size_t a, size_t b, size_t c, size_t d,
                     uint32_t mx, uint32_t my) {
  state[a] = state[a] + state[b] + mx;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + my;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 7);
}

// Round function
static inline void round_fn(uint32_t state[16], const uint32_t *msg, size_t round) {
  const uint8_t *schedule = MSG_SCHEDULE[round];
  
  // Mix columns
  g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
  g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
  g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
  g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);
  
  // Mix diagonals
  g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
  g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
  g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
  g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

// Compression function
static inline void compress(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
                           uint8_t block_len, uint64_t counter, uint8_t flags,
                           uint8_t out[64]) {
  uint32_t block_words[16];
  load_block(block, block_words);
  
  uint32_t state[16] = {
    cv[0], cv[1], cv[2], cv[3],
    cv[4], cv[5], cv[6], cv[7],
    IV[0], IV[1], IV[2], IV[3],
    (uint32_t)counter, (uint32_t)(counter >> 32), (uint32_t)block_len, (uint32_t)flags,
  };
  
  // 7 rounds
  for (size_t round = 0; round < 7; round++) {
    round_fn(state, block_words, round);
  }
  
  // XOR the two halves
  for (size_t i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= cv[i];
  }
  
  // Store output
  for (size_t i = 0; i < 16; i++) {
    store32_le(&out[i * 4], state[i]);
  }
}

#endif /* BLAKE3_IMPL_H */