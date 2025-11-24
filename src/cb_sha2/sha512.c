#include "sha2.h"
#include <string.h>

/* SHA-512 constants */
static const uint64_t K512[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* SHA-512 initial hash values */
static const uint64_t H512[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* SHA-384 initial hash values */
static const uint64_t H384[8] = {
  0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
  0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR64(x, n) ((x) >> (n))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0_512(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SIGMA1_512(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0_512(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR64(x, 7))
#define sigma1_512(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR64(x, 6))

static inline uint64_t load_be64(const uint8_t *p) {
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
}

static inline void store_be64(uint8_t *p, uint64_t v) {
  p[0] = (uint8_t)(v >> 56);
  p[1] = (uint8_t)(v >> 48);
  p[2] = (uint8_t)(v >> 40);
  p[3] = (uint8_t)(v >> 32);
  p[4] = (uint8_t)(v >> 24);
  p[5] = (uint8_t)(v >> 16);
  p[6] = (uint8_t)(v >> 8);
  p[7] = (uint8_t)v;
}

static void sha512_transform(sha512_ctx *ctx, const uint8_t *data) {
  uint64_t W[80];
  uint64_t a, b, c, d, e, f, g, h;
  uint64_t T1, T2;
  int t;

  /* Prepare message schedule */
  for (t = 0; t < 16; t++) {
    W[t] = load_be64(data + t * 8);
  }
  
  for (t = 16; t < 80; t++) {
    W[t] = sigma1_512(W[t - 2]) + W[t - 7] + 
           sigma0_512(W[t - 15]) + W[t - 16];
  }

  /* Initialize working variables */
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  /* Main loop */
  for (t = 0; t < 80; t++) {
    T1 = h + SIGMA1_512(e) + CH(e, f, g) + K512[t] + W[t];
    T2 = SIGMA0_512(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  /* Update state */
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha512_init(sha512_ctx *ctx) {
  ctx->count[0] = 0;
  ctx->count[1] = 0;
  memcpy(ctx->state, H512, sizeof(H512));
}

void sha384_init(sha384_ctx *ctx) {
  ctx->count[0] = 0;
  ctx->count[1] = 0;
  memcpy(ctx->state, H384, sizeof(H384));
}

void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
  size_t buflen = ctx->count[0] % SHA512_BLOCK_SIZE;
  
  /* Update count (128-bit counter) */
  uint64_t old_count = ctx->count[0];
  ctx->count[0] += len;
  if (ctx->count[0] < old_count) {
    ctx->count[1]++; /* Carry */
  }

  /* Handle partial block */
  if (buflen + len >= SHA512_BLOCK_SIZE) {
    size_t partlen = SHA512_BLOCK_SIZE - buflen;
    memcpy(ctx->buffer + buflen, data, partlen);
    sha512_transform(ctx, ctx->buffer);
    data += partlen;
    len -= partlen;

    /* Process full blocks */
    while (len >= SHA512_BLOCK_SIZE) {
      sha512_transform(ctx, data);
      data += SHA512_BLOCK_SIZE;
      len -= SHA512_BLOCK_SIZE;
    }
    buflen = 0;
  }

  /* Copy remaining data to buffer */
  if (len > 0) {
    memcpy(ctx->buffer + buflen, data, len);
  }
}

void sha384_update(sha384_ctx *ctx, const uint8_t *data, size_t len) {
  sha512_update(ctx, data, len);
}

void sha512_final(sha512_ctx *ctx, uint8_t *hash) {
  size_t buflen = ctx->count[0] % SHA512_BLOCK_SIZE;
  
  /* Pad with 0x80 */
  ctx->buffer[buflen++] = 0x80;

  /* Pad with zeros and add length if needed */
  if (buflen > SHA512_BLOCK_SIZE - 16) {
    memset(ctx->buffer + buflen, 0, SHA512_BLOCK_SIZE - buflen);
    sha512_transform(ctx, ctx->buffer);
    buflen = 0;
  }

  /* Pad with zeros */
  memset(ctx->buffer + buflen, 0, SHA512_BLOCK_SIZE - 16 - buflen);
  
  /* Append length in bits (128-bit big-endian) */
  uint64_t bit_count_hi = (ctx->count[1] << 3) | (ctx->count[0] >> 61);
  uint64_t bit_count_lo = ctx->count[0] << 3;
  store_be64(ctx->buffer + SHA512_BLOCK_SIZE - 16, bit_count_hi);
  store_be64(ctx->buffer + SHA512_BLOCK_SIZE - 8, bit_count_lo);
  sha512_transform(ctx, ctx->buffer);

  /* Output hash */
  for (int i = 0; i < 8; i++) {
    store_be64(hash + i * 8, ctx->state[i]);
  }

  /* Clear sensitive data */
  memset(ctx, 0, sizeof(sha512_ctx));
}

void sha384_final(sha384_ctx *ctx, uint8_t *hash) {
  uint8_t temp[SHA512_DIGEST_SIZE];
  sha512_final(ctx, temp);
  memcpy(hash, temp, SHA384_DIGEST_SIZE);
  memset(temp, 0, sizeof(temp));
}

void sha512(const uint8_t *data, size_t len, uint8_t *hash) {
  sha512_ctx ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, data, len);
  sha512_final(&ctx, hash);
}

void sha384(const uint8_t *data, size_t len, uint8_t *hash) {
  sha384_ctx ctx;
  sha384_init(&ctx);
  sha384_update(&ctx, data, len);
  sha384_final(&ctx, hash);
}