#include "scrypt.h"
#include "../cb_sha2/sha2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

static inline uint32_t le32dec(const void *pp) {
  const uint8_t *p = (uint8_t const *)pp;
  return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
          ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void *pp, uint32_t x) {
  uint8_t *p = (uint8_t *)pp;
  p[0] = x & 0xff;
  p[1] = (x >> 8) & 0xff;
  p[2] = (x >> 16) & 0xff;
  p[3] = (x >> 24) & 0xff;
}

static inline void blkcpy(void *dest, const void *src, size_t len) {
  memcpy(dest, src, len);
}

static inline void blkxor(void *dest, const void *src, size_t len) {
  size_t i;
  uint8_t *D = dest;
  const uint8_t *S = src;
  for (i = 0; i < len; i++) {
    D[i] ^= S[i];
  }
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void salsa20_8(uint32_t B[16]) {
  uint32_t x[16];
  size_t i;

  blkcpy(x, B, 64);
  for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
    /* Operate on columns. */
    x[4] ^= R(x[0] + x[12], 7);
    x[8] ^= R(x[4] + x[0], 9);
    x[12] ^= R(x[8] + x[4], 13);
    x[0] ^= R(x[12] + x[8], 18);

    x[9] ^= R(x[5] + x[1], 7);
    x[13] ^= R(x[9] + x[5], 9);
    x[1] ^= R(x[13] + x[9], 13);
    x[5] ^= R(x[1] + x[13], 18);

    x[14] ^= R(x[10] + x[6], 7);
    x[2] ^= R(x[14] + x[10], 9);
    x[6] ^= R(x[2] + x[14], 13);
    x[10] ^= R(x[6] + x[2], 18);

    x[3] ^= R(x[15] + x[11], 7);
    x[7] ^= R(x[3] + x[15], 9);
    x[11] ^= R(x[7] + x[3], 13);
    x[15] ^= R(x[11] + x[7], 18);

    /* Operate on rows. */
    x[1] ^= R(x[0] + x[3], 7);
    x[2] ^= R(x[1] + x[0], 9);
    x[3] ^= R(x[2] + x[1], 13);
    x[0] ^= R(x[3] + x[2], 18);

    x[6] ^= R(x[5] + x[4], 7);
    x[7] ^= R(x[6] + x[5], 9);
    x[4] ^= R(x[7] + x[6], 13);
    x[5] ^= R(x[4] + x[7], 18);

    x[11] ^= R(x[10] + x[9], 7);
    x[8] ^= R(x[11] + x[10], 9);
    x[9] ^= R(x[8] + x[11], 13);
    x[10] ^= R(x[9] + x[8], 18);

    x[12] ^= R(x[15] + x[14], 7);
    x[13] ^= R(x[12] + x[15], 9);
    x[14] ^= R(x[13] + x[12], 13);
    x[15] ^= R(x[14] + x[13], 18);
#undef R
  }
  for (i = 0; i < 16; i++) {
    B[i] += x[i];
  }
}

/**
 * blockmix_salsa8(Bin, Bout, r):
 * Compute Bout = BlockMix_{salsa20/8}(Bin). The input Bin must be 128r
 * bytes in length; the output Bout must also be the same size.
 */
static void blockmix_salsa8(const uint32_t *Bin, uint32_t *Bout, size_t r) {
  uint32_t X[16];
  size_t i;

  /* 1: X <-- B_{2r - 1} */
  blkcpy(X, &Bin[(2 * r - 1) * 16], 64);

  /* 2: for i = 0 to 2r - 1 do */
  for (i = 0; i < 2 * r; i += 2) {
    /* 3: X <-- H(X \xor B_i) */
    blkxor(X, &Bin[i * 16], 64);
    salsa20_8(X);

    /* 4: Y_i <-- X */
    /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
    blkcpy(&Bout[i * 8], X, 64);

    /* 3: X <-- H(X \xor B_i) */
    blkxor(X, &Bin[i * 16 + 16], 64);
    salsa20_8(X);

    /* 4: Y_i <-- X */
    /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
    blkcpy(&Bout[i * 8 + r * 16], X, 64);
  }
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static inline uint64_t integerify(const uint32_t *B, size_t r) {
  const uint32_t *X = &B[(2 * r - 1) * 16];
  return (((uint64_t)(X[13]) << 32) + X[0]);
}

/**
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N). The input B must be 128r bytes in length;
 * the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r + 64 bytes in length.
 */
static void smix(uint8_t *B, size_t r, uint64_t N, uint32_t *V, uint32_t *XY) {
  uint32_t *X = XY;
  uint32_t *Y = &XY[32 * r];
  uint64_t i;
  uint64_t j;
  size_t k;

  /* 1: X <-- B */
  for (k = 0; k < 32 * r; k++) {
    X[k] = le32dec(&B[4 * k]);
  }

  /* 2: for i = 0 to N - 1 do */
  for (i = 0; i < N; i += 2) {
    /* 3: V_i <-- X */
    blkcpy(&V[i * (32 * r)], X, 128 * r);

    /* 4: X <-- H(X) */
    blockmix_salsa8(X, Y, r);

    /* 3: V_i <-- X */
    blkcpy(&V[(i + 1) * (32 * r)], Y, 128 * r);

    /* 4: X <-- H(X) */
    blockmix_salsa8(Y, X, r);
  }

  /* 6: for i = 0 to N - 1 do */
  for (i = 0; i < N; i += 2) {
    /* 7: j <-- Integerify(X) mod N */
    j = integerify(X, r) & (N - 1);

    /* 8: X <-- H(X \xor V_j) */
    blkxor(X, &V[j * (32 * r)], 128 * r);
    blockmix_salsa8(X, Y, r);

    /* 7: j <-- Integerify(X) mod N */
    j = integerify(Y, r) & (N - 1);

    /* 8: X <-- H(X \xor V_j) */
    blkxor(Y, &V[j * (32 * r)], 128 * r);
    blockmix_salsa8(Y, X, r);
  }

  /* 10: B' <-- X */
  for (k = 0; k < 32 * r; k++) {
    le32enc(&B[4 * k], X[k]);
  }
}

int scrypt_check_params(uint64_t N, uint32_t r, uint32_t p) {
  /* Check N is a power of 2 */
  if ((N == 0) || (N & (N - 1))) {
    return -1;
  }

  /* Check r and p are reasonable */
  if (r == 0 || p == 0) {
    return -1;
  }

  /* Check memory requirements don't overflow */
  if (r > SIZE_MAX / 128 / p) {
    return -1;
  }
  
  if (N > SIZE_MAX / 128 / r) {
    return -1;
  }

  return 0;
}

/* HMAC-SHA256 implementation */
#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

static void hmac_sha256(const uint8_t *key, size_t keylen,
                        const uint8_t *data, size_t datalen,
                        uint8_t *out) {
  uint8_t ipad[SHA256_BLOCK_SIZE];
  uint8_t opad[SHA256_BLOCK_SIZE];
  uint8_t tmp[SHA256_DIGEST_LENGTH];
  sha256_ctx ctx;
  int i;

  /* If key is longer than block size, hash it */
  if (keylen > SHA256_BLOCK_SIZE) {
    sha256(key, keylen, ipad);
    keylen = SHA256_DIGEST_LENGTH;
    memcpy(opad, ipad, keylen);
  } else {
    memcpy(ipad, key, keylen);
    memcpy(opad, key, keylen);
  }

  /* Pad key with zeros */
  memset(ipad + keylen, 0, SHA256_BLOCK_SIZE - keylen);
  memset(opad + keylen, 0, SHA256_BLOCK_SIZE - keylen);

  /* XOR with ipad and opad constants */
  for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }

  /* Inner hash: H(K XOR ipad, text) */
  sha256_init(&ctx);
  sha256_update(&ctx, ipad, SHA256_BLOCK_SIZE);
  sha256_update(&ctx, data, datalen);
  sha256_final(&ctx, tmp);

  /* Outer hash: H(K XOR opad, H(...)) */
  sha256_init(&ctx);
  sha256_update(&ctx, opad, SHA256_BLOCK_SIZE);
  sha256_update(&ctx, tmp, SHA256_DIGEST_LENGTH);
  sha256_final(&ctx, out);
}

/* PBKDF2-SHA256 implementation */
static void pbkdf2_sha256(const uint8_t *passwd, size_t passwdlen,
                          const uint8_t *salt, size_t saltlen,
                          uint64_t c, uint8_t *buf, size_t dkLen) {
  uint8_t *S = NULL;  /* salt||counter */
  uint8_t U[SHA256_DIGEST_LENGTH];
  uint8_t T[SHA256_DIGEST_LENGTH];
  uint8_t counter[4];
  uint64_t i, j;
  size_t clen;

  for (i = 0; i * SHA256_DIGEST_LENGTH < dkLen; i++) {
    /* Big-endian counter */
    counter[0] = (uint8_t)((i + 1) >> 24);
    counter[1] = (uint8_t)((i + 1) >> 16);
    counter[2] = (uint8_t)((i + 1) >> 8);
    counter[3] = (uint8_t)(i + 1);

    /* Allocate salt||counter */
    S = malloc(saltlen + 4);
    if (S == NULL) {
      return;  /* Error: out of memory */
    }
    memcpy(S, salt, saltlen);
    memcpy(S + saltlen, counter, 4);

    /* First iteration: U_1 = HMAC-SHA256(P, salt||counter) */
    hmac_sha256(passwd, passwdlen, S, saltlen + 4, U);
    memcpy(T, U, SHA256_DIGEST_LENGTH);

    /* Subsequent iterations: U_j = HMAC-SHA256(P, U_{j-1}) */
    for (j = 1; j < c; j++) {
      hmac_sha256(passwd, passwdlen, U, SHA256_DIGEST_LENGTH, U);
      for (size_t k = 0; k < SHA256_DIGEST_LENGTH; k++) {
        T[k] ^= U[k];
      }
    }

    free(S);

    /* Copy result */
    clen = dkLen - i * SHA256_DIGEST_LENGTH;
    if (clen > SHA256_DIGEST_LENGTH) {
      clen = SHA256_DIGEST_LENGTH;
    }
    memcpy(&buf[i * SHA256_DIGEST_LENGTH], T, clen);
  }
}

int scrypt(const uint8_t *passwd, size_t passwdlen,
           const uint8_t *salt, size_t saltlen,
           uint64_t N, uint32_t r, uint32_t p,
           uint8_t *buf, size_t buflen) {
  uint8_t *B = NULL;
  uint32_t *V = NULL;
  uint32_t *XY = NULL;
  uint32_t i;
  int rc = -1;

  /* Validate parameters */
  if (scrypt_check_params(N, r, p) != 0) {
    goto cleanup;
  }

  /* Allocate memory */
  if ((B = malloc(128 * r * p)) == NULL) {
    goto cleanup;
  }

  if ((XY = malloc(256 * r + 64)) == NULL) {
    goto cleanup;
  }

  if ((V = malloc(128 * r * N)) == NULL) {
    goto cleanup;
  }

  /* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
  pbkdf2_sha256(passwd, passwdlen, salt, saltlen, 1, B, p * 128 * r);

  /* 2: for i = 0 to p - 1 do */
  for (i = 0; i < p; i++) {
    /* 3: B_i <-- MF(B_i, N) */
    smix(&B[i * 128 * r], r, N, V, XY);
  }

  /* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
  pbkdf2_sha256(passwd, passwdlen, B, p * 128 * r, 1, buf, buflen);

  rc = 0;

cleanup:
  if (V) {
    memset(V, 0, 128 * r * N);
    free(V);
  }
  if (XY) {
    memset(XY, 0, 256 * r + 64);
    free(XY);
  }
  if (B) {
    memset(B, 0, 128 * r * p);
    free(B);
  }

  return rc;
}