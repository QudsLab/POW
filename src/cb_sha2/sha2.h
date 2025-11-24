#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-224 and SHA-256 */
#define SHA224_BLOCK_SIZE 64
#define SHA224_DIGEST_SIZE 28
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx;

typedef sha256_ctx sha224_ctx;

void sha224_init(sha224_ctx *ctx);
void sha224_update(sha224_ctx *ctx, const uint8_t *data, size_t len);
void sha224_final(sha224_ctx *ctx, uint8_t *hash);
void sha224(const uint8_t *data, size_t len, uint8_t *hash);

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t *hash);
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

/* SHA-384 and SHA-512 */
#define SHA384_BLOCK_SIZE 128
#define SHA384_DIGEST_SIZE 48
#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct {
  uint64_t state[8];
  uint64_t count[2];
  uint8_t buffer[SHA512_BLOCK_SIZE];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;

void sha384_init(sha384_ctx *ctx);
void sha384_update(sha384_ctx *ctx, const uint8_t *data, size_t len);
void sha384_final(sha384_ctx *ctx, uint8_t *hash);
void sha384(const uint8_t *data, size_t len, uint8_t *hash);

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx *ctx, uint8_t *hash);
void sha512(const uint8_t *data, size_t len, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif /* SHA2_H */