#include "blake3.h"
#include "blake3_impl.h"
#include <string.h>
static inline void chunk_state_init(blake3_chunk_state *self, const uint32_t key[8],
                                    uint8_t flags)
{
    memcpy(self->cv, key, 32);
    self->chunk_counter = 0;
    memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    self->buf_len = 0;
    self->blocks_compressed = 0;
    self->flags = flags;
}
static inline void chunk_state_reset(blake3_chunk_state *self, const uint32_t key[8],
                                     uint64_t chunk_counter)
{
    memcpy(self->cv, key, 32);
    self->chunk_counter = chunk_counter;
    self->blocks_compressed = 0;
    memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    self->buf_len = 0;
}
static inline size_t chunk_state_len(const blake3_chunk_state *self)
{
    return (BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed) + ((size_t)self->buf_len);
}
static inline size_t chunk_state_fill_buf(blake3_chunk_state *self,
                                          const uint8_t *input,
                                          size_t input_len)
{
    size_t take = BLAKE3_BLOCK_LEN - ((size_t)self->buf_len);
    if (take > input_len)
    {
        take = input_len;
    }
    uint8_t *dest = self->buf + ((size_t)self->buf_len);
    memcpy(dest, input, take);
    self->buf_len += (uint8_t)take;
    return take;
}
static inline uint8_t chunk_state_start_flag(const blake3_chunk_state *self)
{
    if (self->blocks_compressed == 0)
    {
        return CHUNK_START;
    }
    else
    {
        return 0;
    }
}
static inline void chunk_state_update(blake3_chunk_state *self, const uint8_t *input,
                                      size_t input_len)
{
    if (self->buf_len > 0)
    {
        size_t take = chunk_state_fill_buf(self, input, input_len);
        input += take;
        input_len -= take;
        if (input_len > 0)
        {
            uint8_t block_flags = self->flags | chunk_state_start_flag(self);
            uint8_t out[64];
            compress(self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter,
                     block_flags, out);
            memcpy(self->cv, out, 32);
            self->blocks_compressed += 1;
            self->buf_len = 0;
            memset(self->buf, 0, BLAKE3_BLOCK_LEN);
        }
    }
    while (input_len > BLAKE3_BLOCK_LEN)
    {
        uint8_t block_flags = self->flags | chunk_state_start_flag(self);
        uint8_t out[64];
        compress(self->cv, input, BLAKE3_BLOCK_LEN, self->chunk_counter,
                 block_flags, out);
        memcpy(self->cv, out, 32);
        self->blocks_compressed += 1;
        input += BLAKE3_BLOCK_LEN;
        input_len -= BLAKE3_BLOCK_LEN;
    }
    size_t take = chunk_state_fill_buf(self, input, input_len);
    input += take;
    input_len -= take;
}
static inline void chunk_state_output(const blake3_chunk_state *self, uint8_t out[32])
{
    uint8_t block_flags = self->flags | chunk_state_start_flag(self) | CHUNK_END;
    uint8_t output[64];
    compress(self->cv, self->buf, self->buf_len, self->chunk_counter,
             block_flags, output);
    memcpy(out, output, 32);
}
static inline void parent_output(const uint8_t block[BLAKE3_BLOCK_LEN],
                                 const uint32_t key[8], uint8_t flags,
                                 uint8_t out[32])
{
    uint8_t output[64];
    compress(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT, output);
    memcpy(out, output, 32);
}
static inline void parent_cv(const uint8_t left_child_cv[32],
                             const uint8_t right_child_cv[32],
                             const uint32_t key[8], uint8_t flags,
                             uint8_t out[32])
{
    uint8_t block[BLAKE3_BLOCK_LEN];
    memcpy(block, left_child_cv, 32);
    memcpy(block + 32, right_child_cv, 32);
    parent_output(block, key, flags, out);
}
static inline void hasher_push_cv(blake3_hasher *self, uint8_t new_cv[32],
                                  uint64_t chunk_counter)
{
    while (chunk_counter & 1)
    {
        uint8_t parent_node_cv[32];
        parent_cv(self->cv_stack + (self->cv_stack_len - 1) * 32, new_cv,
                  self->key, self->chunk.flags, parent_node_cv);
        memcpy(new_cv, parent_node_cv, 32);
        self->cv_stack_len -= 1;
        chunk_counter >>= 1;
    }
    memcpy(self->cv_stack + self->cv_stack_len * 32, new_cv, 32);
    self->cv_stack_len += 1;
}
void blake3_hasher_init(blake3_hasher *self)
{
    memcpy(self->key, IV, 32);
    chunk_state_init(&self->chunk, IV, 0);
    self->cv_stack_len = 0;
}
void blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t key[BLAKE3_KEY_LEN])
{
    uint32_t key_words[8];
    for (size_t i = 0; i < 8; i++)
    {
        load32_le(&key[i * 4], &key_words[i]);
    }
    memcpy(self->key, key_words, 32);
    chunk_state_init(&self->chunk, key_words, KEYED_HASH);
    self->cv_stack_len = 0;
}
void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context,
                                       size_t context_len)
{
    blake3_hasher context_hasher;
    blake3_hasher_init(&context_hasher);
    context_hasher.chunk.flags = DERIVE_KEY_CONTEXT;
    blake3_hasher_update(&context_hasher, context, context_len);
    uint8_t context_key[BLAKE3_KEY_LEN];
    blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
    uint32_t context_key_words[8];
    for (size_t i = 0; i < 8; i++)
    {
        load32_le(&context_key[i * 4], &context_key_words[i]);
    }
    memcpy(self->key, context_key_words, 32);
    chunk_state_init(&self->chunk, context_key_words, DERIVE_KEY_MATERIAL);
    self->cv_stack_len = 0;
}
void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context)
{
    blake3_hasher_init_derive_key_raw(self, context, strlen(context));
}
void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len)
{
    const uint8_t *input_bytes = (const uint8_t *)input;
    while (input_len > 0)
    {
        if (chunk_state_len(&self->chunk) == BLAKE3_CHUNK_LEN)
        {
            uint8_t chunk_cv[32];
            chunk_state_output(&self->chunk, chunk_cv);
            uint64_t total_chunks = self->chunk.chunk_counter + 1;
            hasher_push_cv(self, chunk_cv, total_chunks);
            chunk_state_reset(&self->chunk, self->key, total_chunks);
        }
        size_t want = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
        size_t take = want;
        if (take > input_len)
        {
            take = input_len;
        }
        chunk_state_update(&self->chunk, input_bytes, take);
        input_bytes += take;
        input_len -= take;
    }
}
void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len)
{
    blake3_hasher_finalize_seek(self, 0, out, out_len);
}
void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek,
                                 uint8_t *out, size_t out_len)
{
    if (out_len == 0)
    {
        return;
    }
    uint8_t cv_stack_copy[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN];
    memcpy(cv_stack_copy, self->cv_stack, self->cv_stack_len * 32);
    uint8_t output_cv[32];
    chunk_state_output(&self->chunk, output_cv);
    uint8_t cv_stack_len = self->cv_stack_len;
    while (cv_stack_len > 0)
    {
        cv_stack_len -= 1;
        uint8_t parent_output[32];
        parent_cv(cv_stack_copy + cv_stack_len * 32, output_cv, self->key,
                  self->chunk.flags, parent_output);
        memcpy(output_cv, parent_output, 32);
    }
    uint32_t cv_words[8];
    for (size_t i = 0; i < 8; i++)
    {
        load32_le(&output_cv[i * 4], &cv_words[i]);
    }
    uint64_t output_block_counter = seek / 64;
    size_t offset_in_block = seek % 64;
    uint8_t wide_buf[64];
    while (out_len > 0)
    {
        compress(cv_words, (uint8_t[64]){0}, BLAKE3_BLOCK_LEN, output_block_counter,
                 self->chunk.flags | ROOT, wide_buf);
        size_t available = 64 - offset_in_block;
        size_t memcpy_len = (out_len < available) ? out_len : available;
        memcpy(out, wide_buf + offset_in_block, memcpy_len);
        out += memcpy_len;
        out_len -= memcpy_len;
        output_block_counter += 1;
        offset_in_block = 0;
    }
}
void blake3_hasher_reset(blake3_hasher *self)
{
    chunk_state_reset(&self->chunk, self->key, 0);
    self->cv_stack_len = 0;
}