// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#include <compat/endian.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

// Simplified for C++11 - removed concepts
inline uint16_t ReadLE16(const unsigned char* ptr)
{
    uint16_t x;
    memcpy(&x, ptr, 2);
    return le16toh_internal(x);
}

inline uint32_t ReadLE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy(&x, ptr, 4);
    return le32toh_internal(x);
}

inline uint64_t ReadLE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy(&x, ptr, 8);
    return le64toh_internal(x);
}

inline void WriteLE16(unsigned char* ptr, uint16_t x)
{
    uint16_t v = htole16_internal(x);
    memcpy(ptr, &v, 2);
}

inline void WriteLE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htole32_internal(x);
    memcpy(ptr, &v, 4);
}

inline void WriteLE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htole64_internal(x);
    memcpy(ptr, &v, 8);
}

inline uint16_t ReadBE16(const unsigned char* ptr)
{
    uint16_t x;
    memcpy(&x, ptr, 2);
    return be16toh_internal(x);
}

inline uint32_t ReadBE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy(&x, ptr, 4);
    return be32toh_internal(x);
}

inline uint64_t ReadBE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy(&x, ptr, 8);
    return be64toh_internal(x);
}

inline void WriteBE16(unsigned char* ptr, uint16_t x)
{
    uint16_t v = htobe16_internal(x);
    memcpy(ptr, &v, 2);
}

inline void WriteBE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htobe32_internal(x);
    memcpy(ptr, &v, 4);
}

inline void WriteBE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htobe64_internal(x);
    memcpy(ptr, &v, 8);
}

#endif // BITCOIN_CRYPTO_COMMON_H
