// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license

#ifndef BITCOIN_COMPAT_BYTESWAP_H
#define BITCOIN_COMPAT_BYTESWAP_H

#include <cstdint>
#ifdef _MSC_VER
#include <cstdlib>
#endif

#ifndef DISABLE_BUILTIN_BSWAPS
#  if defined __has_builtin
#    if __has_builtin(__builtin_bswap16)
#      define bitcoin_builtin_bswap16(x) __builtin_bswap16(x)
#    endif
#    if __has_builtin(__builtin_bswap32)
#      define bitcoin_builtin_bswap32(x) __builtin_bswap32(x)
#    endif
#    if __has_builtin(__builtin_bswap64)
#      define bitcoin_builtin_bswap64(x) __builtin_bswap64(x)
#    endif
#  elif defined(_MSC_VER)
#      define bitcoin_builtin_bswap16(x) _byteswap_ushort(x)
#      define bitcoin_builtin_bswap32(x) _byteswap_ulong(x)
#      define bitcoin_builtin_bswap64(x) _byteswap_uint64(x)
#  endif
#endif

#ifndef _MSC_VER
#define BSWAP_CONSTEXPR constexpr
#else
#define BSWAP_CONSTEXPR
#endif

inline BSWAP_CONSTEXPR uint16_t internal_bswap_16(uint16_t x)
{
#ifdef bitcoin_builtin_bswap16
    return bitcoin_builtin_bswap16(x);
#else
    return (x >> 8) | (x << 8);
#endif
}

inline BSWAP_CONSTEXPR uint32_t internal_bswap_32(uint32_t x)
{
#ifdef bitcoin_builtin_bswap32
    return bitcoin_builtin_bswap32(x);
#else
    return (((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >>  8) |
            ((x & 0x0000ff00U) <<  8) | ((x & 0x000000ffU) << 24));
#endif
}

inline BSWAP_CONSTEXPR uint64_t internal_bswap_64(uint64_t x)
{
#ifdef bitcoin_builtin_bswap64
    return bitcoin_builtin_bswap64(x);
#else
    return (((x & 0xff00000000000000ull) >> 56)
          | ((x & 0x00ff000000000000ull) >> 40)
          | ((x & 0x0000ff0000000000ull) >> 24)
          | ((x & 0x000000ff00000000ull) >> 8)
          | ((x & 0x00000000ff000000ull) << 8)
          | ((x & 0x0000000000ff0000ull) << 24)
          | ((x & 0x000000000000ff00ull) << 40)
          | ((x & 0x00000000000000ffull) << 56));
#endif
}

#endif // BITCOIN_COMPAT_BYTESWAP_H
