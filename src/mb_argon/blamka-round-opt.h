/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef BLAMKA_ROUND_OPT_H
#define BLAMKA_ROUND_OPT_H

/* 
 * This file provides optimized (or fallback) implementations of Argon2 hashing.
 * If SSE/AVX support is available, optimized versions would be used here.
 * For now, we use the reference implementation.
 */

#if defined(__AVX512F__)
    /* Would include AVX512F implementation */
    #include "blamka-round-ref.h"
#elif defined(__AVX2__)
    /* Would include AVX2 implementation */
    #include "blamka-round-ref.h"
#elif defined(__SSSE3__)
    /* Would include SSSE3 implementation */
    #include "blamka-round-ref.h"
#else
    /* Fallback to reference implementation */
    #include "blamka-round-ref.h"
#endif

#endif
