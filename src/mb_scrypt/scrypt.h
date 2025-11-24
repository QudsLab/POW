#ifndef SCRYPT_H
#define SCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * scrypt key derivation function
 * 
 * @param passwd Password
 * @param passwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param N CPU/memory cost parameter (must be power of 2, > 1)
 * @param r Block size parameter
 * @param p Parallelization parameter
 * @param buf Output buffer
 * @param buflen Output buffer length
 * @return 0 on success, -1 on error
 */
int scrypt(const uint8_t *passwd, size_t passwdlen,
           const uint8_t *salt, size_t saltlen,
           uint64_t N, uint32_t r, uint32_t p,
           uint8_t *buf, size_t buflen);

/**
 * Validate scrypt parameters
 * 
 * @param N CPU/memory cost parameter
 * @param r Block size parameter
 * @param p Parallelization parameter
 * @return 0 if valid, -1 if invalid
 */
int scrypt_check_params(uint64_t N, uint32_t r, uint32_t p);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_H */