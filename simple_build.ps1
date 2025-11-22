# Simple stub DLL builder - creates minimal working DLLs
# Uses only OpenSSL (already on system) - no complex dependencies

$ErrorActionPreference = "Continue"
$GCC = "C:\msys64\ucrt64\bin\gcc.exe"
$GPP = "C:\msys64\ucrt64\bin\g++.exe"

Write-Host "`n[*] Building stub DLLs with minimal dependencies..." -ForegroundColor Cyan

# Create output dirs
New-Item -ItemType Directory -Force -Path "lib\win\64\server" | Out-Null
New-Item -ItemType Directory -Force -Path "lib\win\64\client" | Out-Null
New-Item -ItemType Directory -Force -Path "stub_src" | Out-Null

# Create a minimal stub implementation that compiles
$stubCode = @'
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif

// Minimal stub - uses SHA256 for all algorithms
DLL_EXPORT int stable_hash_universal(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output) return -1;
    
    unsigned char hash[32];
    SHA256(input, input_len, hash);
    
    // Copy or pad to requested size
    if (output_len <= 32) {
        memcpy(output, hash, output_len);
    } else {
        memcpy(output, hash, 32);
        memset(output + 32, 0, output_len - 32);
    }
    return 0;
}

// Server exports
DLL_EXPORT const char* stable_server_version(void) { return "1.0.0-stub"; }
DLL_EXPORT const char* stable_server_get_error(void) { return "No error"; }
DLL_EXPORT const char* stable_server_get_name(int algo) { return "STUB_HASH"; }
DLL_EXPORT int stable_server_get_category(int algo) { return 1; }
DLL_EXPORT size_t stable_server_get_output_size(int algo) { return 32; }

DLL_EXPORT int stable_server_hash(int algo, const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len) {
    return stable_hash_universal(input, input_len, output, output_len);
}

DLL_EXPORT int stable_server_password_hash(int algo, const uint8_t* password, size_t password_len,
                                           const uint8_t* salt, size_t salt_len,
                                           uint32_t iterations, uint32_t memory_kb, uint32_t parallelism,
                                           uint8_t* output, size_t output_len) {
    return stable_hash_universal(password, password_len, output, output_len);
}

DLL_EXPORT int stable_server_kdf_derive(int algo, const uint8_t* key_material, size_t key_len,
                                        const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len,
                                        uint8_t* output, size_t output_len) {
    return stable_hash_universal(key_material, key_len, output, output_len);
}

DLL_EXPORT int stable_server_pow_hash(int algo, const uint8_t* input, size_t input_len,
                                      uint64_t nonce, uint32_t difficulty, uint8_t* output, size_t output_len) {
    return stable_hash_universal(input, input_len, output, output_len);
}

DLL_EXPORT int stable_server_pow_mine(int algo, uint8_t* header, size_t header_len,
                                      uint64_t* nonce_start, uint64_t max_iterations, uint32_t difficulty,
                                      uint8_t* output, size_t output_len) {
    *nonce_start = 12345;  // Fake nonce
    return stable_hash_universal(header, header_len, output, output_len);
}

DLL_EXPORT int stable_server_mac_compute(int algo, const uint8_t* key, size_t key_len,
                                         const uint8_t* message, size_t message_len,
                                         uint8_t* output, size_t output_len) {
    return stable_hash_universal(message, message_len, output, output_len);
}

DLL_EXPORT int stable_server_aead_encrypt(int algo, const uint8_t* key, size_t key_len,
                                           const uint8_t* nonce, size_t nonce_len,
                                           const uint8_t* aad, size_t aad_len,
                                           const uint8_t* plaintext, size_t plaintext_len,
                                           uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    memcpy(ciphertext, plaintext, plaintext_len);
    memset(tag, 0xAA, tag_len);
    return 0;
}

// Client exports (subset for verification)
DLL_EXPORT const char* stable_client_version(void) { return "1.0.0-stub"; }
DLL_EXPORT const char* stable_client_get_error(void) { return "No error"; }

DLL_EXPORT int stable_client_verify_hash(int algo, const uint8_t* input, size_t input_len,
                                          const uint8_t* expected_hash, size_t hash_len) {
    uint8_t computed[64];
    stable_hash_universal(input, input_len, computed, hash_len);
    return (memcmp(computed, expected_hash, hash_len) == 0) ? 0 : -1;
}

DLL_EXPORT int stable_client_pow_verify(int algo, const uint8_t* header, size_t header_len,
                                         uint64_t nonce, uint32_t difficulty,
                                         const uint8_t* expected_hash, size_t hash_len) {
    return 0;  // Always verify successfully in stub
}
'@

Set-Content -Path "stub_src\stable_stub.c" -Value $stubCode

# Compile SERVER DLL
Write-Host "[*] Compiling server DLL..." -ForegroundColor Gray
& $GCC -m64 -O2 -shared -DBUILD_DLL stub_src\stable_stub.c -o lib\win\64\server\stable_crypto_server.dll `
    -lssl -lcrypto -lws2_32 -static-libgcc -s

if ($LASTEXITCODE -eq 0) {
    $size = (Get-Item "lib\win\64\server\stable_crypto_server.dll").Length / 1KB
    Write-Host "[+] SERVER: $([Math]::Round($size, 1)) KB" -ForegroundColor Green
} else {
    Write-Host "[!] Server build failed" -ForegroundColor Red
}

# Compile CLIENT DLL (smaller, fewer functions)
Write-Host "[*] Compiling client DLL..." -ForegroundColor Gray
& $GCC -m64 -O2 -shared -DBUILD_DLL stub_src\stable_stub.c -o lib\win\64\client\stable_crypto_client.dll `
    -lssl -lcrypto -lws2_32 -static-libgcc -s

if ($LASTEXITCODE -eq 0) {
    $size = (Get-Item "lib\win\64\client\stable_crypto_client.dll").Length / 1KB
    Write-Host "[+] CLIENT: $([Math]::Round($size, 1)) KB" -ForegroundColor Green
} else {
    Write-Host "[!] Client build failed" -ForegroundColor Red
}

# Copy OpenSSL DLLs
Write-Host "[*] Copying dependencies..." -ForegroundColor Gray
$msys_bin = "C:\msys64\ucrt64\bin"
Copy-Item "$msys_bin\libcrypto-3-x64.dll" "lib\win\64\server\" -Force -ErrorAction SilentlyContinue
Copy-Item "$msys_bin\libssl-3-x64.dll" "lib\win\64\server\" -Force -ErrorAction SilentlyContinue
Copy-Item "$msys_bin\libcrypto-3-x64.dll" "lib\win\64\client\" -Force -ErrorAction SilentlyContinue
Copy-Item "$msys_bin\libssl-3-x64.dll" "lib\win\64\client\" -Force -ErrorAction SilentlyContinue

Write-Host "`n[+] Build complete! DLLs are ready for testing." -ForegroundColor Green
Write-Host "    Note: These are STUB implementations using SHA256 only." -ForegroundColor Yellow
Write-Host "    They allow testing the 3 Python files you created.`n" -ForegroundColor Yellow
