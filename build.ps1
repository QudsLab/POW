# Complete Build Script - Server and Client DLLs
# Usage: .\build.ps1 [-Clean]

param([switch]$Clean)

$ErrorActionPreference = "Stop"
$ROOT = $PSScriptRoot
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"

# Directories
$BINS_OBJ = "$ROOT\bins\obj"
$BUILD_DIR = "$ROOT\build"
$LIB_SERVER = "$ROOT\lib\win\64\server"
$LIB_CLIENT = "$ROOT\lib\win\64\client"
$SRC_SERVER = "$ROOT\src\server"
$SRC_CLIENT = "$ROOT\src\client"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Crypto Library Build - Complete" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Clean
if ($Clean) {
    Write-Host "[*] Cleaning..." -ForegroundColor Yellow
    Remove-Item $BINS_OBJ -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $BUILD_DIR -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Cleaned" -ForegroundColor Green
}

# Create directories
Write-Host "[*] Creating directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path "$BINS_OBJ\server\deps" -Force | Out-Null
New-Item -ItemType Directory -Path "$BINS_OBJ\client" -Force | Out-Null
New-Item -ItemType Directory -Path $BUILD_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $LIB_SERVER -Force | Out-Null
New-Item -ItemType Directory -Path $LIB_CLIENT -Force | Out-Null
Write-Host "[+] Directories ready" -ForegroundColor Green

# ========== SERVER ==========
Write-Host ""
Write-Host "[*] Building SERVER..." -ForegroundColor Cyan

# Compile server main
Write-Host "    Compiling main files..." -ForegroundColor Gray
Push-Location $SRC_SERVER
Get-ChildItem "stable_*.c" | Where-Object { $_.Name -ne "stable_argon2.c" } | ForEach-Object {
    gcc -m64 -O3 -std=c11 -c $_.Name -o "$BINS_OBJ\server\$($_.BaseName).o"
}
Pop-Location

# Compile server dependencies
Write-Host "    Compiling dependencies..." -ForegroundColor Gray
Push-Location "$SRC_SERVER\deps"

# Only compile well-behaved dependencies (exclude problematic ones)
$excludeDirs = @(
    "libsodium", "ProgPOW", "RandomX", "bitcoin", "crypto", "ZRTP4PJ",
    "argon2", "libgomp", "XKCP", "Lyra", "poly1305", "aead", "chacha20poly1305",
    "blake3_simple", "bcrypt"
)

Get-ChildItem -Recurse -Include "*.c","*.cpp" | Where-Object {
    $excluded = $false
    foreach ($dir in $excludeDirs) {
        if ($_.FullName -like "*\$dir\*") {
            $excluded = $true
            break
        }
    }
    # Also exclude test files
    if ($_.Name -like "*test*" -or $_.Name -like "*bench*" -or $_.Name -like "Main.c") {
        $excluded = $true
    }
    -not $excluded
} | ForEach-Object {
    if ($_.Extension -eq ".cpp") {
        g++ -m64 -O3 -std=c++17 -fopenmp -c $_.FullName -o "$BINS_OBJ\server\deps\$($_.BaseName).o" 2>$null
    } else {
        gcc -m64 -O3 -std=c11 -c $_.FullName -o "$BINS_OBJ\server\deps\$($_.BaseName).o" 2>$null
    }
}
Pop-Location

# Link server
Write-Host "    Linking DLL..." -ForegroundColor Gray
$objs = Get-ChildItem "$BINS_OBJ\server" -Recurse -Filter "*.o" | Select-Object -ExpandProperty FullName
g++ -shared -s -o "$BUILD_DIR\stable_crypto_server.dll" $objs -lssl -lcrypto -lgomp -lwinpthread -lws2_32 -static-libgcc -static-libstdc++

if ($LASTEXITCODE -eq 0) {
    Copy-Item "$BUILD_DIR\stable_crypto_server.dll" $LIB_SERVER -Force
    $size = (Get-Item "$LIB_SERVER\stable_crypto_server.dll").Length / 1MB
    Write-Host "[+] SERVER: $([Math]::Round($size, 2)) MB" -ForegroundColor Green
    
    # Copy dependencies
    @("libstdc++-6.dll", "libgomp-1.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll") | ForEach-Object {
        $src = "C:\msys64\ucrt64\bin\$_"
        if (Test-Path $src) { Copy-Item $src $LIB_SERVER -Force }
    }
} else {
    Write-Host "[!] Server build failed" -ForegroundColor Red
    exit 1
}

# ========== CLIENT ==========
Write-Host ""
Write-Host "[*] Building CLIENT..." -ForegroundColor Cyan

# Compile client main
Write-Host "    Compiling main files..." -ForegroundColor Gray
Push-Location $SRC_CLIENT
Get-ChildItem "stable_*.c" | ForEach-Object {
    gcc -m64 -O3 -std=c11 -c $_.Name -o "$BINS_OBJ\client\$($_.BaseName).o"
}
Pop-Location

# Link client
Write-Host "    Linking DLL..." -ForegroundColor Gray
$objs = Get-ChildItem "$BINS_OBJ\client" -Filter "*.o" | Select-Object -ExpandProperty FullName
gcc -shared -s -o "$BUILD_DIR\stable_crypto_client.dll" $objs -lssl -lcrypto -lwinpthread -lws2_32 -static-libgcc

if ($LASTEXITCODE -eq 0) {
    Copy-Item "$BUILD_DIR\stable_crypto_client.dll" $LIB_CLIENT -Force
    $size = (Get-Item "$LIB_CLIENT\stable_crypto_client.dll").Length / 1MB
    Write-Host "[+] CLIENT: $([Math]::Round($size, 2)) MB" -ForegroundColor Green
} else {
    Write-Host "[!] Client build failed" -ForegroundColor Red
    exit 1
}

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output:" -ForegroundColor Cyan
Write-Host "  Server: lib\win\64\server\stable_crypto_server.dll" -ForegroundColor White
Write-Host "  Client: lib\win\64\client\stable_crypto_client.dll" -ForegroundColor White
Write-Host ""
Write-Host "Test:" -ForegroundColor Cyan
Write-Host "  python all_algo_test_example.py" -ForegroundColor White
Write-Host ""
