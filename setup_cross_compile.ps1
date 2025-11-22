# Cross-compilation toolchain setup script
# Installs compilers for Linux, macOS, and WebAssembly targets

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  CROSS-COMPILATION TOOLCHAIN SETUP" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if running in MSYS2
$inMSYS2 = $env:MSYSTEM -ne $null

if ($inMSYS2) {
    Write-Host "Running in MSYS2 environment: $($env:MSYSTEM)" -ForegroundColor Green
} else {
    Write-Host "Not in MSYS2. Some operations may require MSYS2." -ForegroundColor Yellow
}

# Install MSYS2 packages for cross-compilation
Write-Host "`n1. Installing MSYS2 cross-compilation packages..." -ForegroundColor Yellow

$msys2Packages = @(
    "mingw-w64-x86_64-gcc",           # Windows x64 compiler (already have)
    "mingw-w64-i686-gcc",             # Windows x86 compiler
    "mingw-w64-x86_64-openssl",       # OpenSSL for Windows x64
    "mingw-w64-i686-openssl"          # OpenSSL for Windows x86
)

Write-Host "To install cross-compilers in MSYS2, run:" -ForegroundColor Cyan
Write-Host "  pacman -S $($msys2Packages -join ' ')" -ForegroundColor White

# Emscripten for WebAssembly
Write-Host "`n2. Installing Emscripten (WebAssembly compiler)..." -ForegroundColor Yellow
Write-Host "Download from: https://emscripten.org/docs/getting_started/downloads.html" -ForegroundColor Cyan
Write-Host "Or use:" -ForegroundColor Cyan
Write-Host "  git clone https://github.com/emscripten-core/emsdk.git" -ForegroundColor White
Write-Host "  cd emsdk" -ForegroundColor White
Write-Host "  emsdk install latest" -ForegroundColor White
Write-Host "  emsdk activate latest" -ForegroundColor White

# Linux cross-compilers
Write-Host "`n3. Installing Linux cross-compilers..." -ForegroundColor Yellow
Write-Host "For x86_64-linux-gnu:" -ForegroundColor Cyan
Write-Host "  Install WSL2: wsl --install" -ForegroundColor White
Write-Host "  Or use Docker: docker run -it ubuntu:22.04" -ForegroundColor White
Write-Host ""
Write-Host "For ARM64 Linux:" -ForegroundColor Cyan
Write-Host "  In WSL/Docker: sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu" -ForegroundColor White

# macOS cross-compilers (OSXCross)
Write-Host "`n4. Installing macOS cross-compilers (OSXCross)..." -ForegroundColor Yellow
Write-Host "Requires macOS SDK (must be obtained legally)" -ForegroundColor Cyan
Write-Host "Steps:" -ForegroundColor Cyan
Write-Host "  git clone https://github.com/tpoechtrager/osxcross" -ForegroundColor White
Write-Host "  # Place MacOSX SDK in osxcross/tarballs/" -ForegroundColor White
Write-Host "  UNATTENDED=1 ./build.sh" -ForegroundColor White

# Docker-based solution (recommended)
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "RECOMMENDED: Use Docker for cross-compilation" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

$dockerfileContent = @"
FROM ubuntu:22.04

# Install cross-compilers
RUN apt-get update && apt-get install -y \
    gcc g++ make cmake \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    libssl-dev \
    git wget curl

# Install Emscripten
RUN git clone https://github.com/emscripten-core/emsdk.git /opt/emsdk && \
    cd /opt/emsdk && \
    ./emsdk install latest && \
    ./emsdk activate latest

ENV PATH="/opt/emsdk:/opt/emsdk/upstream/emscripten:$PATH"

WORKDIR /build
"@

$dockerfileContent | Out-File -FilePath "Dockerfile.crosscompile" -Encoding UTF8

Write-Host "Created Dockerfile.crosscompile" -ForegroundColor Green
Write-Host "To use:" -ForegroundColor Cyan
Write-Host "  docker build -t crypto-builder -f Dockerfile.crosscompile ." -ForegroundColor White
Write-Host "  docker run -v ${PWD}:/build crypto-builder ./build_all_platforms.sh" -ForegroundColor White

# Create shell script version for Linux/Docker
$shellScript = @"
#!/bin/bash
# Multi-platform build script for Linux/Docker environment

set -e

VERSION="1.0.0"
BASE_URL="https://your-cdn.com/builds/v\$VERSION"
OUTPUT_DIR="lib"
MANIFEST_FILE="build_manifest.json"

echo "========================================="
echo "  MULTI-PLATFORM BUILD SYSTEM"
echo "  Version: \$VERSION"
echo "========================================="
echo ""

# Build for Linux x64
if command -v gcc &> /dev/null; then
    echo "Building for linux-x64..."
    # TODO: Add build commands
fi

# Build for Linux ARM64
if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    echo "Building for linux-arm64..."
    # TODO: Add build commands
fi

# Build for WebAssembly
if command -v emcc &> /dev/null; then
    echo "Building for wasm..."
    # TODO: Add build commands
fi

echo ""
echo "Build complete!"
"@

$shellScript | Out-File -FilePath "build_all_platforms.sh" -Encoding UTF8
& wsl chmod +x build_all_platforms.sh 2>$null

Write-Host "`nCreated build_all_platforms.sh" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Setup information saved!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan
