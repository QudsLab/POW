#!/bin/bash
# Linux Build Script - Builds for multiple architectures

set -e

echo "=== Building Linux Binaries ==="

# Build 64-bit x64
echo "Building 64-bit Linux libraries..."
make clean-obj
make all
mkdir -p bin/linux/64
cp bin/*.so bin/linux/64/ 2>/dev/null || echo "No 64-bit libraries found"

# Build 32-bit x86
echo "Building 32-bit Linux libraries..."
make clean-obj
if command -v gcc-multilib &> /dev/null || dpkg -l | grep -q gcc-multilib; then
    CFLAGS="-w -O2 -std=c99 -fPIC -m32" CXXFLAGS="-w -O2 -std=c++11 -fPIC -m32" make all 2>/dev/null || echo "32-bit build failed"
    mkdir -p bin/linux/32
    cp bin/*.so bin/linux/32/ 2>/dev/null || echo "No 32-bit libraries found"
else
    echo "gcc-multilib not available, skipping 32-bit build"
fi

# ARM builds would require cross-compilation toolchain
# Skipping for now as they need specific setup

echo "Linux build complete!"
