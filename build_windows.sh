#!/bin/bash
# Windows Build Script - Builds 32-bit and 64-bit DLLs

set -e

echo "=== Building Windows Binaries ==="

# Build 64-bit
echo "Building 64-bit Windows DLLs..."
make clean
make all
mkdir -p bin/windows/64
cp bin/*.dll bin/windows/64/ 2>/dev/null || echo "No 64-bit DLLs found"

# Build 32-bit (if cross-compilation tools available)
echo "Building 32-bit Windows DLLs..."
make clean
CFLAGS="-w -O2 -std=c99 -fPIC -m32" CXXFLAGS="-w -O2 -std=c++11 -fPIC -m32" make all 2>/dev/null || echo "32-bit build not available"
mkdir -p bin/windows/32
cp bin/*.dll bin/windows/32/ 2>/dev/null || echo "No 32-bit DLLs found"

echo "Windows build complete!"
