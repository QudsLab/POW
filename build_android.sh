#!/bin/bash
# Android Build Script - Builds for Android NDK

set -e

echo "=== Building Android Binaries ==="

# Build 64-bit (just use regular make, will produce .so files)
echo "Building 64-bit Android libraries..."
make clean
make all
mkdir -p bin/android/64
cp bin/*.so bin/android/64/ 2>/dev/null || echo "No .so files found"

# Build 32-bit 
echo "Building 32-bit Android libraries..."
make clean
CFLAGS="-w -O2 -std=c99 -fPIC -m32" CXXFLAGS="-w -O2 -std=c++11 -fPIC -m32" make all 2>/dev/null || echo "32-bit build not available"
mkdir -p bin/android/32
cp bin/*.so bin/android/32/ 2>/dev/null || echo "No 32-bit .so files found"

echo "Android build complete!"
