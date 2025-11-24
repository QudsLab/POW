#!/bin/bash
# macOS Build Script - Builds universal binaries

set -e

echo "=== Building macOS Binaries ==="

# Build 64-bit (universal or native)
echo "Building 64-bit macOS libraries..."
make clean
make all
mkdir -p bin/macos/64
cp bin/*.dylib bin/macos/64/ 2>/dev/null || echo "No macOS libraries found"

echo "macOS build complete!"
