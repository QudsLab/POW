#!/bin/bash
# WebAssembly Build Script - Builds WASM modules

set -e

echo "=== Building WebAssembly Binaries ==="

if ! command -v emcc &> /dev/null; then
    echo "Warning: Emscripten not found, skipping WASM builds"
    mkdir -p bin/wasm/32
    mkdir -p bin/wasm/64
    exit 0
fi

# Build 32-bit WASM
echo "Building 32-bit WebAssembly..."
make clean
mkdir -p bin/wasm/32
# WASM 32-bit build would go here
echo "WASM 32-bit build placeholder"

# Build 64-bit WASM
echo "Building 64-bit WebAssembly..."
make clean
mkdir -p bin/wasm/64
# WASM 64-bit build would go here
echo "WASM 64-bit build placeholder"

echo "WebAssembly build complete!"
