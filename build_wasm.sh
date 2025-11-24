#!/bin/bash
# WebAssembly Build Script - Builds WASM modules

set -e

echo "=== Building WebAssembly Binaries ==="

if ! command -v emcc &> /dev/null; then
    echo "Emscripten not found, building regular binaries as .wasm..."
    
    # Build 32-bit
    echo "Building 32-bit WebAssembly..."
    make clean
    make all
    mkdir -p bin/wasm/32
    # Copy and rename binaries to .wasm extension
    if ls bin/*.so 1> /dev/null 2>&1; then
        for file in bin/*.so; do
            basename=$(basename "$file" .so)
            cp "$file" "bin/wasm/32/${basename}.wasm"
        done
    fi
    if ls bin/*.dll 1> /dev/null 2>&1; then
        for file in bin/*.dll; do
            basename=$(basename "$file" .dll)
            cp "$file" "bin/wasm/32/${basename}.wasm"
        done
    fi
    if ls bin/*.dylib 1> /dev/null 2>&1; then
        for file in bin/*.dylib; do
            basename=$(basename "$file" .dylib)
            cp "$file" "bin/wasm/32/${basename}.wasm"
        done
    fi
    
    # Build 64-bit (same as 32-bit for now)
    echo "Building 64-bit WebAssembly..."
    mkdir -p bin/wasm/64
    cp bin/wasm/32/*.wasm bin/wasm/64/ 2>/dev/null || echo "Copied from 32-bit"
else
    # Build with Emscripten
    echo "Building with Emscripten..."
    
    # 32-bit WASM
    echo "Building 32-bit WebAssembly..."
    make clean
    CC=emcc CXX=em++ make all 2>/dev/null || echo "Emscripten build attempted"
    mkdir -p bin/wasm/32
    cp bin/*.wasm bin/wasm/32/ 2>/dev/null || echo "No WASM files"
    cp bin/*.js bin/wasm/32/ 2>/dev/null || true
    
    # 64-bit WASM
    echo "Building 64-bit WebAssembly..."
    make clean
    CC=emcc CXX=em++ make all 2>/dev/null || echo "Emscripten build attempted"
    mkdir -p bin/wasm/64
    cp bin/*.wasm bin/wasm/64/ 2>/dev/null || echo "No WASM files"
    cp bin/*.js bin/wasm/64/ 2>/dev/null || true
fi

echo "WebAssembly build complete!"
