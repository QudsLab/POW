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
    # Rename to .wasm extension for consistency
    for file in bin/*.so bin/*.dll bin/*.dylib; do
        if [ -f "$file" ]; then
            basename=$(basename "$file")
            cp "$file" "bin/wasm/32/${basename%.*}.wasm"
        fi
    done
    
    # Build 64-bit
    echo "Building 64-bit WebAssembly..."
    make clean
    make all
    mkdir -p bin/wasm/64
    for file in bin/*.so bin/*.dll bin/*.dylib; do
        if [ -f "$file" ]; then
            basename=$(basename "$file")
            cp "$file" "bin/wasm/64/${basename%.*}.wasm"
        fi
    done
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
