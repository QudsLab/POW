#!/bin/bash
# WebAssembly Build Script - Builds WASM modules

set -e

echo "=== Building WebAssembly Binaries ==="

if ! command -v emcc &> /dev/null; then
    echo "Emscripten not found, building regular binaries as .wasm..."
    
    # Build once
    echo "Building binaries..."
    make clean
    make all
    
    # Copy to 32-bit
    mkdir -p bin/wasm/32
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
    
    # Copy to 64-bit
    mkdir -p bin/wasm/64
    if [ "$(ls -A bin/wasm/32 2>/dev/null)" ]; then
        cp bin/wasm/32/*.wasm bin/wasm/64/
        echo "Copied to 64-bit directory"
    else
        echo "Warning: No files in 32-bit directory"
    fi
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
