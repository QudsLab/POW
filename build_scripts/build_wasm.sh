#!/bin/bash
# WebAssembly builder using Emscripten

set -e

SRC_DIR="../src/server"
BUILD_DIR="../build_temp/wasm"
OUT_DIR="../lib/wasm"

echo "Building WebAssembly modules..."

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/obj"
mkdir -p "$OUT_DIR"

EMCC="emcc"
CFLAGS="-O3 -std=c11 -s WASM=1 -s EXPORTED_RUNTIME_METHODS=['ccall','cwrap'] -s ALLOW_MEMORY_GROWTH=1"
INCLUDES="-I$SRC_DIR -I$SRC_DIR/deps -I$SRC_DIR/deps/sph -I$SRC_DIR/deps/blake2 -I$SRC_DIR/deps/pbkdf2 -I$SRC_DIR/deps/scrypt"

# Collect source files
SOURCES=""

for file in "$SRC_DIR/deps/sph"/*.c; do
    base=$(basename "$file" .c)
    [[ ! "$base" =~ test|bench|Main|blake2 ]] && SOURCES="$SOURCES $file"
done

for file in "$SRC_DIR/deps/blake2"/*-ref.c; do
    SOURCES="$SOURCES $file"
done

[ -f "$SRC_DIR/deps/pbkdf2/pbkdf2.c" ] && SOURCES="$SOURCES $SRC_DIR/deps/pbkdf2/pbkdf2.c"

for file in "$SRC_DIR/deps/scrypt"/*.c; do
    base=$(basename "$file" .c)
    [[ ! "$base" =~ test|check|hash ]] && SOURCES="$SOURCES $file"
done

# Create WASM-compatible implementation (remove dllexport)
sed 's/__declspec(dllexport)/EMSCRIPTEN_KEEPALIVE/g' \
    "../build_scripts/build_windows.sh" | \
    awk '/^cat > .*real_impl.c/,/^IMPL_EOF$/' | \
    sed '1d;$d;1i#include <emscripten.h>' > "$BUILD_DIR/real_impl.c"

echo "Compiling to WebAssembly..."
$EMCC $CFLAGS $INCLUDES $SOURCES "$BUILD_DIR/real_impl.c" \
    -o "$OUT_DIR/stable_crypto.js" \
    -s EXPORTED_FUNCTIONS='["_stable_server_hash","_stable_client_verify_hash"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='StableCrypto'

echo "Build complete!"
ls -lh "$OUT_DIR/"
