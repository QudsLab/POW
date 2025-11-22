#!/bin/bash
# Linux .so builder for all architectures

set -e

ARCH=${1:-x64}
SRC_DIR="../src/server"
BUILD_DIR="../build_temp/linux_${ARCH}"
OUT_DIR="../lib/linux/${ARCH}"

echo "Building Linux $ARCH shared libraries..."

# Determine compiler
case "$ARCH" in
    x64)
        CC="gcc"
        ARCH_FLAGS="-m64"
        ;;
    arm64)
        CC="aarch64-linux-gnu-gcc"
        ARCH_FLAGS=""
        ;;
    armv7)
        CC="arm-linux-gnueabihf-gcc"
        ARCH_FLAGS="-march=armv7-a"
        ;;
    *)
        echo "Unknown architecture: $ARCH"
        exit 1
        ;;
esac

# Clean and create directories
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/obj"
mkdir -p "$OUT_DIR/server"
mkdir -p "$OUT_DIR/client"

# Compiler flags
CFLAGS="$ARCH_FLAGS -O2 -std=c11 -fPIC -Wall"
INCLUDES="-I$SRC_DIR -I$SRC_DIR/deps -I$SRC_DIR/deps/sph -I$SRC_DIR/deps/blake2 -I$SRC_DIR/deps/pbkdf2 -I$SRC_DIR/deps/scrypt"

echo "Compiling SPH library..."
for file in "$SRC_DIR/deps/sph"/*.c; do
    base=$(basename "$file" .c)
    if [[ ! "$base" =~ test|bench|Main|blake2 ]]; then
        $CC $CFLAGS $INCLUDES -c "$file" -o "$BUILD_DIR/obj/${base}.o" 2>/dev/null || true
    fi
done

echo "Compiling BLAKE2..."
for file in "$SRC_DIR/deps/blake2"/*-ref.c; do
    base=$(basename "$file" .c)
    $CC $CFLAGS $INCLUDES -c "$file" -o "$BUILD_DIR/obj/${base}.o"
done

echo "Compiling PBKDF2..."
[ -f "$SRC_DIR/deps/pbkdf2/pbkdf2.c" ] && \
    $CC $CFLAGS $INCLUDES -c "$SRC_DIR/deps/pbkdf2/pbkdf2.c" -o "$BUILD_DIR/obj/pbkdf2.o"

echo "Compiling scrypt..."
for file in "$SRC_DIR/deps/scrypt"/*.c; do
    base=$(basename "$file" .c)
    [[ ! "$base" =~ test|check|hash ]] && \
        $CC $CFLAGS $INCLUDES -c "$file" -o "$BUILD_DIR/obj/scrypt_${base}.o" 2>/dev/null || true
done

# Use same implementation as Windows but change dllexport
sed 's/__declspec(dllexport)/__attribute__((visibility("default")))/g' \
    "../build_scripts/build_windows.sh" | \
    awk '/^cat > .*real_impl.c/,/^IMPL_EOF$/' | \
    sed '1d;$d' > "$BUILD_DIR/real_impl.c"

echo "Linking shared libraries..."
$CC $CFLAGS $INCLUDES -c "$BUILD_DIR/real_impl.c" -o "$BUILD_DIR/obj/real_impl.o"

OBJ_FILES=$(find "$BUILD_DIR/obj" -name "*.o")

$CC $ARCH_FLAGS -shared -o "$OUT_DIR/server/libstable_crypto_server.so" $OBJ_FILES -lssl -lcrypto -s
cp "$OUT_DIR/server/libstable_crypto_server.so" "$OUT_DIR/client/libstable_crypto_client.so"

echo "Build complete!"
ls -lh "$OUT_DIR/server/"
