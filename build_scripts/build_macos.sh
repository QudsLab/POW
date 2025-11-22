#!/bin/bash
# macOS dylib builder

set -e

ARCH=${1:-x64}
SRC_DIR="../src/server"
BUILD_DIR="../build_temp/macos_${ARCH}"
OUT_DIR="../lib/macos/${ARCH}"

echo "Building macOS $ARCH dynamic libraries..."

case "$ARCH" in
    x64)
        ARCH_FLAGS="-arch x86_64"
        ;;
    arm64)
        ARCH_FLAGS="-arch arm64"
        ;;
    *)
        echo "Unknown architecture: $ARCH"
        exit 1
        ;;
esac

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/obj"
mkdir -p "$OUT_DIR/server"
mkdir -p "$OUT_DIR/client"

CC="clang"
CFLAGS="$ARCH_FLAGS -O2 -std=c11 -fPIC -Wall"
INCLUDES="-I$SRC_DIR -I$SRC_DIR/deps -I$SRC_DIR/deps/sph -I$SRC_DIR/deps/blake2 -I$SRC_DIR/deps/pbkdf2 -I$SRC_DIR/deps/scrypt -I/usr/local/opt/openssl@3/include"
LDFLAGS="$ARCH_FLAGS -L/usr/local/opt/openssl@3/lib"

echo "Compiling sources..."
for file in "$SRC_DIR/deps/sph"/*.c; do
    base=$(basename "$file" .c)
    [[ ! "$base" =~ test|bench|Main|blake2 ]] && \
        $CC $CFLAGS $INCLUDES -c "$file" -o "$BUILD_DIR/obj/${base}.o" 2>/dev/null || true
done

for file in "$SRC_DIR/deps/blake2"/*-ref.c; do
    base=$(basename "$file" .c)
    $CC $CFLAGS $INCLUDES -c "$file" -o "$BUILD_DIR/obj/${base}.o"
done

[ -f "$SRC_DIR/deps/pbkdf2/pbkdf2.c" ] && \
    $CC $CFLAGS $INCLUDES -c "$SRC_DIR/deps/pbkdf2/pbkdf2.c" -o "$BUILD_DIR/obj/pbkdf2.o"

for file in "$SRC_DIR/deps/scrypt"/*.c; do
    base=$(basename "$file" .c)
    [[ ! "$base" =~ test|check|hash ]] && \
        $CC $CFLAGS $INCLUDES -c "$file" -o "$BUILD_DIR/obj/scrypt_${base}.o" 2>/dev/null || true
done

# Create implementation (replace dllexport with visibility)
sed 's/__declspec(dllexport)/__attribute__((visibility("default")))/g' \
    "../build_scripts/build_windows.sh" | \
    awk '/^cat > .*real_impl.c/,/^IMPL_EOF$/' | \
    sed '1d;$d' > "$BUILD_DIR/real_impl.c"

$CC $CFLAGS $INCLUDES -c "$BUILD_DIR/real_impl.c" -o "$BUILD_DIR/obj/real_impl.o"

OBJ_FILES=$(find "$BUILD_DIR/obj" -name "*.o")

echo "Linking dylibs..."
$CC $LDFLAGS -dynamiclib -o "$OUT_DIR/server/libstable_crypto_server.dylib" $OBJ_FILES -lssl -lcrypto
cp "$OUT_DIR/server/libstable_crypto_server.dylib" "$OUT_DIR/client/libstable_crypto_client.dylib"

echo "Build complete!"
ls -lh "$OUT_DIR/server/"
