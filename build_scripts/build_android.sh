#!/bin/bash
# Android NDK builder

set -e

ABI=${1:-arm64-v8a}
SRC_DIR="../src/server"
BUILD_DIR="../build_temp/android_${ABI}"
OUT_DIR="../lib/android/${ABI}"

echo "Building Android $ABI libraries..."

case "$ABI" in
    arm64-v8a)
        TOOLCHAIN="aarch64-linux-android"
        API_LEVEL="21"
        ;;
    armeabi-v7a)
        TOOLCHAIN="armv7a-linux-androideabi"
        API_LEVEL="21"
        ;;
    x86_64)
        TOOLCHAIN="x86_64-linux-android"
        API_LEVEL="21"
        ;;
    x86)
        TOOLCHAIN="i686-linux-android"
        API_LEVEL="21"
        ;;
    *)
        echo "Unknown ABI: $ABI"
        exit 1
        ;;
esac

NDK_ROOT="${ANDROID_NDK_HOME:-$ANDROID_NDK_ROOT}"
[ -z "$NDK_ROOT" ] && echo "Error: NDK not found" && exit 1

CC="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/${TOOLCHAIN}${API_LEVEL}-clang"
SYSROOT="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/sysroot"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/obj"
mkdir -p "$OUT_DIR"

CFLAGS="-O2 -std=c11 -fPIC -Wall --sysroot=$SYSROOT"
INCLUDES="-I$SRC_DIR -I$SRC_DIR/deps -I$SRC_DIR/deps/sph -I$SRC_DIR/deps/blake2 -I$SRC_DIR/deps/pbkdf2 -I$SRC_DIR/deps/scrypt"

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

sed 's/__declspec(dllexport)/__attribute__((visibility("default")))/g' \
    "../build_scripts/build_windows.sh" | \
    awk '/^cat > .*real_impl.c/,/^IMPL_EOF$/' | \
    sed '1d;$d' > "$BUILD_DIR/real_impl.c"

$CC $CFLAGS $INCLUDES -c "$BUILD_DIR/real_impl.c" -o "$BUILD_DIR/obj/real_impl.o"

OBJ_FILES=$(find "$BUILD_DIR/obj" -name "*.o")

echo "Linking shared library..."
$CC -shared -o "$OUT_DIR/libstable_crypto.so" $OBJ_FILES -lssl -lcrypto

echo "Build complete!"
ls -lh "$OUT_DIR/"
