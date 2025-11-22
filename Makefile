# POW Algorithms Build System
# Compiles all stable PoW algorithms into shared libraries

# Compiler and flags
CC = gcc
CXX = g++
CFLAGS = -Wall -O3 -fPIC -I. -Isrc/stable
CXXFLAGS = -Wall -O3 -fPIC -std=c++11 -I. -Isrc/stable
LDFLAGS = -shared

# Directories
SRC_DIR = src/stable
CACHE_DIR = cache/stable
BUILD_DIR = build
BIN_DIR = bin
LIB_DIR = lib

# Output directories
$(shell mkdir -p $(BUILD_DIR))
$(shell mkdir -p $(BIN_DIR))
$(shell mkdir -p $(LIB_DIR))

# Targets
.PHONY: all clean sha256d randomx wrapper test_sha256d test_randomx

all: sha256d randomx wrapper

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) $(LIB_DIR)

# ============================================================
# SHA-256d (Bitcoin PoW)
# ============================================================
SHA256D_SRC = $(SRC_DIR)/sha256d/server/sha256d.c
SHA256D_CLIENT = $(SRC_DIR)/sha256d/client/sha256d_client.c
SHA256D_OBJ = $(BUILD_DIR)/sha256d.o
SHA256D_CLIENT_OBJ = $(BUILD_DIR)/sha256d_client.o
SHA256D_LIB = $(LIB_DIR)/libpow_sha256d.dll

sha256d: $(SHA256D_LIB)

$(SHA256D_OBJ): $(SHA256D_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(SHA256D_CLIENT_OBJ): $(SHA256D_CLIENT)
	$(CC) $(CFLAGS) -c $< -o $@

$(SHA256D_LIB): $(SHA256D_OBJ) $(SHA256D_CLIENT_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

# ============================================================
# RandomX (Monero PoW)
# ============================================================
RANDOMX_DIR = $(CACHE_DIR)/randomx
RANDOMX_BUILD = $(RANDOMX_DIR)/build
RANDOMX_LIB_SRC = $(RANDOMX_BUILD)/librandomx.a
RANDOMX_WRAPPER_SRC = $(SRC_DIR)/randomx/server/randomx_wrapper.c
RANDOMX_CLIENT_SRC = $(SRC_DIR)/randomx/client/randomx_client.c
RANDOMX_WRAPPER_OBJ = $(BUILD_DIR)/randomx_wrapper.o
RANDOMX_CLIENT_OBJ = $(BUILD_DIR)/randomx_client.o
RANDOMX_LIB = $(LIB_DIR)/libpow_randomx.dll

# Build RandomX library first
$(RANDOMX_LIB_SRC):
	cd $(RANDOMX_DIR) && mkdir -p build && cd build && cmake .. && cmake --build . --config Release

randomx: $(RANDOMX_LIB)

$(RANDOMX_WRAPPER_OBJ): $(RANDOMX_WRAPPER_SRC) $(RANDOMX_LIB_SRC)
	$(CC) $(CFLAGS) -I$(RANDOMX_DIR)/src -c $< -o $@

$(RANDOMX_CLIENT_OBJ): $(RANDOMX_CLIENT_SRC)
	$(CC) $(CFLAGS) -I$(RANDOMX_DIR)/src -c $< -o $@

$(RANDOMX_LIB): $(RANDOMX_WRAPPER_OBJ) $(RANDOMX_CLIENT_OBJ) $(RANDOMX_LIB_SRC)
	$(CXX) $(LDFLAGS) -o $@ $(RANDOMX_WRAPPER_OBJ) $(RANDOMX_CLIENT_OBJ) $(RANDOMX_LIB_SRC) -static-libgcc -static-libstdc++

# ============================================================
# Unified Wrapper Library
# ============================================================
WRAPPER_SRC = $(SRC_DIR)/pow_wrapper.c
WRAPPER_OBJ = $(BUILD_DIR)/pow_wrapper.o
WRAPPER_LIB = $(LIB_DIR)/libpow_wrapper.dll

wrapper: $(WRAPPER_LIB)

$(WRAPPER_OBJ): $(WRAPPER_SRC) $(SHA256D_OBJ)
	$(CC) $(CFLAGS) -I$(SRC_DIR)/sha256d/server -c $< -o $@

$(WRAPPER_LIB): $(WRAPPER_OBJ) $(SHA256D_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

# ============================================================
# Test Programs
# ============================================================
test_sha256d: $(BIN_DIR)/test_sha256d.exe

$(BIN_DIR)/test_sha256d.exe: tests/test_sha256d.c $(SHA256D_LIB)
	$(CC) $(CFLAGS) -o $@ $< -L$(LIB_DIR) -lpow_sha256d

test_randomx: $(BIN_DIR)/test_randomx.exe

$(BIN_DIR)/test_randomx.exe: tests/test_randomx.c $(RANDOMX_LIB)
	$(CC) $(CFLAGS) -I$(RANDOMX_DIR)/src -I$(SRC_DIR)/randomx/server -o $@ $< -L$(LIB_DIR) -lpow_randomx

# ============================================================
# Help
# ============================================================
help:
	@echo "POW Algorithms Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build all libraries"
	@echo "  sha256d      - Build SHA-256d library"
	@echo "  randomx      - Build RandomX library"
	@echo "  wrapper      - Build unified wrapper library"
	@echo "  clean        - Remove all build artifacts"
	@echo "  test_sha256d - Build SHA-256d test program"
	@echo "  test_randomx - Build RandomX test program"
	@echo ""
	@echo "Output:"
	@echo "  Libraries: lib/"
	@echo "  Binaries:  bin/"
