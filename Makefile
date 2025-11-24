# Makefile - Windows-Compatible PoW Build System
# Builds shared libraries (.dll) with object files in obj/ directory

# Compiler settings
CC = gcc
CXX = g++
CFLAGS = -w -O2 -std=c99 -fPIC
CXXFLAGS = -w -O2 -std=c++11 -fPIC
LDFLAGS = -lm -lpthread

# Platform detection
UNAME := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME),Linux)
	DLL_EXT = .so
else ifeq ($(UNAME),Darwin)
	DLL_EXT = .dylib
else
	DLL_EXT = .dll
endif

# Paths
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Manually list all C and C++ files (cross-platform)
C_SRCS = \
	src/cb_blake3/blake3.c \
	src/cb_keccak/keccak.c \
	src/cb_sha2/sha256.c \
	src/cb_sha2/sha512.c \
	src/crypto/blake2b-ref.c \
	src/hb_zhash/zhash.c \
	src/hb_zhash/zsorted_hash.c \
	src/mb_argon/argon2.c \
	src/mb_argon/core.c \
	src/mb_argon/encoding.c \
	src/mb_argon/ref.c \
	src/mb_argon/thread.c \
	src/mb_scrypt/scrypt.c \
	src/client.c \
	src/client_main.c \
	src/pow_utils.c \
	src/pow_wrappers.c \
	src/server.c \
	src/server_main.c

CPP_SRCS =

# Map source files to object files in obj/ directory (cross-platform)
# Files stored flat in obj/ with path encoded in filename
C_OBJS = \
	obj/cb_blake3_blake3.obj \
	obj/cb_keccak_keccak.obj \
	obj/cb_sha2_sha256.obj \
	obj/cb_sha2_sha512.obj \
	obj/crypto_blake2b-ref.obj \
	obj/hb_zhash_zhash.obj \
	obj/hb_zhash_zsorted_hash.obj \
	obj/mb_argon_argon2.obj \
	obj/mb_argon_core.obj \
	obj/mb_argon_encoding.obj \
	obj/mb_argon_ref.obj \
	obj/mb_argon_thread.obj \
	obj/mb_scrypt_scrypt.obj \
	obj/client.obj \
	obj/client_main.obj \
	obj/pow_utils.obj \
	obj/pow_wrappers.obj \
	obj/server.obj \
	obj/server_main.obj

CPP_OBJS =
ALL_OBJS = $(C_OBJS) $(CPP_OBJS)

# Include paths
INCLUDES = -I$(SRC_DIR) \
	-I$(SRC_DIR)/cb_blake3 \
	-I$(SRC_DIR)/cb_keccak \
	-I$(SRC_DIR)/cb_sha2 \
	-I$(SRC_DIR)/mb_argon \
	-I$(SRC_DIR)/mb_scrypt \
	-I$(SRC_DIR)/pb_cuckoo \
	-I$(SRC_DIR)/pb_cuckaroo \
	-I$(SRC_DIR)/pb_cuckarood \
	-I$(SRC_DIR)/pb_cuckaroom \
	-I$(SRC_DIR)/pb_cuckarooz \
	-I$(SRC_DIR)/pb_cuckatoo \
	-I$(SRC_DIR)/hb_zhash \
	-I$(SRC_DIR)/crypto

# DLL targets
SERVER_DLL = $(BIN_DIR)/server$(DLL_EXT)
CLIENT_DLL = $(BIN_DIR)/client$(DLL_EXT)

# Default target
.PHONY: all clean rebuild info help

all: $(SERVER_DLL) $(CLIENT_DLL)
	@echo.
	@echo Build Complete!
	@echo   Server DLL: $(SERVER_DLL)
	@echo   Client DLL: $(CLIENT_DLL)

# Create build directories
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Compile C files to object files in obj/ directory (flat structure)
obj/cb_blake3_blake3.obj: src/cb_blake3/blake3.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/cb_keccak_keccak.obj: src/cb_keccak/keccak.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/cb_sha2_sha256.obj: src/cb_sha2/sha256.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/cb_sha2_sha512.obj: src/cb_sha2/sha512.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/crypto_blake2b-ref.obj: src/crypto/blake2b-ref.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/hb_zhash_zhash.obj: src/hb_zhash/zhash.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/hb_zhash_zsorted_hash.obj: src/hb_zhash/zsorted_hash.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/mb_argon_argon2.obj: src/mb_argon/argon2.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/mb_argon_core.obj: src/mb_argon/core.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/mb_argon_encoding.obj: src/mb_argon/encoding.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/mb_argon_ref.obj: src/mb_argon/ref.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/mb_argon_thread.obj: src/mb_argon/thread.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/mb_scrypt_scrypt.obj: src/mb_scrypt/scrypt.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/client.obj: src/client.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/client_main.obj: src/client_main.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/pow_utils.obj: src/pow_utils.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/pow_wrappers.obj: src/pow_wrappers.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/server.obj: src/server.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/server_main.obj: src/server_main.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link server DLL - exclude client_main.obj
SERVER_OBJS = $(C_OBJS) $(CPP_OBJS)
SERVER_OBJS := $(filter-out obj/client_main.obj,$(SERVER_OBJS))

$(SERVER_DLL): $(SERVER_OBJS) | $(BIN_DIR)
	$(CXX) -shared $(SERVER_OBJS) -o $@ $(LDFLAGS)
	@echo Built: $@

# Link client DLL - exclude server_main.obj
CLIENT_OBJS = $(C_OBJS) $(CPP_OBJS)
CLIENT_OBJS := $(filter-out obj/server_main.obj,$(CLIENT_OBJS))

$(CLIENT_DLL): $(CLIENT_OBJS) | $(BIN_DIR)
	$(CXX) -shared $(CLIENT_OBJS) -o $@ $(LDFLAGS)
	@echo Built: $@

# Info target
info:
	@echo.
	@echo === Build Information ===
	@echo C files: $(words $(C_SRCS))
	@echo C++ files: $(words $(CPP_SRCS))
	@echo Total: $(words $(C_SRCS) $(CPP_SRCS))
	@echo.
	@echo Output:
	@echo   $(SERVER_DLL)
	@echo   $(CLIENT_DLL)

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo Cleaned.

rebuild: clean all

help:
	@echo.
	@echo PoW System Build Commands:
	@echo   make all       - Build both server and client DLLs
	@echo   make clean     - Remove all build files
	@echo   make rebuild   - Clean and rebuild
	@echo   make info      - Show build information
	@echo   make help      - Show this help
	@echo.
