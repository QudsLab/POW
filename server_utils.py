"""
Server Utilities - Full hash computation for all 39 algorithms
Automatically detects and loads DLLs from absolute paths
"""
import ctypes
import os
import platform
import sys
from pathlib import Path
from enum import IntEnum


class CryptoAlgorithm(IntEnum):
    """Enumeration of all 39 supported algorithms"""
    SHA2 = 0
    SHA3 = 1
    SHA256D = 2
    BLAKE2 = 3
    BLAKE2MAC = 4
    BLAKE3 = 5
    KECCAK = 6
    SKEIN = 7
    GROESTL = 8
    JH = 9
    CUBEHASH = 10
    WHIRLPOOL = 11
    RIPEMD = 12
    X11 = 13
    X13 = 14
    X16R = 15
    SCRYPT = 16
    ARGON2_FULL = 17
    BCRYPT = 18
    PBKDF2 = 19
    LYRA2REV2 = 20
    LYRA2Z = 21
    EQUIHASH = 22
    RANDOMX = 23
    PROGPOW = 24
    ETHASH = 25
    HKDF = 26
    CONCATKDF = 27
    X963KDF = 28
    HMAC = 29
    POLY1305 = 30
    KMAC = 31
    GMAC = 32
    SIPHASH = 33
    CHACHA20POLY1305 = 34
    AESGCM = 35
    AESCCM = 36
    AESOCB = 37
    AESEAX = 38


def find_server_dll():
    """Find server DLL using absolute paths"""
    base_dir = Path(__file__).parent.absolute()
    
    # Check possible locations
    possible_paths = [
        base_dir / "lib" / "win" / "64" / "server" / "stable_crypto_server.dll",
        base_dir / "lib" / "stable_crypto_server.dll",
        base_dir / "stable_crypto_server.dll",
    ]
    
    for dll_path in possible_paths:
        if dll_path.exists():
            # Add directory to PATH for dependencies
            dll_dir = dll_path.parent
            os.environ['PATH'] = str(dll_dir) + os.pathsep + os.environ.get('PATH', '')
            return dll_path
    
    # Also try MinGW path
    mingw_path = r"C:\msys64\ucrt64\bin"
    if os.path.exists(mingw_path):
        os.environ['PATH'] = mingw_path + os.pathsep + os.environ.get('PATH', '')
    
    raise FileNotFoundError(f"Server DLL not found. Searched:\n" + "\n".join(str(p) for p in possible_paths))


class ServerUtils:
    """Server utilities for hash computation"""
    
    # Expected output sizes for each algorithm (in bytes)
    OUTPUT_SIZES = {
        CryptoAlgorithm.SHA2: 64,
        CryptoAlgorithm.SHA3: 32,
        CryptoAlgorithm.SHA256D: 32,
        CryptoAlgorithm.BLAKE2: 64,
        CryptoAlgorithm.BLAKE2MAC: 32,
        CryptoAlgorithm.BLAKE3: 32,
        CryptoAlgorithm.KECCAK: 32,
        CryptoAlgorithm.SKEIN: 64,
        CryptoAlgorithm.GROESTL: 64,
        CryptoAlgorithm.JH: 64,
        CryptoAlgorithm.CUBEHASH: 64,
        CryptoAlgorithm.WHIRLPOOL: 64,
        CryptoAlgorithm.RIPEMD: 20,
        CryptoAlgorithm.X11: 32,
        CryptoAlgorithm.X13: 32,
        CryptoAlgorithm.X16R: 32,
        CryptoAlgorithm.SCRYPT: 32,
        CryptoAlgorithm.ARGON2_FULL: 32,
        CryptoAlgorithm.BCRYPT: 60,
        CryptoAlgorithm.PBKDF2: 32,
        CryptoAlgorithm.LYRA2REV2: 32,
        CryptoAlgorithm.LYRA2Z: 32,
        CryptoAlgorithm.EQUIHASH: 32,
        CryptoAlgorithm.RANDOMX: 32,
        CryptoAlgorithm.PROGPOW: 32,
        CryptoAlgorithm.ETHASH: 32,
        CryptoAlgorithm.HKDF: 32,
        CryptoAlgorithm.CONCATKDF: 32,
        CryptoAlgorithm.X963KDF: 32,
        CryptoAlgorithm.HMAC: 32,
        CryptoAlgorithm.POLY1305: 16,
        CryptoAlgorithm.KMAC: 32,
        CryptoAlgorithm.GMAC: 16,
        CryptoAlgorithm.SIPHASH: 8,
        CryptoAlgorithm.CHACHA20POLY1305: 48,
        CryptoAlgorithm.AESGCM: 48,
        CryptoAlgorithm.AESCCM: 48,
        CryptoAlgorithm.AESOCB: 48,
        CryptoAlgorithm.AESEAX: 48,
    }
    
    def __init__(self, dll_path=None):
        """Initialize server utils with DLL"""
        if dll_path is None:
            dll_path = find_server_dll()
        
        self.dll_path = dll_path
        self.dll = ctypes.CDLL(str(dll_path))
        print(f"Server DLL loaded: {dll_path}")
    
    def hash(self, algorithm, input_data, output_size=None):
        """
        Compute hash using specified algorithm
        
        Args:
            algorithm: CryptoAlgorithm enum value
            input_data: bytes - input data to hash
            output_size: int - expected output size (auto-determined if None)
        
        Returns:
            bytes: Hash output
        """
        if output_size is None:
            output_size = self.OUTPUT_SIZES.get(algorithm, 32)
        
        # Use unified server hash function
        hash_func = self.dll.stable_server_hash
        
        # Setup function signature
        hash_func.argtypes = [
            ctypes.c_int,                    # algo
            ctypes.POINTER(ctypes.c_uint8),  # input
            ctypes.c_size_t,                 # input_len
            ctypes.POINTER(ctypes.c_uint8),  # output
            ctypes.c_size_t                  # output_len
        ]
        hash_func.restype = ctypes.c_int
        
        # Prepare buffers
        input_buf = (ctypes.c_uint8 * len(input_data)).from_buffer_copy(input_data)
        output_buf = (ctypes.c_uint8 * output_size)()
        
        # Call function with algorithm enum value
        result = hash_func(algorithm, input_buf, len(input_data), output_buf, output_size)
        
        if result != 0:
            raise RuntimeError(f"Hash computation failed with code {result}")
        
        return bytes(output_buf)
    
    def get_algorithm_name(self, algorithm):
        """Get human-readable algorithm name"""
        return CryptoAlgorithm(algorithm).name
    
    def get_output_size(self, algorithm):
        """Get expected output size for algorithm"""
        return self.OUTPUT_SIZES.get(algorithm, 32)
    
    def get_all_algorithms(self):
        """Get list of all algorithms"""
        return list(CryptoAlgorithm)


# Quick test when run directly
if __name__ == "__main__":
    print("Testing Server Utils...")
    server = ServerUtils()
    
    test_data = b"Hello, World!"
    result = server.hash(CryptoAlgorithm.SHA256D, test_data)
    print(f"SHA256D: {result.hex()[:32]}...")
    print("Server utils working!")
