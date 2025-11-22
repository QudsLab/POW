"""
Client Utilities - Lightweight verification for all 39 algorithms
Automatically detects and loads DLLs from absolute paths
"""
import ctypes
import os
from pathlib import Path
from server_utils import CryptoAlgorithm, find_server_dll


def find_client_dll():
    """Find client DLL using absolute paths"""
    base_dir = Path(__file__).parent.absolute()
    
    # Check possible locations
    possible_paths = [
        base_dir / "lib" / "win" / "64" / "client" / "stable_crypto_client.dll",
        base_dir / "lib" / "stable_crypto_client.dll",
        base_dir / "stable_crypto_client.dll",
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
    
    raise FileNotFoundError(f"Client DLL not found. Searched:\n" + "\n".join(str(p) for p in possible_paths))


class ClientUtils:
    """Client utilities for hash verification"""
    
    def __init__(self, dll_path=None):
        """Initialize client utils with DLL"""
        if dll_path is None:
            try:
                dll_path = find_client_dll()
            except FileNotFoundError:
                # Fallback to server DLL if client not found
                print("Client DLL not found, using server DLL for verification")
                dll_path = find_server_dll()
        
        self.dll_path = dll_path
        self.dll = ctypes.CDLL(str(dll_path))
        print(f"Client DLL loaded: {dll_path}")
    
    def verify_hash(self, algorithm, input_data, expected_hash):
        """
        Verify a hash against expected value
        
        Args:
            algorithm: CryptoAlgorithm enum value
            input_data: bytes - input data
            expected_hash: bytes - expected hash value
        
        Returns:
            bool: True if hash matches
        """
        algo_name = CryptoAlgorithm(algorithm).name.lower()
        if algo_name == "argon2_full":
            algo_name = "argon2"
        
        # Try client-specific verify function first
        func_name = f"stable_{algo_name}_verify_client"
        
        try:
            verify_func = getattr(self.dll, func_name)
        except AttributeError:
            # Fallback: recompute hash and compare
            return self._verify_by_recompute(algorithm, input_data, expected_hash)
        
        # Setup function signature
        verify_func.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t
        ]
        verify_func.restype = ctypes.c_int
        
        # Prepare buffers
        input_buf = (ctypes.c_uint8 * len(input_data)).from_buffer_copy(input_data)
        hash_buf = (ctypes.c_uint8 * len(expected_hash)).from_buffer_copy(expected_hash)
        
        # Call function (returns 0 on success)
        result = verify_func(input_buf, len(input_data), hash_buf, len(expected_hash))
        
        return result == 0
    
    def _verify_by_recompute(self, algorithm, input_data, expected_hash):
        """Fallback: verify by recomputing hash"""
        # Use server hash function if available
        # Use unified client verify function or fallback to server hash
        try:
            verify_func = self.dll.stable_client_verify_hash
            verify_func.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t
            ]
            verify_func.restype = ctypes.c_int
            
            # Prepare buffers
            input_buf = (ctypes.c_uint8 * len(input_data)).from_buffer_copy(input_data)
            hash_buf = (ctypes.c_uint8 * len(expected_hash)).from_buffer_copy(expected_hash)
            
            # Call verify function
            result = verify_func(algorithm, input_buf, len(input_data), hash_buf, len(expected_hash))
            return result == 0
            
        except AttributeError:
            # Fallback: compute hash and compare
            hash_func = self.dll.stable_server_hash
            hash_func.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t
            ]
            hash_func.restype = ctypes.c_int
            
            # Compute hash
            input_buf = (ctypes.c_uint8 * len(input_data)).from_buffer_copy(input_data)
            output_buf = (ctypes.c_uint8 * len(expected_hash))()
            
            result = hash_func(algorithm, input_buf, len(input_data), output_buf, len(expected_hash))
            
            if result != 0:
                return False
            
            # Compare
            return bytes(output_buf) == expected_hash
    
    def get_algorithm_name(self, algorithm):
        """Get human-readable algorithm name"""
        return CryptoAlgorithm(algorithm).name


# Quick test when run directly
if __name__ == "__main__":
    from server_utils import ServerUtils
    
    print("Testing Client Utils...")
    server = ServerUtils()
    client = ClientUtils()
    
    test_data = b"Hello, World!"
    hash_result = server.hash(CryptoAlgorithm.SHA256D, test_data)
    
    is_valid = client.verify_hash(CryptoAlgorithm.SHA256D, test_data, hash_result)
    print(f"Verification: {'PASS' if is_valid else 'FAIL'}")
    print("Client utils working!")
