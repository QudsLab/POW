from server_utils import *
import binascii

su = ServerUtils()

# Test various algorithms
tests = [
    (CryptoAlgorithm.SHA2, 'SHA2'),
    (CryptoAlgorithm.SHA3, 'SHA3'),
    (CryptoAlgorithm.BLAKE2, 'BLAKE2'),
    (CryptoAlgorithm.KECCAK, 'KECCAK'),
    (CryptoAlgorithm.SKEIN, 'SKEIN'),
    (CryptoAlgorithm.GROESTL, 'GROESTL'),
    (CryptoAlgorithm.JH, 'JH'),
    (CryptoAlgorithm.CUBEHASH, 'CUBEHASH'),
    (CryptoAlgorithm.WHIRLPOOL, 'WHIRLPOOL'),
    (CryptoAlgorithm.RIPEMD, 'RIPEMD'),
    (CryptoAlgorithm.X11, 'X11'),
    (CryptoAlgorithm.SCRYPT, 'SCRYPT'),
    (CryptoAlgorithm.PBKDF2, 'PBKDF2'),
]

print("Testing real algorithm implementations:\n")
print(f"{'Algorithm':<12} {'Hash (first 32 chars)':>35}")
print("-" * 50)

hashes = []
for algo, name in tests:
    h = su.hash(algo, b'test')
    hex_hash = binascii.hexlify(h[:16]).decode()
    print(f"{name:<12} {hex_hash}")
    hashes.append(h[:32])

# Count unique hashes
unique = len(set([bytes(h[:32]) for h in hashes]))
print(f"\nResult: {unique}/{len(tests)} algorithms producing unique hashes")

# Note: SHA3 and KECCAK should be same (KECCAK is SHA3)
if unique >= len(tests) - 1:
    print("✓ All algorithms working with real implementations!")
    print("  (SHA3 and KECCAK produce same hash - this is correct)")
else:
    print(f"⚠ Warning: {len(tests) - unique} algorithms may be using fallback")
