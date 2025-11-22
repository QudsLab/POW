from server_utils import *
import binascii

su = ServerUtils()

print("=" * 60)
print("COMPREHENSIVE ALGORITHM TEST")
print("=" * 60)

# Test with fixed input to verify determinism
test_input = b'test123'

print(f"\nTesting all 39 algorithms with input: {test_input}")
print(f"{'ID':<4} {'Algorithm':<20} {'Hash (first 24 chars)':>30} {'Status'}")
print("-" * 80)

hashes = {}
for i in range(39):
    try:
        h = su.hash(i, test_input)
        hex_hash = binascii.hexlify(h[:12]).decode()
        hashes[i] = hex_hash
        
        # Check if it's the SHA256 fallback pattern
        sha256_test = binascii.hexlify(su.hash(0, test_input)[:12]).decode()
        status = "SHA256" if hex_hash == sha256_test and i != 0 else "REAL"
        
        algo_name = CryptoAlgorithm(i).name
        print(f"{i:<4} {algo_name:<20} {hex_hash:>30} {status}")
    except Exception as e:
        print(f"{i:<4} ERROR: {e}")

# Count real vs fallback
sha256_hash = hashes.get(0, "")
real_count = sum(1 for h in hashes.values() if h != sha256_hash)
fallback_count = len(hashes) - real_count - 1  # -1 for SHA2 itself

print("\n" + "=" * 60)
print(f"RESULTS:")
print(f"  Real implementations: {real_count + 1} (including SHA2)")
print(f"  Fallback to SHA256: {fallback_count}")
print(f"  Total algorithms: {len(hashes)}")
print("=" * 60)
