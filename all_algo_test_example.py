"""
Complete Algorithm Test Example
Tests all 39 algorithms using server and client utils

No external dependencies required
"""
import time
import sys
import os
from server_utils import ServerUtils, CryptoAlgorithm
from client_utils import ClientUtils

# Force UTF-8 encoding for Windows console
if os.name == 'nt':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Simple colored output replacement
def colored(text, color=None, attrs=None):
    return text
def cprint(text, color=None, attrs=None):
    print(text)


class AlgorithmTester:
    """Test all 39 cryptographic algorithms"""
    
    def __init__(self):
        print(colored("\nInitializing crypto libraries...", "cyan"))
        self.server = ServerUtils()
        self.client = ClientUtils()
        self.passed = 0
        self.failed = 0
    
    def print_header(self):
        """Print colorful header"""
        print()
        cprint("╔═══════════════════════════════════════════════════════════╗", "cyan", attrs=["bold"])
        cprint("║   🔐 TESTING ALL 39 CRYPTOGRAPHIC ALGORITHMS 🔐          ║", "cyan", attrs=["bold"])
        cprint("║        Server Compute | Client Verify                     ║", "cyan", attrs=["bold"])
        cprint("╚═══════════════════════════════════════════════════════════╝", "cyan", attrs=["bold"])
        print()
    
    def print_category(self, name):
        """Print category header"""
        print()
        cprint(f"═══ {name} ═══", "yellow", attrs=["bold"])
    
    def test_algorithm(self, algorithm, test_data):
        """
        Test single algorithm:
        1. Server computes hash
        2. Client verifies hash
        """
        algo_name = self.server.get_algorithm_name(algorithm)
        
        try:
            # Server computes
            print(colored(f"\n[{algo_name}]", "cyan", attrs=["bold"]))
            start = time.time()
            hash_result = self.server.hash(algorithm, test_data)
            server_time = (time.time() - start) * 1000
            
            print(colored("  [SERVER]", "green") + 
                  f" Hash: {colored(hash_result.hex()[:24] + '...', 'magenta')}")
            print(colored("  [SERVER]", "green") + 
                  f" Time: {server_time:.2f}ms | Size: {len(hash_result)} bytes")
            
            # Client verifies
            start = time.time()
            is_valid = self.client.verify_hash(algorithm, test_data, hash_result)
            client_time = (time.time() - start) * 1000
            
            if is_valid:
                print(colored("  [CLIENT]", "blue") + 
                      colored(" ✓ Verified!", "green", attrs=["bold"]) + 
                      f" ({client_time:.2f}ms)")
                self.passed += 1
                return True
            else:
                print(colored("  [CLIENT]", "blue") + 
                      colored(" ✗ Verification failed!", "red", attrs=["bold"]))
                self.failed += 1
                return False
                
        except Exception as e:
            print(colored(f"  [ERROR] {str(e)}", "red", attrs=["bold"]))
            self.failed += 1
            return False
    
    def run_all_tests(self):
        """Test all 39 algorithms organized by category"""
        self.print_header()
        
        test_data = b"Test data for all 39 algorithms!"
        
        # Define categories
        categories = {
            "Basic Hash Functions": [
                CryptoAlgorithm.SHA2,
                CryptoAlgorithm.SHA3,
                CryptoAlgorithm.SHA256D,
                CryptoAlgorithm.BLAKE2,
                CryptoAlgorithm.BLAKE3,
                CryptoAlgorithm.KECCAK,
                CryptoAlgorithm.SKEIN,
                CryptoAlgorithm.GROESTL,
                CryptoAlgorithm.JH,
                CryptoAlgorithm.CUBEHASH,
                CryptoAlgorithm.WHIRLPOOL,
                CryptoAlgorithm.RIPEMD,
            ],
            "X-Series (Multi-Hash)": [
                CryptoAlgorithm.X11,
                CryptoAlgorithm.X13,
                CryptoAlgorithm.X16R,
            ],
            "Memory-Hard / KDF": [
                CryptoAlgorithm.SCRYPT,
                CryptoAlgorithm.ARGON2_FULL,
                CryptoAlgorithm.BCRYPT,
                CryptoAlgorithm.PBKDF2,
                CryptoAlgorithm.LYRA2REV2,
                CryptoAlgorithm.LYRA2Z,
            ],
            "C++ Mining Algorithms": [
                CryptoAlgorithm.RANDOMX,
                CryptoAlgorithm.PROGPOW,
                CryptoAlgorithm.ETHASH,
                CryptoAlgorithm.EQUIHASH,
            ],
            "Key Derivation Functions": [
                CryptoAlgorithm.HKDF,
                CryptoAlgorithm.CONCATKDF,
                CryptoAlgorithm.X963KDF,
            ],
            "Message Authentication Codes": [
                CryptoAlgorithm.HMAC,
                CryptoAlgorithm.BLAKE2MAC,
                CryptoAlgorithm.POLY1305,
                CryptoAlgorithm.KMAC,
                CryptoAlgorithm.GMAC,
                CryptoAlgorithm.SIPHASH,
            ],
            "AEAD (Authenticated Encryption)": [
                CryptoAlgorithm.CHACHA20POLY1305,
                CryptoAlgorithm.AESGCM,
                CryptoAlgorithm.AESCCM,
                CryptoAlgorithm.AESOCB,
                CryptoAlgorithm.AESEAX,
            ],
        }
        
        start_time = time.time()
        
        # Test each category
        for category_name, algorithms in categories.items():
            self.print_category(category_name)
            for algorithm in algorithms:
                self.test_algorithm(algorithm, test_data)
        
        total_time = time.time() - start_time
        
        # Print summary
        self.print_summary(total_time)
    
    def print_summary(self, total_time):
        """Print final summary"""
        print()
        cprint("═" * 65, "cyan", attrs=["bold"])
        cprint("FINAL SUMMARY", "cyan", attrs=["bold"])
        cprint("═" * 65, "cyan", attrs=["bold"])
        print()
        
        total = self.passed + self.failed
        success_rate = (self.passed / total * 100) if total > 0 else 0
        
        print(f"Total Algorithms: {total}")
        print(colored(f"✓ Passed: {self.passed}", "green", attrs=["bold"]))
        
        if self.failed > 0:
            print(colored(f"✗ Failed: {self.failed}", "red", attrs=["bold"]))
        else:
            print(colored(f"✗ Failed: {self.failed}", "green"))
        
        print(f"Success Rate: {colored(f'{success_rate:.1f}%', 'yellow', attrs=['bold'])}")
        print(f"Total Time: {total_time:.2f}s")
        print()
        
        if self.failed == 0:
            cprint("🎉 ALL 39 ALGORITHMS WORKING PERFECTLY! 🎉", "green", attrs=["bold"])
        else:
            cprint(f"⚠ {self.failed} algorithms need attention", "yellow", attrs=["bold"])
        print()


def run_proof_of_work_demo():
    """Bonus: Simple proof-of-work challenge demo"""
    print()
    cprint("═" * 65, "cyan", attrs=["bold"])
    cprint("BONUS: PROOF-OF-WORK CHALLENGE DEMO", "cyan", attrs=["bold"])
    cprint("═" * 65, "cyan", attrs=["bold"])
    print()
    
    server = ServerUtils()
    challenge = b"POW_Challenge_"
    target = "00"  # Find hash starting with "00"
    
    print(colored("[SERVER]", "green", attrs=["bold"]) + 
          f" Challenge: Find nonce where SHA256D hash starts with '{colored(target, 'yellow')}'")
    print()
    print(colored("[CLIENT]", "blue", attrs=["bold"]) + " Working...")
    
    start = time.time()
    for nonce in range(10000):
        data = challenge + str(nonce).encode()
        hash_result = server.hash(CryptoAlgorithm.SHA256D, data)
        
        if hash_result.hex().startswith(target):
            elapsed = time.time() - start
            print(colored("[CLIENT]", "blue") + 
                  f" ✓ Solution: nonce={colored(str(nonce), 'yellow')}")
            print(colored("[CLIENT]", "blue") + 
                  f" Hash: {colored(hash_result.hex(), 'magenta')}")
            print(colored("[CLIENT]", "blue") + 
                  f" Time: {elapsed:.4f}s ({nonce + 1} iterations)")
            print()
            print(colored("[SERVER]", "green", attrs=["bold"]) + 
                  colored(" ✓ Solution verified! Challenge passed!", "green", attrs=["bold"]))
            break
    
    print()


def main():
    """Main entry point"""
    try:
        # Run comprehensive test
        tester = AlgorithmTester()
        tester.run_all_tests()
        
        # Run bonus demo
        run_proof_of_work_demo()
        
        return 0
        
    except FileNotFoundError as e:
        cprint(f"\n✗ Error: {e}", "red", attrs=["bold"])
        cprint("\nPlease build DLLs first:", "yellow")
        cprint("  .\\build_windows_64.ps1", "white")
        return 1
        
    except Exception as e:
        cprint(f"\n✗ Unexpected error: {e}", "red", attrs=["bold"])
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
