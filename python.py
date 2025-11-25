#!/usr/bin/env python3
"""
POW Library - Python Integration Test
Tests server-side challenge generation and client-side solving
using the compiled Windows 64-bit binaries
"""

import ctypes
import os
import sys
from pathlib import Path

# Configuration
BIN_DIR = Path("bin/windows/64")
SERVER_DLL = BIN_DIR / "server.dll"
CLIENT_DLL = BIN_DIR / "client.dll"

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text:^60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

def print_success(text):
    print(f"{Colors.OKGREEN}[OK] {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}[ERROR] {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.OKCYAN}>> {text}{Colors.ENDC}")

def print_warning(text):
    print(f"{Colors.WARNING}[WARN] {text}{Colors.ENDC}")

# Define C structures matching the library
class PowChallenge(ctypes.Structure):
    _fields_ = [
        ("pow_type", ctypes.c_char * 32),
        ("challenge_data", ctypes.POINTER(ctypes.c_uint8)),
        ("challenge_len", ctypes.c_size_t),
        ("difficulty", ctypes.c_uint32)
    ]

class PowSolution(ctypes.Structure):
    _fields_ = [
        ("pow_type", ctypes.c_char * 32),
        ("solution_data", ctypes.POINTER(ctypes.c_uint8)),
        ("solution_len", ctypes.c_size_t)
    ]

class POWTester:
    def __init__(self):
        self.server_lib = None
        self.client_lib = None
        self.libc = None
        
    def load_libraries(self):
        """Load server and client DLLs"""
        print_header("Loading POW Libraries")
        
        # Check if binaries exist
        if not SERVER_DLL.exists():
            print_error(f"Server DLL not found: {SERVER_DLL}")
            return False
        
        if not CLIENT_DLL.exists():
            print_error(f"Client DLL not found: {CLIENT_DLL}")
            return False
        
        try:
            # Load server library
            self.server_lib = ctypes.CDLL(str(SERVER_DLL))
            print_success(f"Loaded server library: {SERVER_DLL}")
            
            # Load client library
            self.client_lib = ctypes.CDLL(str(CLIENT_DLL))
            print_success(f"Loaded client library: {CLIENT_DLL}")
            
            # Load C runtime for malloc/free
            self.libc = ctypes.cdll.msvcrt
            
            # Configure function signatures
            self._configure_functions()
            return True
            
        except Exception as e:
            print_error(f"Failed to load libraries: {e}")
            return False
    
    def _configure_functions(self):
        """Configure C function signatures"""
        
        # Server functions
        self.server_lib.server_list_pow_types.argtypes = [
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_size_t
        ]
        self.server_lib.server_list_pow_types.restype = ctypes.c_size_t
        
        self.server_lib.server_generate_challenge.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(PowChallenge)
        ]
        self.server_lib.server_generate_challenge.restype = ctypes.c_int
        
        self.server_lib.server_verify_solution.argtypes = [
            ctypes.POINTER(PowChallenge),
            ctypes.POINTER(PowSolution)
        ]
        self.server_lib.server_verify_solution.restype = ctypes.c_int
        
        # Client functions
        self.client_lib.client_handle_challenge.argtypes = [ctypes.c_char_p]
        self.client_lib.client_handle_challenge.restype = ctypes.c_int
        
        self.client_lib.client_request_challenge.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(PowChallenge)
        ]
        self.client_lib.client_request_challenge.restype = ctypes.c_int
        
        # Configure client_solve_challenge for real testing
        self.client_lib.client_solve_challenge.argtypes = [
            ctypes.POINTER(PowChallenge),
            ctypes.POINTER(PowSolution)
        ]
        self.client_lib.client_solve_challenge.restype = ctypes.c_int
        
        # C runtime
        self.libc.malloc.argtypes = [ctypes.c_size_t]
        self.libc.malloc.restype = ctypes.c_void_p
        
        self.libc.free.argtypes = [ctypes.c_void_p]
        self.libc.free.restype = None
    
    def list_pow_types(self):
        """List all available PoW types"""
        print_header("Available PoW Types")
        
        MAX_POW_TYPES = 16
        pow_types = (ctypes.c_char_p * MAX_POW_TYPES)()
        
        count = self.server_lib.server_list_pow_types(pow_types, MAX_POW_TYPES)
        
        print_info(f"Found {count} PoW algorithm(s):")
        types_list = []
        for i in range(count):
            if pow_types[i]:
                pow_type = pow_types[i].decode('utf-8')
                types_list.append(pow_type)
                print(f"  [{i+1}] {pow_type}")
        
        return types_list
    
    def test_pow_workflow(self, pow_type):
        """Test complete PoW workflow: generate -> solve -> verify"""
        print_header(f"Testing PoW: {pow_type}")
        
        print_info("Using client_handle_challenge for integrated workflow...")
        print_warning("Note: Solve/Verify functions are stubs - they return placeholder results")
        
        # Use the integrated client_handle_challenge function
        # This function does: request -> solve -> verify internally
        result = self.client_lib.client_handle_challenge(pow_type.encode('utf-8'))
        
        if result == 0:
            print_success("PoW workflow completed successfully!")
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}{'─'*60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{Colors.BOLD}SUCCESS: Challenge generated, solved, and verified!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{Colors.BOLD}{'─'*60}{Colors.ENDC}\n")
            return True
        elif result == -1:
            print_error("Failed to get challenge from server")
            return False
        elif result == -2:
            print_error("Failed to solve challenge")
            return False
        elif result == -3:
            print_error("Solution verification failed")
            return False
        else:
            print_error(f"Unknown error (code: {result})")
            return False
    
    def test_pow_workflow_detailed(self, pow_type):
        """Test complete PoW workflow with detailed steps: generate -> solve -> verify"""
        print_header(f"Testing PoW (Detailed): {pow_type}")
        
        # Step 1: Generate challenge
        print_info("Step 1: Generating challenge...")
        challenge = PowChallenge()
        
        result = self.server_lib.server_generate_challenge(
            pow_type.encode('utf-8'),
            ctypes.byref(challenge)
        )
        
        if result != 0:
            print_error(f"Failed to generate challenge (error code: {result})")
            return False
        
        print_success("Challenge generated")
        print(f"  Type: {challenge.pow_type.decode('utf-8')}")
        print(f"  Difficulty: {challenge.difficulty}")
        print(f"  Challenge length: {challenge.challenge_len} bytes")
        
        # Display challenge data (first 16 bytes)
        if challenge.challenge_data and challenge.challenge_len > 0:
            challenge_bytes = bytes([challenge.challenge_data[i] for i in range(min(16, challenge.challenge_len))])
            print(f"  Challenge data (first 16 bytes): {challenge_bytes.hex()}")
        
        # Step 2: Solve the challenge (REAL SOLVE)
        print_info("\nStep 2: Solving challenge...")
        print_info("Calling real solve function to find valid nonce...")
        
        solution = PowSolution()
        
        # Don't pre-allocate - let the C function allocate the solution buffer
        solution.solution_data = None
        solution.solution_len = 0
        solution.pow_type = challenge.pow_type
        
        # Call the REAL solve function
        solve_result = self.client_lib.client_solve_challenge(
            ctypes.byref(challenge),
            ctypes.byref(solution)
        )
        
        if solve_result == 0:
            print_success("Solution found!")
            print(f"  Solution length: {solution.solution_len} bytes")
            
            # Display solution data (first 16 bytes)
            if solution.solution_data and solution.solution_len > 0:
                solution_bytes = bytes([solution.solution_data[i] for i in range(min(16, solution.solution_len))])
                print(f"  Solution data (first 16 bytes): {solution_bytes.hex()}")
        else:
            print_warning(f"Solve function returned {solve_result}")
            print_info("Algorithm may not have real solve implementation...")
        
        # Step 3: Verify solution (server-side)
        print_info("\nStep 3: Verifying solution (server-side)...")
        
        verified = self.server_lib.server_verify_solution(
            ctypes.byref(challenge),
            ctypes.byref(solution)
        )
        
        # Proper verification check: 1 = success, 0 = failure, -1 = error
        if verified == 1:
            print_success("Solution VERIFIED [OK]")
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}{'─'*60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{Colors.BOLD}SUCCESS: Complete PoW workflow (Generate->Solve->Verify)!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{Colors.BOLD}{'─'*60}{Colors.ENDC}\n")
            success = True
        elif verified == 0:
            print_error("Verification FAILED (returned 0)")
            print(f"{Colors.FAIL}The solution does not meet difficulty requirements{Colors.ENDC}")
            success = False
        elif verified == -1:
            print_error("Verification ERROR (returned -1)")
            success = False
        else:
            print_warning(f"Unexpected verification result: {verified}")
            success = False
        
        # Cleanup
        self.libc.free(challenge.challenge_data)
        # Free solution buffer if it was allocated by C code
        if solution.solution_data:
            self.libc.free(solution.solution_data)
        
        return success
    
    def run_full_test(self):
        """Run complete test suite"""
        print_header("POW Library - Python Integration Test")
        print_info("Testing Windows 64-bit binaries\n")
        
        # Load libraries
        if not self.load_libraries():
            return False
        
        # List available PoW types
        pow_types = self.list_pow_types()
        
        if not pow_types:
            print_error("No PoW types available")
            return False
        
        # Test ALL PoW types
        print_info(f"\nTesting all {len(pow_types)} PoW algorithms...")
        print_info("This tests: generate challenge -> solve -> verify\n")
        
        results = {}
        
        # Test each algorithm using detailed workflow (safe for stub C code)
        print_info("Testing with detailed step-by-step workflow for all algorithms:")
        print_info("="*60 + "\n")

        for i, pow_type in enumerate(pow_types, 1):
            print(f"\n{Colors.BOLD}[{i}/{len(pow_types)}]{Colors.ENDC}", end=" ")
            try:
                success = self.test_pow_workflow_detailed(pow_type)
                results[pow_type] = success
            except Exception as e:
                print_error(f"Exception during {pow_type} test: {e}")
                import traceback
                traceback.print_exc()
                results[pow_type] = False
        
        # Summary
        print_header("Test Summary")
        total = len(results)
        passed = sum(1 for v in results.values() if v)
        failed = total - passed
        
        print(f"{Colors.BOLD}Results by Algorithm:{Colors.ENDC}\n")
        for pow_type, success in sorted(results.items()):
            status = "PASS" if success else "FAIL"
            color = Colors.OKGREEN if success else Colors.FAIL
            symbol = "[OK]" if success else "[FAIL]"
            impl_status = "(Real verify)" if success else "(Not implemented)"
            print(f"  {color}{symbol} {status:6}{Colors.ENDC} - {pow_type:15} {impl_status}")
        
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}Total: {total} | Passed: {Colors.OKGREEN}{passed}{Colors.ENDC}{Colors.BOLD} | Failed: {Colors.FAIL}{failed}{Colors.ENDC}{Colors.BOLD}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'─'*60}{Colors.ENDC}")
        
        if passed == total:
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}🎉 ALL TESTS PASSED! 🎉{Colors.ENDC}")
            print(f"{Colors.OKGREEN}All algorithms have working verify functions!{Colors.ENDC}")
        elif passed > 0:
            print(f"\n{Colors.WARNING}[WARN] {passed}/{total} algorithms verified successfully{Colors.ENDC}")
            print(f"{Colors.WARNING}Failed algorithms need real implementation{Colors.ENDC}")
        else:
            print(f"\n{Colors.FAIL}[ERROR] No algorithms passed verification{Colors.ENDC}")
            print(f"{Colors.FAIL}All verify functions need implementation{Colors.ENDC}")
        
        print_info("\nTest Results:")
        print_info("- PASS = Verify function returns 1 (real implementation)")
        print_info("- FAIL = Verify function returns 0 (stub/not implemented)")
        
        return failed == 0

def main():
    """Main entry point"""
    print(f"{Colors.BOLD}POW Library Test{Colors.ENDC}")
    print(f"Python {sys.version}")
    print(f"Working directory: {os.getcwd()}\n")
    
    tester = POWTester()
    success = tester.run_full_test()
    
    print_header("Test Complete")
    if success:
        print_success("All tests passed!")
    else:
        print_error("Some tests failed")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()