#!/usr/bin/env python3
"""
Universal Builder for POW - Cross-Platform Binary Builder
Builds binaries for Windows, Linux, macOS, Android, and WASM
"""

import os
import sys
import subprocess
import platform
import shutil
import argparse
from pathlib import Path


class POWBuilder:
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.bin_dir = self.root_dir / "bin"
        self.obj_dir = self.root_dir / "obj"
        self.host_os = platform.system().lower()
        
    def clean_obj(self):
        """Clean object files only"""
        if self.obj_dir.exists():
            shutil.rmtree(self.obj_dir)
            print(f"✓ Cleaned {self.obj_dir}")
    
    def clean_all(self):
        """Clean all build artifacts"""
        if self.obj_dir.exists():
            shutil.rmtree(self.obj_dir)
        if self.bin_dir.exists():
            shutil.rmtree(self.bin_dir)
        print("✓ Cleaned all build artifacts")
    
    def run_make(self, env=None, capture_output=False):
        """Run make with optional environment variables"""
        try:
            result = subprocess.run(
                ["make", "all"],
                cwd=self.root_dir,
                env={**os.environ, **(env or {})},
                capture_output=capture_output,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            print(f"✗ Make failed: {e}")
            return False
    
    def copy_binaries(self, pattern, dest_dir):
        """Copy binaries matching pattern to destination"""
        dest_path = self.bin_dir / dest_dir
        dest_path.mkdir(parents=True, exist_ok=True)
        
        bin_root = self.bin_dir
        copied = 0
        
        for file in bin_root.glob(pattern):
            if file.is_file() and file.parent == bin_root:
                shutil.copy2(file, dest_path)
                print(f"  → {file.name} → {dest_dir}/")
                copied += 1
        
        return copied
    
    def build_windows_32(self):
        """Build Windows 32-bit binaries"""
        print("\n=== Building Windows 32-bit ===")
        self.clean_obj()
        
        env = {
            "CFLAGS": "-w -O2 -std=c99 -fPIC -m32",
            "CXXFLAGS": "-w -O2 -std=c++11 -fPIC -m32"
        }
        
        if self.run_make(env):
            copied = self.copy_binaries("*.dll", "windows/32")
            print(f"✓ Windows 32-bit: {copied} binaries")
            return True
        else:
            print("⚠ Windows 32-bit build failed (may not be supported)")
            return False
    
    def build_windows_64(self):
        """Build Windows 64-bit binaries"""
        print("\n=== Building Windows 64-bit ===")
        self.clean_obj()
        
        if self.run_make():
            copied = self.copy_binaries("*.dll", "windows/64")
            print(f"✓ Windows 64-bit: {copied} binaries")
            return True
        else:
            print("✗ Windows 64-bit build failed")
            return False
    
    def build_linux_32(self):
        """Build Linux 32-bit binaries"""
        print("\n=== Building Linux 32-bit ===")
        self.clean_obj()
        
        env = {
            "CFLAGS": "-w -O2 -std=c99 -fPIC -m32",
            "CXXFLAGS": "-w -O2 -std=c++11 -fPIC -m32"
        }
        
        if self.run_make(env):
            copied = self.copy_binaries("*.so", "linux/32")
            print(f"✓ Linux 32-bit: {copied} binaries")
            return True
        else:
            print("⚠ Linux 32-bit build failed (may need gcc-multilib)")
            return False
    
    def build_linux_64(self):
        """Build Linux 64-bit binaries"""
        print("\n=== Building Linux 64-bit ===")
        self.clean_obj()
        
        if self.run_make():
            copied = self.copy_binaries("*.so", "linux/64")
            print(f"✓ Linux 64-bit: {copied} binaries")
            return True
        else:
            print("✗ Linux 64-bit build failed")
            return False
    
    def build_macos_64(self):
        """Build macOS 64-bit binaries (only 64-bit supported)"""
        print("\n=== Building macOS 64-bit ===")
        self.clean_obj()
        
        if self.run_make():
            copied = self.copy_binaries("*.dylib", "macos/64")
            print(f"✓ macOS 64-bit: {copied} binaries")
            return True
        else:
            print("✗ macOS 64-bit build failed")
            return False
    
    def build_android_32(self):
        """Build Android 32-bit binaries"""
        print("\n=== Building Android 32-bit ===")
        self.clean_obj()
        
        env = {
            "CFLAGS": "-w -O2 -std=c99 -fPIC -m32",
            "CXXFLAGS": "-w -O2 -std=c++11 -fPIC -m32"
        }
        
        if self.run_make(env):
            copied = self.copy_binaries("*.so", "android/32")
            print(f"✓ Android 32-bit: {copied} binaries")
            return True
        else:
            print("⚠ Android 32-bit build failed")
            return False
    
    def build_android_64(self):
        """Build Android 64-bit binaries"""
        print("\n=== Building Android 64-bit ===")
        self.clean_obj()
        
        if self.run_make():
            copied = self.copy_binaries("*.so", "android/64")
            print(f"✓ Android 64-bit: {copied} binaries")
            return True
        else:
            print("✗ Android 64-bit build failed")
            return False
    
    def build_wasm_32(self):
        """Build WebAssembly 32-bit binaries"""
        print("\n=== Building WASM 32-bit ===")
        
        # Check if emscripten is available
        if not shutil.which("emcc"):
            print("⚠ Emscripten not found, skipping WASM build")
            return False
        
        self.clean_obj()
        if self.bin_dir.exists():
            shutil.rmtree(self.bin_dir)
        
        env = {
            "CC": "emcc",
            "CXX": "em++",
            "CFLAGS": "-w -O2 -std=c99 -fPIC -s USE_PTHREADS=1 -s PTHREAD_POOL_SIZE=4 -s SIDE_MODULE=1 -s EXPORT_ALL=1 -s WASM=1",
            "CXXFLAGS": "-w -O2 -std=c++11 -fPIC -s USE_PTHREADS=1 -s PTHREAD_POOL_SIZE=4 -s SIDE_MODULE=1 -s EXPORT_ALL=1 -s WASM=1",
            "LDFLAGS": "-s USE_PTHREADS=1 -s PTHREAD_POOL_SIZE=4 -s SIDE_MODULE=1 -s EXPORT_ALL=1 -s WASM=1"
        }
        
        if self.run_make(env, capture_output=True):
            copied_wasm = self.copy_binaries("*.wasm", "wasm/32")
            copied_js = self.copy_binaries("*.js", "wasm/32")
            if copied_wasm > 0:
                print(f"✓ WASM 32-bit: {copied_wasm} wasm, {copied_js} js files")
            else:
                print("⚠ WASM 32-bit: Build succeeded but no files (pthread not supported)")
        else:
            print("⚠ WASM 32-bit: Build failed (pthread not fully supported)")
        
        # Create placeholder directory
        (self.bin_dir / "wasm/32").mkdir(parents=True, exist_ok=True)
        # Don't fail - WASM is experimental
        return True
    
    def build_wasm_64(self):
        """Build WebAssembly 64-bit binaries"""
        print("\n=== Building WASM 64-bit ===")
        
        # Check if emscripten is available
        if not shutil.which("emcc"):
            print("⚠ Emscripten not found, skipping WASM build")
            return False
        
        self.clean_obj()
        if self.bin_dir.exists():
            shutil.rmtree(self.bin_dir)
        
        env = {
            "CC": "emcc",
            "CXX": "em++",
            "CFLAGS": "-w -O2 -std=c99 -fPIC -s USE_PTHREADS=1 -s PTHREAD_POOL_SIZE=4 -s SIDE_MODULE=1 -s EXPORT_ALL=1 -s WASM=1 -s MEMORY64=1",
            "CXXFLAGS": "-w -O2 -std=c++11 -fPIC -s USE_PTHREADS=1 -s PTHREAD_POOL_SIZE=4 -s SIDE_MODULE=1 -s EXPORT_ALL=1 -s WASM=1 -s MEMORY64=1",
            "LDFLAGS": "-s USE_PTHREADS=1 -s PTHREAD_POOL_SIZE=4 -s SIDE_MODULE=1 -s EXPORT_ALL=1 -s WASM=1 -s MEMORY64=1"
        }
        
        if self.run_make(env, capture_output=True):
            copied_wasm = self.copy_binaries("*.wasm", "wasm/64")
            copied_js = self.copy_binaries("*.js", "wasm/64")
            if copied_wasm > 0:
                print(f"✓ WASM 64-bit: {copied_wasm} wasm, {copied_js} js files")
            else:
                print("⚠ WASM 64-bit: Build succeeded but no files (pthread not supported)")
        else:
            print("⚠ WASM 64-bit: Build failed (pthread not fully supported)")
        
        # Create placeholder directory
        (self.bin_dir / "wasm/64").mkdir(parents=True, exist_ok=True)
        # Don't fail - WASM is experimental
        return True
    
    def build_all(self):
        """Build all supported platforms"""
        print("=" * 60)
        print("POW Universal Builder")
        print(f"Host OS: {self.host_os}")
        print("=" * 60)
        
        results = {}
        
        if self.host_os == "windows":
            results["Windows 32-bit"] = self.build_windows_32()
            results["Windows 64-bit"] = self.build_windows_64()
        elif self.host_os == "linux":
            results["Linux 32-bit"] = self.build_linux_32()
            results["Linux 64-bit"] = self.build_linux_64()
            results["Android 32-bit"] = self.build_android_32()
            results["Android 64-bit"] = self.build_android_64()
            results["WASM 32-bit"] = self.build_wasm_32()
            results["WASM 64-bit"] = self.build_wasm_64()
        elif self.host_os == "darwin":
            results["macOS 64-bit"] = self.build_macos_64()
        
        # Summary
        print("\n" + "=" * 60)
        print("Build Summary:")
        print("=" * 60)
        for platform, success in results.items():
            status = "✓" if success else "✗"
            print(f"{status} {platform}")
        
        # List all binaries
        print("\n" + "=" * 60)
        print("Generated Binaries:")
        print("=" * 60)
        total = 0
        for file in sorted(self.bin_dir.rglob("*")):
            if file.is_file() and file.suffix in [".dll", ".so", ".dylib", ".wasm", ".js"]:
                rel_path = file.relative_to(self.bin_dir)
                size = file.stat().st_size
                print(f"  {rel_path} ({size:,} bytes)")
                total += 1
        
        print(f"\nTotal: {total} files")
        return sum(results.values()) > 0


def main():
    parser = argparse.ArgumentParser(description="POW Universal Builder")
    parser.add_argument("target", nargs="?", default="all",
                       choices=["all", "windows-32", "windows-64", 
                               "linux-32", "linux-64", "macos-64",
                               "android-32", "android-64",
                               "wasm-32", "wasm-64", "clean"],
                       help="Build target (default: all)")
    
    args = parser.parse_args()
    builder = POWBuilder()
    
    if args.target == "clean":
        builder.clean_all()
        return 0
    
    # Build specific target
    target_map = {
        "all": builder.build_all,
        "windows-32": builder.build_windows_32,
        "windows-64": builder.build_windows_64,
        "linux-32": builder.build_linux_32,
        "linux-64": builder.build_linux_64,
        "macos-64": builder.build_macos_64,
        "android-32": builder.build_android_32,
        "android-64": builder.build_android_64,
        "wasm-32": builder.build_wasm_32,
        "wasm-64": builder.build_wasm_64,
    }
    
    success = target_map[args.target]()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
