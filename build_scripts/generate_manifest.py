#!/usr/bin/env python3
"""Generate versions.json manifest with download links and checksums"""

import os
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime

def calculate_checksums(filepath):
    """Calculate SHA256 and MD5 checksums for a file"""
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            md5_hash.update(byte_block)
    
    return {
        "sha256": sha256_hash.hexdigest(),
        "md5": md5_hash.hexdigest()
    }

def get_file_info(filepath, base_url):
    """Get complete file information"""
    stat = os.stat(filepath)
    checksums = calculate_checksums(filepath)
    
    # Generate download URL
    rel_path = str(filepath).replace("\\", "/")
    filename = os.path.basename(filepath)
    download_url = f"{base_url}/{filename}"
    
    return {
        "filename": filename,
        "size": stat.st_size,
        "size_human": format_size(stat.st_size),
        "sha256": checksums["sha256"],
        "md5": checksums["md5"],
        "url": download_url,
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
    }

def format_size(bytes):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} TB"

def scan_directory(base_dir, base_url):
    """Recursively scan directory for binaries"""
    base_path = Path(base_dir)
    manifest = {
        "version": os.environ.get("BUILD_VERSION", "1"),
        "generated": datetime.utcnow().isoformat() + "Z",
        "repository": os.environ.get("GITHUB_REPOSITORY", "unknown/unknown"),
        "commit": os.environ.get("GITHUB_SHA", "unknown"),
        "platforms": {}
    }
    
    # Define platform structure
    platforms = {
        "windows": {
            "x64": {"server": [], "client": []},
            "x86": {"server": [], "client": []}
        },
        "linux": {
            "x64": {"server": [], "client": []},
            "arm64": {"server": [], "client": []},
            "armv7": {"server": [], "client": []}
        },
        "macos": {
            "x64": {"server": [], "client": []},
            "arm64": {"server": [], "client": []}
        },
        "android": {
            "arm64-v8a": [],
            "armeabi-v7a": [],
            "x86_64": [],
            "x86": []
        },
        "wasm": {
            "modules": []
        }
    }
    
    # Scan all files
    for root, dirs, files in os.walk(base_path):
        for file in files:
            filepath = Path(root) / file
            rel_path = filepath.relative_to(base_path)
            parts = rel_path.parts
            
            # Skip non-binary files
            if not any(file.endswith(ext) for ext in ['.dll', '.so', '.dylib', '.wasm', '.js']):
                continue
            
            try:
                file_info = get_file_info(filepath, base_url)
                
                # Categorize by platform
                if "win" in parts:
                    arch = "x64" if "64" in parts else "x86"
                    category = "server" if "server" in parts else "client"
                    platforms["windows"][arch][category].append(file_info)
                
                elif "linux" in parts:
                    if "arm64" in parts:
                        arch = "arm64"
                    elif "armv7" in parts or "arm" in parts:
                        arch = "armv7"
                    else:
                        arch = "x64"
                    category = "server" if "server" in parts else "client"
                    platforms["linux"][arch][category].append(file_info)
                
                elif "macos" in parts:
                    arch = "arm64" if "arm64" in parts else "x64"
                    category = "server" if "server" in parts else "client"
                    platforms["macos"][arch][category].append(file_info)
                
                elif "android" in parts:
                    for abi in ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]:
                        if abi in parts:
                            platforms["android"][abi].append(file_info)
                            break
                
                elif "wasm" in parts:
                    platforms["wasm"]["modules"].append(file_info)
            
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
    
    manifest["platforms"] = platforms
    
    # Add algorithm info
    manifest["algorithms"] = {
        "real_implementations": [
            "SHA2", "SHA3", "SHA256D", "BLAKE2", "KECCAK", "SKEIN",
            "GROESTL", "JH", "CUBEHASH", "WHIRLPOOL", "RIPEMD", 
            "X11", "SCRYPT", "PBKDF2"
        ],
        "fallback_to_sha256": [
            "BLAKE2MAC", "BLAKE3", "X13", "X16R", "ARGON2_FULL", "BCRYPT",
            "LYRA2REV2", "LYRA2Z", "EQUIHASH", "RANDOMX", "PROGPOW", "ETHASH",
            "HKDF", "CONCATKDF", "X963KDF", "HMAC", "POLY1305", "KMAC", "GMAC",
            "SIPHASH", "CHACHA20POLY1305", "AESGCM", "AESCCM", "AESOCB", "AESEAX"
        ],
        "total": 39,
        "real_count": 14,
        "fallback_count": 25
    }
    
    return manifest

def main():
    parser = argparse.ArgumentParser(description='Generate versions.json manifest')
    parser.add_argument('--release-url', required=True, help='Base URL for downloads')
    parser.add_argument('--version', required=True, help='Build version')
    parser.add_argument('--input-dir', required=True, help='Directory to scan')
    parser.add_argument('--output', required=True, help='Output JSON file')
    
    args = parser.parse_args()
    
    os.environ["BUILD_VERSION"] = args.version
    
    print(f"Scanning {args.input_dir}...")
    manifest = scan_directory(args.input_dir, args.release_url)
    
    # Write manifest
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Manifest written to {args.output}")
    print(f"Total files: {sum(len(files) for platform in manifest['platforms'].values() for files in (platform.values() if isinstance(platform, dict) else [platform]))}")

if __name__ == "__main__":
    main()
