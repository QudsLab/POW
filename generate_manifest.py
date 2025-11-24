#!/usr/bin/env python3
"""
Generate versions.json manifest with checksums for all binaries
"""

import json
import os
import hashlib
import sys
from pathlib import Path

def calculate_checksums(file_path):
    """Calculate SHA256 and MD5 checksums for a file"""
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            md5_hash.update(byte_block)
    
    return {
        "sha256": sha256_hash.hexdigest(),
        "md5": md5_hash.hexdigest()
    }

def scan_binaries(base_dir="bin"):
    """Scan bin directory for all binaries and organize by platform"""
    manifest = {
        "version": os.environ.get("BUILD_VERSION", "dev"),
        "repository": "qudslab/pow",
        "release_url": os.environ.get("RELEASE_URL", "https://github.com/qudslab/pow/releases/download/vdev"),
        "platforms": {}
    }
    
    platforms = ["windows", "linux", "macos", "wasm", "android"]
    
    for platform in platforms:
        platform_dir = os.path.join(base_dir, platform)
        if not os.path.isdir(platform_dir):
            continue
            
        manifest["platforms"][platform] = {"variants": {}}
        
        # Scan for 32 and 64 bit directories
        for bits in ["32", "64"]:
            bits_dir = os.path.join(platform_dir, bits)
            if not os.path.isdir(bits_dir):
                continue
                
            variant_key = f"{bits}bit"
            manifest["platforms"][platform]["variants"][variant_key] = {"binaries": []}
            
            # Scan for binary files
            for entry in os.listdir(bits_dir):
                file_path = os.path.join(bits_dir, entry)
                
                # Skip non-files and checksum files
                if not os.path.isfile(file_path):
                    continue
                if entry.endswith('.json') or entry.endswith('.txt'):
                    continue
                
                # Calculate checksums
                checksums = calculate_checksums(file_path)
                file_size = os.path.getsize(file_path)
                
                binary_info = {
                    "name": entry,
                    "type": os.path.splitext(entry)[1],
                    "size": file_size,
                    "sha256": checksums["sha256"],
                    "md5": checksums["md5"],
                    "download_url": f"{manifest['release_url']}/{platform}/{bits}/{entry}"
                }
                
                manifest["platforms"][platform]["variants"][variant_key]["binaries"].append(binary_info)
    
    return manifest

def main():
    """Main function"""
    base_dir = sys.argv[1] if len(sys.argv) > 1 else "bin"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "bin/versions.json"
    
    print(f"Scanning binaries in: {base_dir}")
    manifest = scan_binaries(base_dir)
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    
    # Write manifest
    with open(output_file, "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Manifest generated: {output_file}")
    print(f"Total platforms: {len(manifest['platforms'])}")
    
    # Print summary
    for platform, data in manifest["platforms"].items():
        total_binaries = sum(len(v["binaries"]) for v in data["variants"].values())
        print(f"  {platform}: {total_binaries} binaries")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
