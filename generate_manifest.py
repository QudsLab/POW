#!/usr/bin/env python3
"""
Generate versions.json manifest with GitHub raw download URLs
"""

import os
import json
import hashlib
import sys
from pathlib import Path
from datetime import datetime

def get_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Warning: Could not hash {filepath}: {e}")
        return None

def get_file_size(filepath):
    """Get file size in bytes"""
    try:
        return os.path.getsize(filepath)
    except Exception as e:
        print(f"Warning: Could not get size of {filepath}: {e}")
        return 0

def scan_binaries(bin_dir, github_repo, github_branch="main"):
    """
    Scan bin directory and generate manifest with GitHub raw URLs
    
    Args:
        bin_dir: Path to bin directory
        github_repo: GitHub repository in format 'owner/repo'
        github_branch: Branch name (default: main)
    
    Returns:
        Dictionary with binary information
    """
    bin_path = Path(bin_dir)
    
    if not bin_path.exists():
        print(f"Error: {bin_dir} does not exist")
        return None
    
    manifest = {
        "version": os.environ.get("BUILD_VERSION", "1"),
        "build_number": os.environ.get("GITHUB_RUN_NUMBER", "1"),
        "commit_sha": os.environ.get("GITHUB_SHA", "unknown")[:7],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repository": github_repo,
        "branch": github_branch,
        "platforms": {}
    }
    
    # Base URL for GitHub raw files
    base_url = f"https://github.com/{github_repo}/raw/refs/heads/{github_branch}"
    
    # Expected platforms and architectures
    platforms_config = {
        "windows": {
            "32": [".dll"],
            "64": [".dll"]
        },
        "linux": {
            "32": [".so"],
            "64": [".so"]
        },
        "macos": {
            "64": [".dylib"]
        },
        "android": {
            "32": [".so"],
            "64": [".so"]
        }
    }
    
    # Scan each platform
    for platform, archs in platforms_config.items():
        platform_path = bin_path / platform
        
        if not platform_path.exists():
            print(f"Warning: {platform} directory not found")
            continue
        
        manifest["platforms"][platform] = {}
        
        for arch in archs.keys():
            arch_path = platform_path / arch
            
            if not arch_path.exists():
                print(f"Warning: {platform}/{arch} directory not found")
                continue
            
            manifest["platforms"][platform][arch] = {}
            
            # Scan for binary files
            for file_path in arch_path.iterdir():
                if file_path.is_file():
                    ext = file_path.suffix.lower()
                    
                    # Check if it's a binary file we care about
                    if ext in platforms_config[platform][arch]:
                        binary_name = file_path.stem  # filename without extension
                        
                        # Generate GitHub raw URL
                        # Format: https://github.com/owner/repo/raw/refs/heads/main/bin/platform/arch/file
                        relative_path = f"bin/{platform}/{arch}/{file_path.name}"
                        download_url = f"{base_url}/{relative_path}"
                        
                        file_info = {
                            "url": download_url,
                            "filename": file_path.name,
                            "size": get_file_size(file_path),
                            "sha256": get_file_hash(file_path),
                            "path": relative_path
                        }
                        
                        manifest["platforms"][platform][arch][binary_name] = file_info
                        
                        print(f"✓ {platform}/{arch}/{file_path.name}")
    
    # Count total binaries
    total_binaries = 0
    for platform in manifest["platforms"].values():
        for arch in platform.values():
            total_binaries += len(arch)
    
    manifest["total_binaries"] = total_binaries
    
    return manifest

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 generate_manifest.py <bin_dir> <output_json> [github_repo] [branch]")
        print("Example: python3 generate_manifest.py bin bin/versions.json QudsLab/POW main")
        sys.exit(1)
    
    bin_dir = sys.argv[1]
    output_json = sys.argv[2]
    
    # Get GitHub repo from args or environment
    if len(sys.argv) >= 4:
        github_repo = sys.argv[3]
    else:
        # Try to extract from GITHUB_REPOSITORY env var
        github_repo = os.environ.get("GITHUB_REPOSITORY", "")
        if not github_repo:
            print("Error: GitHub repository not specified")
            print("Provide it as argument or set GITHUB_REPOSITORY env var")
            sys.exit(1)
    
    # Get branch from args or environment
    if len(sys.argv) >= 5:
        branch = sys.argv[4]
    else:
        # Try to extract from GITHUB_REF
        github_ref = os.environ.get("GITHUB_REF", "refs/heads/main")
        branch = github_ref.replace("refs/heads/", "")
    
    print(f"=== Generating Manifest ===")
    print(f"Repository: {github_repo}")
    print(f"Branch: {branch}")
    print(f"Bin Directory: {bin_dir}")
    print(f"Output: {output_json}")
    print()
    
    # Generate manifest
    manifest = scan_binaries(bin_dir, github_repo, branch)
    
    if not manifest:
        print("Error: Failed to generate manifest")
        sys.exit(1)
    
    if manifest["total_binaries"] == 0:
        print("Warning: No binaries found!")
    else:
        print(f"\n✓ Found {manifest['total_binaries']} binaries")
    
    # Write to JSON file
    try:
        output_path = Path(output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_json, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        print(f"\n✓ Manifest written to {output_json}")
        
        # Print sample URLs
        print("\n=== Sample Download URLs ===")
        for platform, archs in manifest["platforms"].items():
            for arch, binaries in archs.items():
                for name, info in binaries.items():
                    print(f"{platform}/{arch}/{name}: {info['url']}")
                    break
            break
        
        return 0
    
    except Exception as e:
        print(f"Error: Failed to write manifest: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()