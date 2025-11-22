# Multi-Platform Build System for Cryptographic Libraries
# Automatically builds binaries on push to repository

## Setup Instructions

### 1. Enable GitHub Actions
Push this to your repository and GitHub Actions will automatically run.

### 2. Required Secrets (Optional)
No secrets needed - uses GitHub's built-in GITHUB_TOKEN.

### 3. Trigger Builds
Builds trigger on:
- Push to main/master/develop branches
- Pull requests to main/master
- Manual workflow dispatch
- Weekly schedule (every Sunday)

## Build Outputs

### Platforms Built
- **Windows**: x64, x86 (DLLs)
- **Linux**: x64, ARM64, ARMv7 (.so)
- **macOS**: x64 (Intel), ARM64 (M1/M2) (.dylib)
- **WebAssembly**: Universal (.wasm + .js)
- **Android**: arm64-v8a, armeabi-v7a, x86_64, x86 (.so)

### Generated Files
After each build, the following are created:

1. **Binary Artifacts** (90-day retention):
   - Windows DLLs in `lib/win/{64,32}/{server,client}/`
   - Linux .so in `lib/linux/{x64,arm64,armv7}/{server,client}/`
   - macOS .dylib in `lib/macos/{x64,arm64}/{server,client}/`
   - WASM modules in `lib/wasm/`
   - Android .so in `lib/android/{abi}/`

2. **versions.json** (365-day retention):
   - Complete manifest with:
     - Download URLs for all binaries
     - SHA256 and MD5 checksums
     - File sizes and metadata
     - Build version and commit info
     - Algorithm implementation status

3. **GitHub Release**:
   - Tagged as `v{build_number}`
   - Includes all binaries
   - Includes versions.json
   - Auto-generated release notes

## Local Build

### Windows (MSYS2)
```bash
cd build_scripts
bash build_windows.sh x64
```

### Linux
```bash
cd build_scripts
bash build_linux.sh x64
```

### macOS
```bash
cd build_scripts
bash build_macos.sh arm64
```

### WebAssembly
```bash
# Install Emscripten first
cd build_scripts
bash build_wasm.sh
```

### Android
```bash
# Set ANDROID_NDK_HOME first
cd build_scripts
bash build_android.sh arm64-v8a
```

## Generate Manifest Locally
```bash
python build_scripts/generate_manifest.py \
  --release-url "https://example.com/releases" \
  --version "1" \
  --input-dir lib \
  --output versions.json
```

## Using versions.json

### Download Latest Build
```python
import requests
import hashlib

# Fetch manifest
manifest = requests.get("https://github.com/user/repo/releases/latest/download/versions.json").json()

# Get Windows x64 server DLL
dll_info = manifest["platforms"]["windows"]["x64"]["server"][0]
print(f"Downloading: {dll_info['filename']}")
print(f"Size: {dll_info['size_human']}")

# Download and verify
response = requests.get(dll_info["url"])
data = response.content

# Verify SHA256
assert hashlib.sha256(data).hexdigest() == dll_info["sha256"]
print("✓ Checksum verified!")

with open(dll_info["filename"], "wb") as f:
    f.write(data)
```

### Check Available Platforms
```javascript
fetch('versions.json')
  .then(r => r.json())
  .then(manifest => {
    console.log('Available platforms:', Object.keys(manifest.platforms));
    console.log('Build version:', manifest.version);
    console.log('Real algorithms:', manifest.algorithms.real_implementations);
  });
```

## Customization

### Add More Platforms
Edit `.github/workflows/build-all-platforms.yml` and add new job:
```yaml
build-freebsd:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Build FreeBSD
      uses: cross-platform-actions/action@v0.23.0
      with:
        operating_system: freebsd
        version: '13.2'
        run: cd build_scripts && bash build_freebsd.sh
```

### Change Build Triggers
Modify `on:` section in workflow file:
```yaml
on:
  push:
    branches: [ main ]
    paths:
      - 'src/**'      # Only rebuild if source changes
  schedule:
    - cron: '0 0 * * 1'  # Build every Monday
```

### Add Build Matrix
Expand architectures:
```yaml
strategy:
  matrix:
    arch: [x64, x86, arm64, armv7, riscv64]
```

## Monitoring Builds

- View build status: `https://github.com/user/repo/actions`
- Download artifacts: Actions → Workflow run → Artifacts
- View releases: `https://github.com/user/repo/releases`

## Troubleshooting

### Build Fails on ARM
Install cross-compile tools in workflow:
```yaml
- name: Install ARM toolchain
  run: sudo apt-get install -y gcc-aarch64-linux-gnu
```

### WebAssembly Build Fails
Update Emscripten version:
```yaml
- uses: mymindstorm/setup-emsdk@v14
  with:
    version: '3.1.50'  # Specific version
```

### Checksums Don't Match
Ensure deterministic builds - disable timestamps:
```bash
gcc -Wl,--no-insert-timestamp ...
```

## File Structure After Build
```
lib/
├── win/
│   ├── 64/
│   │   ├── server/
│   │   │   ├── stable_crypto_server.dll
│   │   │   └── libcrypto-3-x64.dll
│   │   └── client/
│   │       └── stable_crypto_client.dll
│   └── 32/
│       └── ...
├── linux/
│   ├── x64/
│   ├── arm64/
│   └── armv7/
├── macos/
│   ├── x64/
│   └── arm64/
├── wasm/
│   ├── stable_crypto.wasm
│   └── stable_crypto.js
├── android/
│   ├── arm64-v8a/
│   ├── armeabi-v7a/
│   ├── x86_64/
│   └── x86/
└── versions.json
```
