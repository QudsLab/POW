# POW Binary Information

## Directory Structure

```
bin/
├── versions.json              # Manifest with checksums and download links
├── windows/
│   ├── 32/                    # 32-bit Windows DLLs
│   └── 64/                    # 64-bit Windows DLLs
├── linux/
│   ├── 32/                    # 32-bit Linux libraries
│   └── 64/                    # 64-bit Linux libraries
├── macos/
│   └── 64/                    # macOS libraries (universal)
├── wasm/
│   ├── 32/                    # 32-bit WebAssembly modules
│   └── 64/                    # 64-bit WebAssembly modules
└── android/
    ├── 32/                    # 32-bit Android libraries
    └── 64/                    # 64-bit Android libraries
```

## How We Handle Binaries

### Build Process

Sequential build process ensures consistency:
1. **Windows** → 32-bit & 64-bit DLLs
2. **Linux** → 32-bit & 64-bit .so files
3. **macOS** → 64-bit universal .dylib files
4. **Android** → 32-bit & 64-bit .so files
5. **WebAssembly** → 32-bit & 64-bit .wasm modules
6. **Manifest Generation** → Calculate checksums, create versions.json

### Organization

- **Bit-based**: Organized by 32-bit or 64-bit architecture
- **Platform-separated**: Each OS has its own directory
- **Checksums included**: SHA-256 and MD5 for verification
- **Centralized manifest**: versions.json contains all metadata

### File Extensions

- Windows: `.dll`
- Linux: `.so`
- macOS: `.dylib`
- WebAssembly: `.wasm`, `.js`
- Android: `.so`

## Manifest (versions.json)

Contains for each binary:
- Name, type, size
- SHA-256 and MD5 checksums
- Direct download URL from GitHub releases

## Use Cases

- **Desktop Apps**: Use Windows/macOS/Linux binaries
- **Web Apps**: Use WebAssembly modules
- **Mobile Apps**: Use Android libraries
- **Servers**: Use Linux 64-bit for performance
- **Embedded**: Use Linux 32-bit for resource-constrained devices

## Verification

```bash
# Verify binary integrity
sha256sum binary_file
# Compare with versions.json
```

## Build Triggers

Workflow runs on:
- Push to main/master/develop (when src/ or Makefile changes)
- Pull requests
- Manual dispatch
- Weekly (Sunday 00:00 UTC)
