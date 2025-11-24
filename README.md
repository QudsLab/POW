# POW - Proof of Work Cryptographic Library

Multi-platform cryptographic library with proof-of-work implementations.

## Quick Start

### Local Build

```bash
make all
```

This will build client and server DLLs in the `bin/` directory.

### Multi-Platform Builds

The GitHub Actions workflow automatically builds for all platforms on every push to main:

- **Windows**: 32-bit & 64-bit DLLs
- **Linux**: x86 (32-bit), x64 (64-bit)
- **macOS**: Universal 64-bit (Intel & Apple Silicon)
- **WebAssembly**: 32-bit & 64-bit modules
- **Android**: ARMv7 & ARM64

## Build Scripts

Individual platform builds can be run locally:

```bash
# Windows
bash build_windows.sh

# Linux
bash build_linux.sh

# macOS
bash build_macos.sh

# Android (requires NDK)
bash build_android.sh

# WebAssembly (requires Emscripten)
bash build_wasm.sh
```

## Binary Organization

All binaries are organized in `bin/` by platform and architecture:

```
bin/
├── versions.json          # Manifest with checksums
├── BINARY_INFO.md         # Detailed documentation
├── windows/
│   ├── 32/
│   └── 64/
├── linux/
│   ├── 32/
│   └── 64/
├── macos/
│   └── 64/
├── wasm/
│   ├── 32/
│   └── 64/
└── android/
    ├── 32/
    └── 64/
```

## Releases

Automated releases are created on every push to main with:
- All platform binaries
- SHA-256 and MD5 checksums
- Download links in `versions.json`

See [Releases](https://github.com/qudslab/pow/releases) for downloads.

## License

See [LICENSE](LICENSE) file.
