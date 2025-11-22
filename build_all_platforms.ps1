# Multi-Platform Build Script
# Builds cryptographic DLLs for Windows x64/x86, Linux x64/ARM, macOS x64/ARM64, WebAssembly
# Generates JSON manifest with download links and checksums

$ErrorActionPreference = "Continue"

# Configuration
$VERSION = "1.0.0"
$BASE_URL = "https://your-cdn.com/builds/v$VERSION"  # Change this to your CDN/GitHub releases URL
$OUTPUT_DIR = "lib"
$MANIFEST_FILE = "build_manifest.json"

# Build configurations
$PLATFORMS = @{
    "win-x64" = @{
        "compiler" = "C:\msys64\ucrt64\bin\gcc.exe"
        "flags" = "-m64 -O2 -std=c11"
        "output" = "stable_crypto.dll"
        "enabled" = $true
    }
    "win-x86" = @{
        "compiler" = "C:\msys64\mingw32\bin\gcc.exe"
        "flags" = "-m32 -O2 -std=c11"
        "output" = "stable_crypto.dll"
        "enabled" = $false  # Requires 32-bit toolchain
    }
    "linux-x64" = @{
        "compiler" = "x86_64-linux-gnu-gcc"
        "flags" = "-m64 -O2 -std=c11 -fPIC"
        "output" = "stable_crypto.so"
        "enabled" = $false  # Requires cross-compiler
    }
    "linux-arm64" = @{
        "compiler" = "aarch64-linux-gnu-gcc"
        "flags" = "-O2 -std=c11 -fPIC"
        "output" = "stable_crypto.so"
        "enabled" = $false  # Requires cross-compiler
    }
    "macos-x64" = @{
        "compiler" = "x86_64-apple-darwin-gcc"
        "flags" = "-m64 -O2 -std=c11"
        "output" = "stable_crypto.dylib"
        "enabled" = $false  # Requires OSXCross
    }
    "macos-arm64" = @{
        "compiler" = "aarch64-apple-darwin-gcc"
        "flags" = "-O2 -std=c11"
        "output" = "stable_crypto.dylib"
        "enabled" = $false  # Requires OSXCross
    }
    "wasm" = @{
        "compiler" = "emcc"
        "flags" = "-O2 -s WASM=1 -s EXPORTED_FUNCTIONS='[""_stable_server_hash"",""_stable_client_verify_hash""]' -s EXPORTED_RUNTIME_METHODS='[""cwrap""]'"
        "output" = "stable_crypto.wasm"
        "enabled" = $false  # Requires Emscripten
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  MULTI-PLATFORM BUILD SYSTEM" -ForegroundColor Cyan
Write-Host "  Version: $VERSION" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Create output directories
$PLATFORMS.Keys | ForEach-Object {
    New-Item -ItemType Directory -Force -Path "$OUTPUT_DIR\$_\server" | Out-Null
    New-Item -ItemType Directory -Force -Path "$OUTPUT_DIR\$_\client" | Out-Null
}

# Common source files
$SRC = "src\server"
$OBJ = "build_obj"

# Include paths
$INCLUDES = @(
    "-I$SRC",
    "-I$SRC\deps",
    "-I$SRC\deps\sph",
    "-I$SRC\deps\blake2",
    "-I$SRC\deps\pbkdf2",
    "-I$SRC\deps\scrypt",
    "-I$SRC\deps\argon2",
    "-I$SRC\deps\argon2\blake2"
)

# Build manifest
$manifest = @{
    "version" = $VERSION
    "build_date" = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    "builds" = @{}
}

function Get-FileHash256 {
    param($Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

function Get-FileHashMD5 {
    param($Path)
    return (Get-FileHash -Path $Path -Algorithm MD5).Hash.ToLower()
}

function Build-Platform {
    param(
        [string]$Platform,
        [hashtable]$Config
    )
    
    if (-not $Config.enabled) {
        Write-Host "Platform '$Platform' - SKIPPED (not enabled)" -ForegroundColor Yellow
        return $null
    }
    
    Write-Host "`nBuilding for platform: $Platform" -ForegroundColor Green
    Write-Host "Compiler: $($Config.compiler)" -ForegroundColor Gray
    
    # Check if compiler exists
    $compilerPath = $Config.compiler
    if (-not (Get-Command $compilerPath -ErrorAction SilentlyContinue)) {
        Write-Host "  ERROR: Compiler not found: $compilerPath" -ForegroundColor Red
        return $null
    }
    
    # Create platform-specific object directory
    $platformObj = "$OBJ\$Platform"
    Remove-Item -Recurse -Force $platformObj -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $platformObj | Out-Null
    
    # Compile dependencies
    Write-Host "  Compiling SPH library..." -ForegroundColor Gray
    $sphFiles = Get-ChildItem "$SRC\deps\sph\*.c" | Where-Object {
        $_.Name -notlike "*test*" -and $_.Name -notlike "*bench*" -and 
        $_.Name -ne "Main.c" -and $_.Name -notlike "*blake2*"
    }
    
    $objFiles = @()
    foreach ($file in $sphFiles) {
        $objFile = "$platformObj\$($file.BaseName).o"
        & $compilerPath $Config.flags -c $file.FullName -o $objFile $INCLUDES 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $objFiles += $objFile
        }
    }
    
    Write-Host "  Compiling BLAKE2..." -ForegroundColor Gray
    Get-ChildItem "$SRC\deps\blake2\*.c" | Where-Object { $_.Name -like "*ref.c" } | ForEach-Object {
        $objFile = "$platformObj\$($_.BaseName).o"
        & $compilerPath $Config.flags -c $_.FullName -o $objFile $INCLUDES 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $objFiles += $objFile
        }
    }
    
    Write-Host "  Compiling PBKDF2..." -ForegroundColor Gray
    if (Test-Path "$SRC\deps\pbkdf2\pbkdf2.c") {
        $objFile = "$platformObj\pbkdf2_impl.o"
        & $compilerPath $Config.flags -c "$SRC\deps\pbkdf2\pbkdf2.c" -o $objFile $INCLUDES 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $objFiles += $objFile
        }
    }
    
    Write-Host "  Compiling scrypt..." -ForegroundColor Gray
    Get-ChildItem "$SRC\deps\scrypt\*.c" | Where-Object {
        $_.Name -notlike "*test*" -and $_.Name -notlike "*check*" -and $_.Name -notlike "*hash*"
    } | ForEach-Object {
        $objFile = "$platformObj\scrypt_$($_.BaseName).o"
        & $compilerPath $Config.flags -c $_.FullName -o $objFile $INCLUDES 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $objFiles += $objFile
        }
    }
    
    # Generate implementation file (use existing one)
    if (-not (Test-Path "$OBJ\real_impl.c")) {
        Write-Host "  ERROR: real_impl.c not found. Run build_real_fixed.ps1 first." -ForegroundColor Red
        return $null
    }
    
    Write-Host "  Compiling implementation..." -ForegroundColor Gray
    $implObj = "$platformObj\real_impl.o"
    & $compilerPath $Config.flags -c "$OBJ\real_impl.c" -o $implObj $INCLUDES 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: Implementation compilation failed" -ForegroundColor Red
        return $null
    }
    $objFiles += $implObj
    
    # Link server library
    Write-Host "  Linking server library..." -ForegroundColor Gray
    $serverOutput = "$OUTPUT_DIR\$Platform\server\$($Config.output)"
    
    $linkFlags = $Config.flags
    if ($Config.output -like "*.dll") {
        $linkFlags += " -shared"
    } elseif ($Config.output -like "*.so") {
        $linkFlags += " -shared -fPIC"
    } elseif ($Config.output -like "*.dylib") {
        $linkFlags += " -dynamiclib"
    }
    
    & $compilerPath $linkFlags -o $serverOutput $objFiles -lssl -lcrypto -s 2>&1 | Out-Null
    
    if (-not (Test-Path $serverOutput)) {
        Write-Host "  ERROR: Server library build failed" -ForegroundColor Red
        return $null
    }
    
    # Copy to client
    $clientOutput = "$OUTPUT_DIR\$Platform\client\$($Config.output)"
    Copy-Item $serverOutput $clientOutput -Force
    
    $serverSize = (Get-Item $serverOutput).Length / 1KB
    Write-Host "  SUCCESS: $([Math]::Round($serverSize, 1)) KB" -ForegroundColor Green
    
    # Generate checksums
    $serverHash256 = Get-FileHash256 $serverOutput
    $serverHashMD5 = Get-FileHashMD5 $serverOutput
    $clientHash256 = Get-FileHash256 $clientOutput
    $clientHashMD5 = Get-FileHashMD5 $clientOutput
    
    # Build info for manifest
    return @{
        "platform" = $Platform
        "server" = @{
            "filename" = $Config.output
            "path" = "$Platform/server/$($Config.output)"
            "url" = "$BASE_URL/$Platform/server/$($Config.output)"
            "size" = (Get-Item $serverOutput).Length
            "sha256" = $serverHash256
            "md5" = $serverHashMD5
        }
        "client" = @{
            "filename" = $Config.output
            "path" = "$Platform/client/$($Config.output)"
            "url" = "$BASE_URL/$Platform/client/$($Config.output)"
            "size" = (Get-Item $clientOutput).Length
            "sha256" = $clientHash256
            "md5" = $clientHashMD5
        }
        "compiler" = $Config.compiler
        "flags" = $Config.flags
    }
}

# Build all platforms
Write-Host "`nStarting builds...`n" -ForegroundColor Cyan

foreach ($platform in $PLATFORMS.Keys | Sort-Object) {
    $result = Build-Platform -Platform $platform -Config $PLATFORMS[$platform]
    if ($result) {
        $manifest.builds[$platform] = $result
    }
}

# Generate manifest JSON
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Generating build manifest..." -ForegroundColor Cyan

$manifestJson = $manifest | ConvertTo-Json -Depth 10
$manifestJson | Out-File -FilePath $MANIFEST_FILE -Encoding UTF8

Write-Host "Manifest saved: $MANIFEST_FILE" -ForegroundColor Green

# Pretty print summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "BUILD SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$successCount = $manifest.builds.Count
$totalCount = $PLATFORMS.Count
Write-Host "Built: $successCount / $totalCount platforms`n" -ForegroundColor $(if ($successCount -gt 0) { "Green" } else { "Red" })

foreach ($platform in $manifest.builds.Keys | Sort-Object) {
    $build = $manifest.builds[$platform]
    Write-Host "$platform" -ForegroundColor Yellow
    Write-Host "  Server: $($build.server.filename) ($($build.server.size / 1KB) KB)" -ForegroundColor Gray
    Write-Host "    SHA256: $($build.server.sha256)" -ForegroundColor Gray
    Write-Host "    MD5:    $($build.server.md5)" -ForegroundColor Gray
    Write-Host "    URL:    $($build.server.url)" -ForegroundColor Gray
    Write-Host "  Client: $($build.client.filename) ($($build.client.size / 1KB) KB)" -ForegroundColor Gray
    Write-Host "    SHA256: $($build.client.sha256)" -ForegroundColor Gray
    Write-Host "    MD5:    $($build.client.md5)" -ForegroundColor Gray
    Write-Host "    URL:    $($build.client.url)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build complete! Manifest: $MANIFEST_FILE" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan
