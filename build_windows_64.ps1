#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build script for Windows 64-bit crypto library (server and client)

.DESCRIPTION
    Compiles both server and client DLLs for 64-bit Windows and organizes
    them into lib/win/64/server and lib/win/64/client directories.
    
    Requirements:
    - MSYS2 with MinGW-w64 (ucrt64 or mingw64)
    - GCC compiler
    - OpenSSL development libraries
    
.EXAMPLE
    .\build_windows_64.ps1
#>

param(
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Configuration
$SCRIPT_DIR = $PSScriptRoot
$SRC_SERVER = Join-Path $SCRIPT_DIR "src\server"
$SRC_CLIENT = Join-Path $SCRIPT_DIR "src\client"
$OUTPUT_DIR = Join-Path $SCRIPT_DIR "lib\win\64"
$SERVER_OUTPUT = Join-Path $OUTPUT_DIR "server"
$CLIENT_OUTPUT = Join-Path $OUTPUT_DIR "client"

# Compiler settings
$MINGW_PATH = "C:\msys64\ucrt64\bin"
$GCC = Join-Path $MINGW_PATH "gcc.exe"
$GPP = Join-Path $MINGW_PATH "g++.exe"

# Compiler flags
$COMMON_FLAGS = @(
    "-m64",
    "-O3",
    "-Wall",
    "-fPIC",
    "-DNDEBUG"
)

$C_FLAGS = $COMMON_FLAGS + @(
    "-std=c11"
)

$CPP_FLAGS = $COMMON_FLAGS + @(
    "-std=c++17",
    "-fopenmp"
)

$LD_FLAGS = @(
    "-m64",
    "-shared",
    "-s",
    "-static-libgcc",
    "-static-libstdc++",
    "-Wl,--subsystem,windows"
)

# Colors for output
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Step {
    param([string]$Message)
    Write-ColorOutput "`n[*] $Message" "Cyan"
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "[✓] $Message" "Green"
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "[✗] $Message" "Red"
}

# Check prerequisites
function Test-Prerequisites {
    Write-Step "Checking prerequisites..."
    
    if (-not (Test-Path $MINGW_PATH)) {
        Write-Error "MinGW-w64 not found at $MINGW_PATH"
        Write-Host "Please install MSYS2 from https://www.msys2.org/"
        exit 1
    }
    
    if (-not (Test-Path $GCC)) {
        Write-Error "GCC not found at $GCC"
        Write-Host "Run in MSYS2: pacman -S mingw-w64-ucrt-x86_64-gcc"
        exit 1
    }
    
    Write-Success "All prerequisites found"
}

# Clean build artifacts
function Invoke-Clean {
    Write-Step "Cleaning build artifacts..."
    
    # Clean object files
    Get-ChildItem -Path $SRC_SERVER -Filter "*.o" -Recurse | Remove-Item -Force
    Get-ChildItem -Path $SRC_CLIENT -Filter "*.o" -Recurse | Remove-Item -Force
    
    # Clean output directories
    if (Test-Path $OUTPUT_DIR) {
        Remove-Item -Path $OUTPUT_DIR -Recurse -Force
    }
    
    Write-Success "Clean complete"
}

# Compile C/C++ files
function Invoke-Compile {
    param(
        [string]$SourceDir,
        [string]$Type  # "server" or "client"
    )
    
    Write-Step "Compiling $Type sources..."
    
    Push-Location $SourceDir
    
    try {
        # Compile C files
        $cFiles = Get-ChildItem -Path "." -Filter "stable_*.c" -File
        foreach ($file in $cFiles) {
            $objFile = $file.Name -replace '\.c$', '.o'
            
            if ($Verbose) {
                Write-Host "  Compiling: $($file.Name)"
            }
            
            & $GCC @C_FLAGS -c $file.Name -o $objFile
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to compile $($file.Name)"
            }
        }
        
        # Compile C++ files (only in server - RandomX, ProgPOW, etc.)
        if ($Type -eq "server") {
            # Compile RandomX
            $randomxDir = Join-Path $SourceDir "deps\RandomX"
            if (Test-Path $randomxDir) {
                Write-Host "  Compiling RandomX..."
                $cppFiles = Get-ChildItem -Path $randomxDir -Filter "*.cpp" -File
                foreach ($file in $cppFiles) {
                    $objFile = Join-Path $randomxDir ($file.Name -replace '\.cpp$', '.o')
                    
                    if ($Verbose) {
                        Write-Host "    $($file.Name)"
                    }
                    
                    & $GPP @CPP_FLAGS -c $file.FullName -o $objFile
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to compile $($file.Name)"
                    }
                }
            }
            
            # Compile ProgPOW/Ethash
            $progpowDir = Join-Path $SourceDir "deps\progpow"
            if (Test-Path $progpowDir) {
                Write-Host "  Compiling ProgPOW/Ethash..."
                $cppFiles = Get-ChildItem -Path $progpowDir -Filter "*.cpp" -File
                foreach ($file in $cppFiles) {
                    $objFile = Join-Path $progpowDir ($file.Name -replace '\.cpp$', '.o')
                    
                    if ($Verbose) {
                        Write-Host "    $($file.Name)"
                    }
                    
                    & $GPP @CPP_FLAGS -c $file.FullName -o $objFile
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to compile $($file.Name)"
                    }
                }
            }
            
            # Compile Equihash
            $equihashDir = Join-Path $SourceDir "deps\equihash"
            if (Test-Path $equihashDir) {
                Write-Host "  Compiling Equihash..."
                $cppFiles = Get-ChildItem -Path $equihashDir -Filter "*.cpp" -File
                foreach ($file in $cppFiles) {
                    $objFile = Join-Path $equihashDir ($file.Name -replace '\.cpp$', '.o')
                    
                    if ($Verbose) {
                        Write-Host "    $($file.Name)"
                    }
                    
                    & $GPP @CPP_FLAGS -c $file.FullName -o $objFile
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to compile $($file.Name)"
                    }
                }
            }
            
            # Compile Lyra2
            $lyra2Dir = Join-Path $SourceDir "deps\Lyra2"
            if (Test-Path $lyra2Dir) {
                Write-Host "  Compiling Lyra2..."
                $cFiles = Get-ChildItem -Path $lyra2Dir -Filter "*.c" -File
                foreach ($file in $cFiles) {
                    $objFile = Join-Path $lyra2Dir ($file.Name -replace '\.c$', '.o')
                    
                    if ($Verbose) {
                        Write-Host "    $($file.Name)"
                    }
                    
                    & $GCC @C_FLAGS -c $file.FullName -o $objFile
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to compile $($file.Name)"
                    }
                }
            }
        }
        
        Write-Success "Compilation complete"
    }
    finally {
        Pop-Location
    }
}

# Link DLL
function Invoke-Link {
    param(
        [string]$SourceDir,
        [string]$OutputPath,
        [string]$DllName,
        [string]$Type
    )
    
    Write-Step "Linking $Type DLL..."
    
    Push-Location $SourceDir
    
    try {
        # Collect all object files
        $objFiles = @()
        
        # Add main C objects
        $objFiles += Get-ChildItem -Path "." -Filter "*.o" -File | Select-Object -ExpandProperty Name
        
        # Add dependency objects (server only)
        if ($Type -eq "server") {
            # RandomX objects
            $randomxDir = Join-Path $SourceDir "deps\RandomX"
            if (Test-Path $randomxDir) {
                $objFiles += Get-ChildItem -Path $randomxDir -Filter "*.o" -File | Select-Object -ExpandProperty FullName
            }
            
            # ProgPOW objects
            $progpowDir = Join-Path $SourceDir "deps\progpow"
            if (Test-Path $progpowDir) {
                $objFiles += Get-ChildItem -Path $progpowDir -Filter "*.o" -File | Select-Object -ExpandProperty FullName
            }
            
            # Equihash objects
            $equihashDir = Join-Path $SourceDir "deps\equihash"
            if (Test-Path $equihashDir) {
                $objFiles += Get-ChildItem -Path $equihashDir -Filter "*.o" -File | Select-Object -ExpandProperty FullName
            }
            
            # Lyra2 objects
            $lyra2Dir = Join-Path $SourceDir "deps\Lyra2"
            if (Test-Path $lyra2Dir) {
                $objFiles += Get-ChildItem -Path $lyra2Dir -Filter "*.o" -File | Select-Object -ExpandProperty FullName
            }
        }
        
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        $dllPath = Join-Path $OutputPath $DllName
        
        # Link command
        if ($Type -eq "server") {
            # Server needs C++ runtime and OpenMP
            & $GPP @LD_FLAGS -o $dllPath $objFiles -lssl -lcrypto -lgomp
        } else {
            # Client is pure C
            & $GCC @LD_FLAGS -o $dllPath $objFiles -lssl -lcrypto
        }
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to link $DllName"
        }
        
        Write-Success "Linked: $dllPath"
    }
    finally {
        Pop-Location
    }
}

# Copy runtime dependencies
function Copy-Dependencies {
    param(
        [string]$OutputPath,
        [string]$Type
    )
    
    Write-Step "Copying dependencies for $Type..."
    
    $dependencies = @(
        "libssl-3-x64.dll",
        "libcrypto-3-x64.dll"
    )
    
    # Server needs additional C++ runtime
    if ($Type -eq "server") {
        $dependencies += @(
            "libstdc++-6.dll",
            "libgomp-1.dll",
            "libgcc_s_seh-1.dll",
            "libwinpthread-1.dll"
        )
    }
    
    foreach ($dll in $dependencies) {
        $sourcePath = Join-Path $MINGW_PATH $dll
        if (Test-Path $sourcePath) {
            Copy-Item -Path $sourcePath -Destination $OutputPath -Force
            if ($Verbose) {
                Write-Host "  Copied: $dll"
            }
        } else {
            Write-Warning "Dependency not found: $dll"
        }
    }
    
    Write-Success "Dependencies copied"
}

# Display build summary
function Show-Summary {
    Write-Step "Build Summary"
    
    # Server DLL
    $serverDll = Join-Path $SERVER_OUTPUT "stable_crypto_server.dll"
    if (Test-Path $serverDll) {
        $size = (Get-Item $serverDll).Length / 1MB
        Write-ColorOutput "  Server DLL: $([Math]::Round($size, 2)) MB" "Green"
    }
    
    # Client DLL
    $clientDll = Join-Path $CLIENT_OUTPUT "stable_crypto_client.dll"
    if (Test-Path $clientDll) {
        $size = (Get-Item $clientDll).Length / 1MB
        Write-ColorOutput "  Client DLL: $([Math]::Round($size, 2)) MB" "Green"
    }
    
    # Dependencies
    $serverDeps = Get-ChildItem -Path $SERVER_OUTPUT -Filter "*.dll" | Where-Object { $_.Name -ne "stable_crypto_server.dll" }
    $clientDeps = Get-ChildItem -Path $CLIENT_OUTPUT -Filter "*.dll" | Where-Object { $_.Name -ne "stable_crypto_client.dll" }
    
    Write-Host "`n  Server dependencies: $($serverDeps.Count) DLLs"
    Write-Host "  Client dependencies: $($clientDeps.Count) DLLs"
    
    Write-ColorOutput "`n[✓] Build complete!" "Green"
    Write-Host "Output directory: $OUTPUT_DIR"
}

# Main build process
function Invoke-Build {
    Write-ColorOutput "`n╔════════════════════════════════════════════╗" "Cyan"
    Write-ColorOutput "║  Windows 64-bit Crypto Library Builder    ║" "Cyan"
    Write-ColorOutput "╚════════════════════════════════════════════╝" "Cyan"
    
    Test-Prerequisites
    
    if ($Clean) {
        Invoke-Clean
    }
    
    # Build server
    Invoke-Compile -SourceDir $SRC_SERVER -Type "server"
    Invoke-Link -SourceDir $SRC_SERVER -OutputPath $SERVER_OUTPUT -DllName "stable_crypto_server.dll" -Type "server"
    Copy-Dependencies -OutputPath $SERVER_OUTPUT -Type "server"
    
    # Build client
    Invoke-Compile -SourceDir $SRC_CLIENT -Type "client"
    Invoke-Link -SourceDir $SRC_CLIENT -OutputPath $CLIENT_OUTPUT -DllName "stable_crypto_client.dll" -Type "client"
    Copy-Dependencies -OutputPath $CLIENT_OUTPUT -Type "client"
    
    Show-Summary
}

# Run build
Invoke-Build
