#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Quick start script for Crypto POW Library

.DESCRIPTION
    Sets up the environment and runs a quick demo to verify everything works
#>

$ErrorActionPreference = "Stop"

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

function Write-Fail {
    param([string]$Message)
    Write-ColorOutput "[✗] $Message" "Red"
}

# Header
Write-ColorOutput "`n╔═══════════════════════════════════════════════════════════╗" "Cyan"
Write-ColorOutput "║      Crypto POW Library - Quick Start                    ║" "Cyan"
Write-ColorOutput "╚═══════════════════════════════════════════════════════════╝" "Cyan"

# Check DLLs
Write-Step "Checking library files..."
$serverDll = "lib\win\64\server\stable_crypto_server.dll"
$clientDll = "lib\win\64\client\stable_crypto_client.dll"

if (-not (Test-Path $serverDll)) {
    Write-Fail "Server DLL not found: $serverDll"
    Write-Host "`nPlease build first:"
    Write-Host "  .\build_windows_64.ps1" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $clientDll)) {
    Write-Fail "Client DLL not found: $clientDll"
    Write-Host "`nPlease build first:"
    Write-Host "  .\build_windows_64.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Success "DLLs found"

# Check Python
Write-Step "Checking Python..."
try {
    $pythonVersion = python --version 2>&1
    Write-Success "Python installed: $pythonVersion"
} catch {
    Write-Fail "Python not found"
    Write-Host "Please install Python from https://www.python.org/" -ForegroundColor Yellow
    exit 1
}

# Install dependencies
Write-Step "Installing Python dependencies..."
try {
    python -m pip install termcolor --quiet
    Write-Success "Dependencies installed"
} catch {
    Write-Fail "Failed to install dependencies"
    exit 1
}

# Quick test
Write-Step "Running quick test..."
$testScript = @"
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))

from crypto_server import CryptoServer, CryptoAlgorithm

server = CryptoServer()
test_data = b'Quick Start Test'

# Test 3 algorithms
algorithms = [
    CryptoAlgorithm.SHA256D,
    CryptoAlgorithm.BLAKE3,
    CryptoAlgorithm.KECCAK
]

print('\nTesting 3 algorithms:')
for algo in algorithms:
    result = server.hash(algo, test_data)
    print(f'  ✓ {algo.name}: {result.hex()[:16]}...')

print('\n✓ All tests passed!')
"@

try {
    $testScript | python
    Write-Success "Quick test passed"
} catch {
    Write-Fail "Quick test failed"
    exit 1
}

# Show next steps
Write-ColorOutput "`n╔═══════════════════════════════════════════════════════════╗" "Green"
Write-ColorOutput "║      ✓ Setup Complete! Ready to use.                     ║" "Green"
Write-ColorOutput "╚═══════════════════════════════════════════════════════════╝" "Green"

Write-ColorOutput "`nTry these examples:" "Cyan"
Write-Host "  1. Simple challenge:      " -NoNewline
Write-Host "python examples\simple_challenge.py" -ForegroundColor White

Write-Host "  2. All 39 algorithms:     " -NoNewline
Write-Host "python examples\challenge_all_algorithms.py" -ForegroundColor White

Write-Host "  3. Mining demo:           " -NoNewline
Write-Host "python examples\mining_challenge.py" -ForegroundColor White

Write-Host "  4. Client-server:         " -NoNewline
Write-Host "python examples\client_server_verification.py" -ForegroundColor White

Write-Host "  5. Full test suite:       " -NoNewline
Write-Host "python tests\test_all_algorithms.py" -ForegroundColor White

Write-ColorOutput "`nDocumentation:" "Cyan"
Write-Host "  - BUILD_README.md:        Build system and architecture"
Write-Host "  - examples\README.md:     Example usage and customization"

Write-Host ""
