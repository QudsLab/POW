# Rebuild server DLL with all fixed algorithms
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  REBUILDING CRYPTO SERVER DLL" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

Set-Location "src\server"

# Step 1: Compile all algorithm implementations
Write-Host "`n[1/3] Compiling all 39 algorithms..." -ForegroundColor Yellow
$algoFiles = Get-ChildItem -Filter "stable_*.c" | Where-Object { $_.Name -ne "stable_argon2_full.c" -and $_.Name -ne "stable_server_api.c" } | ForEach-Object { $_.Name }
gcc -c $algoFiles -I. -O2 -std=c11
if ($LASTEXITCODE -ne 0) { Write-Host "✗ Algorithm compilation failed" -ForegroundColor Red; exit 1 }
Write-Host "✓ All 39 algorithms compiled" -ForegroundColor Green

# Step 2: Compile dependencies
Write-Host "`n[2/3] Compiling dependencies..." -ForegroundColor Yellow
Set-Location "..\.."

# Compile each dependency library
$depDirs = @("blake2", "sph", "pbkdf2", "scrypt", "argon2", "Lyra", "blake3_simple")
foreach ($dir in $depDirs) {
    $files = Get-ChildItem -Path "src\server\deps\$dir" -Filter "*.c" -ErrorAction SilentlyContinue
    if ($files) {
        $fileNames = $files | ForEach-Object { $_.FullName }
        gcc -c $fileNames -Isrc\server -O2 -std=c11 2>$null
    }
}
Write-Host "✓ Dependencies compiled" -ForegroundColor Green

# Step 3: Link everything into DLL
Write-Host "`n[3/3] Linking DLL..." -ForegroundColor Yellow
$allObjs = Get-ChildItem -Filter "*.o" | ForEach-Object { $_.FullName }
if ($allObjs.Count -lt 40) { 
    Write-Host "✗ Not enough object files found ($($allObjs.Count))" -ForegroundColor Red
    exit 1
}

Write-Host "  Found $($allObjs.Count) object files"
g++ -shared -o lib/stable_crypto_server.dll $allObjs -lwinpthread -lws2_32 -static-libgcc -static-libstdc++

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓✓✓ SERVER DLL BUILT SUCCESSFULLY! ✓✓✓" -ForegroundColor Green
    Remove-Item *.o -ErrorAction SilentlyContinue
    $dll = Get-Item lib\stable_crypto_server.dll
    Write-Host "`nDLL Info:" -ForegroundColor Cyan
    Write-Host "  Path: $($dll.FullName)"
    Write-Host "  Size: $([math]::Round($dll.Length/1MB,2)) MB"
} else {
    Write-Host "`n✗ Linking failed" -ForegroundColor Red
    exit 1
}
