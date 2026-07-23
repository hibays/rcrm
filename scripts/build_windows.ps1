# build_windows.ps1
# Full Windows build pipeline: tests (debug only) → Rust → deps → Flutter → assets
# Usage:
#   .\scripts\build_windows.ps1             # debug
#   .\scripts\build_windows.ps1 -Release    # release
param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path -Parent
$gui = "$root\crates\rcrm-gui"
$bridge = "$root\crates\rcrm-flutter-bridge"
$buildDir = "$gui\build\windows\x64"

$flutterMode = if ($Release) { "release" } else { "debug" }
$destSuffix = if ($Release) { "Release" } else { "Debug" }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " RCrm GUI --- Windows Build ($flutterMode)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 0: Tests (debug only) ──────────────────────────────────
if (-not $Release) {
    Write-Host "[0/4] Running tests..." -ForegroundColor Yellow
    Push-Location $gui
    flutter test test/rcrm_gui_test.dart
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Tests failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    Pop-Location
    Write-Host ""
}

# ── Step 1: Rust bridge ─────────────────────────────────────────
Write-Host "[1/4] Building Rust bridge (release)..." -ForegroundColor Yellow
Push-Location $bridge; cargo build --release; Pop-Location
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust build failed!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ── Step 2: Pre-download media_kit deps ─────────────────────────
Write-Host "[2/4] Downloading media_kit Windows deps..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force $buildDir | Out-Null

$mpvUrl = "https://github.com/media-kit/libmpv-win32-video-build/releases/download/2023-09-24/mpv-dev-x86_64-20230924-git-652a1dd.7z"
$angleUrl = "https://github.com/alexmercerind/flutter-windows-ANGLE-OpenGL-ES/releases/download/v1.0.1/ANGLE.7z"

$mpv7z = "$buildDir\mpv-dev-x86_64-20230924-git-652a1dd.7z"
$angle7z = "$buildDir\ANGLE.7z"

if (-not (Test-Path $mpv7z)) {
    Write-Host "  Downloading mpv..." -ForegroundColor Gray
    Invoke-WebRequest $mpvUrl -OutFile $mpv7z -UseBasicParsing
    Write-Host "  mpv [OK]" -ForegroundColor Green
} else {
    Write-Host "  mpv [cached]" -ForegroundColor Gray
}

if (-not (Test-Path $angle7z)) {
    Write-Host "  Downloading ANGLE..." -ForegroundColor Gray
    Invoke-WebRequest $angleUrl -OutFile $angle7z -UseBasicParsing
    Write-Host "  ANGLE [OK]" -ForegroundColor Green
} else {
    Write-Host "  ANGLE [cached]" -ForegroundColor Gray
}
Write-Host ""

# ── Step 3: Flutter build ───────────────────────────────────────
Write-Host "[3/4] Building Flutter ($flutterMode)..." -ForegroundColor Yellow
Push-Location $gui
flutter build windows --$flutterMode
$buildOk = $LASTEXITCODE -eq 0
Pop-Location
if (-not $buildOk) {
    Write-Host "ERROR: Flutter build failed!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ── Step 4: Copy assets ─────────────────────────────────────────
Write-Host "[4/4] Copying assets..." -ForegroundColor Yellow
$dest = "$buildDir\runner\$destSuffix"

Remove-Item "$dest\data\flutter_assets" -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "$gui\build\flutter_assets" "$dest\data\flutter_assets" -Recurse -Force

if ($Release) {
    Copy-Item "$gui\build\windows\app.so" "$dest\data\app.so" -Force
}

Copy-Item "$root\target\release\rcrm_flutter_bridge.dll" $dest -Force
Copy-Item "$buildDir\ANGLE\*.dll" $dest -Force
Copy-Item "$buildDir\libmpv\*.dll" $dest -Force
Get-ChildItem "$buildDir\plugins" -Recurse -Filter *.dll | ForEach-Object {
    Copy-Item $_.FullName $dest -Force
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  $dest\rcrm_gui.exe" -ForegroundColor Green
