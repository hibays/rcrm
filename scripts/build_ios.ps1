# build_ios.ps1
# Full iOS build pipeline: Rust static lib -> Flutter .app
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   Xcode + CocoaPods installed
#   Must be run on macOS (cargo target aarch64-apple-ios only works there)
# Usage:
#   .\scripts\build_ios.ps1                 # debug (simulator)
#   .\scripts\build_ios.ps1 -Release        # release (device)
#   .\scripts\build_ios.ps1 -Release -NoSign # release without codesign
param(
    [switch]$Release,
    [switch]$NoSign  # Skip code signing
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path -Parent
$gui = "$root\crates\rcrm-gui"
$bridge = "$root\crates\rcrm-flutter-bridge"

$flutterMode = if ($Release) { "release" } else { "debug" }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " RCrm GUI --- iOS Build ($flutterMode)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Rust bridge for iOS ─────────────────────────────────
Write-Host "[1/4] Building Rust bridge for iOS..." -ForegroundColor Yellow
Push-Location $bridge
# RUSTC_BOOTSTRAP=rav1d: keep identical to Android/Windows scripts — cargo folds
# it into the fingerprint config hash; any mismatch forces a full rebuild.
$env:RUSTC_BOOTSTRAP = "rav1d"
cargo build --release -p rcrm-flutter-bridge --features mobile-decode --target aarch64-apple-ios
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust iOS device build failed!" -ForegroundColor Red
    Pop-Location; exit 1
}
Write-Host "  -> librcrm_flutter_bridge.a (device)" -ForegroundColor Green

cargo build --release -p rcrm-flutter-bridge --features mobile-decode --target aarch64-apple-ios-sim 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  -> librcrm_flutter_bridge.a (simulator)" -ForegroundColor Green
}
Pop-Location
Write-Host ""

# ── Step 2: Copy static lib into Xcode project ─────────────────
Write-Host "[2/4] Linking Rust static lib into Xcode project..." -ForegroundColor Yellow
$staticLib = "$root\target\aarch64-apple-ios\release\librcrm_flutter_bridge.a"
if (Test-Path $staticLib) {
    Copy-Item $staticLib "$gui\ios\Runner\librcrm_flutter_bridge.a" -Force
    Write-Host "  -> librcrm_flutter_bridge.a copied to Runner/" -ForegroundColor Green
} else {
    Write-Host "  WARNING: librcrm_flutter_bridge.a not found at $staticLib" -ForegroundColor Yellow
}
Write-Host ""

# ── Step 3: Pre-download libmpv xcframeworks ───────────────────
Write-Host "[3/4] Pre-downloading libmpv xcframeworks..." -ForegroundColor Yellow
$cacheDir = "$gui\ios\.symlinks\plugins\media_kit_libs_ios_video\ios\.cache\xcframeworks"
$libmpvVer = "v0.6.0"
$libmpvUrl = "https://github.com/media-kit/libmpv-darwin-build/releases/download/$libmpvVer/libmpv-xcframeworks_$($libmpvVer)_ios-universal-video-default.tar.gz"
$libmpvFile = "libmpv-xcframeworks-$libmpvVer-ios-universal.tar.gz"

New-Item -ItemType Directory -Force $cacheDir | Out-Null
if (Test-Path "$cacheDir\$libmpvFile") {
    Write-Host "  libmpv xcframework [cached]" -ForegroundColor Gray
} else {
    Write-Host "  Downloading libmpv xcframework..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $libmpvUrl -OutFile "$cacheDir\$libmpvFile" -UseBasicParsing
        Write-Host "  libmpv xcframework [OK]" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Failed to download libmpv xcframework" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# ── Step 4: Flutter build ───────────────────────────────────────
Write-Host "[4/4] Building Flutter ($flutterMode)..." -ForegroundColor Yellow
Push-Location $gui
if ($NoSign) {
    flutter build ios --$flutterMode --no-codesign
} else {
    flutter build ios --$flutterMode
}
$buildOk = $LASTEXITCODE -eq 0
Pop-Location

if ($buildOk) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " BUILD SUCCESSFUL" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  App: $gui\build\ios\iphoneos\Runner.app" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host " BUILD FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}
