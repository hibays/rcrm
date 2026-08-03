# build_android.ps1
# Full Android build pipeline: Rust .so for 4 ABIs → Flutter APK
# Prerequisites:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
#   cargo install cargo-ndk
#   $env:ANDROID_NDK_HOME = "path/to/ndk"

param(
    [switch]$Release,
    [switch]$SplitAbi  # Produce split APKs (smaller)
)

$ErrorActionPreference = "Stop"
$root = $PWD

$profile = if ($Release) { "release" } else { "debug" }
$cargoFlag = "--release"
$flutterMode = if ($Release) { "release" } else { "debug" }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " RCrm GUI --- Android Build Pipeline" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Build Rust for Android ABIs ────────────────────────
Write-Host "[1/4] Building Rust bridge for Android ($profile)..." -ForegroundColor Yellow

$jniLibsBase = "crates/rcrm-gui/android/app/src/main/jniLibs"
New-Item -ItemType Directory -Force -Path "$jniLibsBase/arm64-v8a" | Out-Null
New-Item -ItemType Directory -Force -Path "$jniLibsBase/armeabi-v7a" | Out-Null
New-Item -ItemType Directory -Force -Path "$jniLibsBase/x86_64" | Out-Null
New-Item -ItemType Directory -Force -Path "$jniLibsBase/x86" | Out-Null

# RUSTC_BOOTSTRAP=rav1d: unlock only the stdarch_arm_feature_detection
# nightly gate that rav1d's ARM asm needs on armv7. MUST be identical in
# every build script: cargo folds RUSTC_BOOTSTRAP into the fingerprint
# config hash, so a mismatch between scripts forces a full rebuild.
$env:RUSTC_BOOTSTRAP = "rav1d"
cargo ndk `
    --target aarch64-linux-android `
    --target armv7-linux-androideabi `
    --target x86_64-linux-android `
    --target i686-linux-android `
    -o $jniLibsBase `
    build -p rcrm-flutter-bridge --features mobile-decode $cargoFlag

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust Android build failed!" -ForegroundColor Red
    exit 1
}

# cargo-ndk already placed the .so files in the right directories
Write-Host "  -> Native libraries placed in $jniLibsBase" -ForegroundColor Green
Get-ChildItem -Recurse "$jniLibsBase/*.so" | ForEach-Object {
    Write-Host "     $($_.FullName)" -ForegroundColor Gray
}

Write-Host ""

# ── Step 2: Pre-download media_kit Android JARs ──────────────
Write-Host "[2/4] Pre-downloading media_kit Android JARs..." -ForegroundColor Yellow

$mkJarsDir = "crates\rcrm-gui\build\media_kit_libs_android_video\v1.1.7"
New-Item -ItemType Directory -Force $mkJarsDir | Out-Null

$mkJars = @(
    "default-arm64-v8a.jar",
    "default-armeabi-v7a.jar",
    "default-x86_64.jar",
    "default-x86.jar"
)

$baseUrl = "https://github.com/media-kit/libmpv-android-video-build/releases/download/v1.1.7"

foreach ($j in $mkJars) {
    $dest = "$mkJarsDir\$j"
    if (-not (Test-Path $dest) -or (Get-Item $dest).Length -eq 0) {
        Write-Host "  Downloading $j..." -ForegroundColor Gray
        try {
            Invoke-WebRequest -Uri "$baseUrl/$j" -OutFile $dest -UseBasicParsing
            Write-Host "  $j [OK]" -ForegroundColor Green
        } catch {
            Write-Host "  ERROR: Failed to download $j --- $_" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "  $j [cached]" -ForegroundColor Gray
    }
}

Write-Host ""

# ── Step 3: Flutter pub get ────────────────────────────────────
Write-Host "[3/4] Resolving Flutter dependencies..." -ForegroundColor Yellow
Push-Location crates\rcrm-gui
flutter pub get
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: flutter pub get failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location
Write-Host ""

# ── Step 4: Flutter build APK ──────────────────────────────────
Write-Host "[4/4] Building Flutter APK ($flutterMode)..." -ForegroundColor Yellow
Push-Location crates\rcrm-gui

if ($SplitAbi) {
    flutter build apk --$flutterMode --split-per-abi
} else {
    flutter build apk --$flutterMode
}

$buildOk = $LASTEXITCODE -eq 0
Pop-Location

if ($buildOk) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " BUILD SUCCESSFUL" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " APK(s) in: crates\rcrm-gui\build\app\outputs\flutter-apk\" -ForegroundColor Green
    Get-ChildItem "crates\rcrm-gui\build\app\outputs\flutter-apk\*.apk" | ForEach-Object {
        Write-Host "  -> $($_.Name) ($('{0:N1} MB' -f ($_.Length / 1MB)))" -ForegroundColor Green
    }
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host " BUILD FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}
