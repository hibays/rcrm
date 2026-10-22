# build_android.ps1
# Full Android build pipeline: Rust .so for 3 ABIs → Flutter APK
# Prerequisites:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
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

# RUSTC_BOOTSTRAP=rav1d: unlock only the stdarch_arm_feature_detection
# nightly gate that rav1d's ARM asm needs on armv7. MUST be identical in
# every build script: cargo folds RUSTC_BOOTSTRAP into the fingerprint
# config hash, so a mismatch between scripts forces a full rebuild.
$env:RUSTC_BOOTSTRAP = "rav1d"

# ── zxing-cpp (C++ through its official Rust wrapper) ──────────
# The wrapper's `bundled` build compiles the C++ core with CMake; cmake-rs
# picks a toolchain file per Rust target, so each ABI has its own shim (the NDK
# toolchain needs ANDROID_ABI before it is included). Ninja is required on
# Windows: the NDK toolchain file does not support Visual Studio generators.
$cmakeShims = Join-Path $root "scripts/cmake"
$env:CMAKE_GENERATOR = "Ninja"
$env:CMAKE_TOOLCHAIN_FILE_aarch64_linux_android = Join-Path $cmakeShims "android-arm64-v8a.cmake"
$env:CMAKE_TOOLCHAIN_FILE_armv7_linux_androideabi = Join-Path $cmakeShims "android-armeabi-v7a.cmake"
$env:CMAKE_TOOLCHAIN_FILE_x86_64_linux_android = Join-Path $cmakeShims "android-x86_64.cmake"

# zxing-cpp is C++. The wrapper links `-lstdc++`, which on Android resolves to
# the NDK's small compatibility stub rather than the C++ runtime, so the real
# one is linked here — statically, so the APK does not need libc++_shared.so.
# Target-scoped rustflags keep the host-side build scripts clean (a global -l
# would be passed to every host proc-macro link too).
$libcxxFlags = "-C link-arg=-lc++_static -C link-arg=-lc++abi -C link-arg=-lunwind"

# The NDK ships BOTH a legacy `libstdc++.so` stub (API-level dir, found first by
# default) and a static `libstdc++.a` (ABI dir). A search dir holding ONLY the
# static stub makes the wrapper's `-lstdc++` resolve to it, without also
# changing how `-lc`/`-lm` resolve (pointing at the whole ABI dir would link
# static libc and break armv7's versioned __aeabi_* symbols).
#
# RUSTFLAGS are split on whitespace, so the path is used unquoted: keep the
# checkout path free of spaces.
$llvmPrebuilt = Get-ChildItem (Join-Path $env:ANDROID_NDK_HOME "toolchains\llvm\prebuilt") -Directory | Select-Object -First 1
$ndkLibDir = Join-Path $llvmPrebuilt.FullName "sysroot\usr\lib"
$stdcxxRoot = Join-Path $root "target\android-stdcxx"
foreach ($v in @(
        @{ dir = "arm64-v8a"; triple = "aarch64-linux-android" },
        @{ dir = "armeabi-v7a"; triple = "arm-linux-androideabi" },
        @{ dir = "x86_64"; triple = "x86_64-linux-android" })) {
    $d = Join-Path $stdcxxRoot $v.dir
    New-Item -ItemType Directory -Force $d | Out-Null
    Copy-Item (Join-Path $ndkLibDir "$($v.triple)\libstdc++.a") (Join-Path $d "libstdc++.a") -Force
}
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS = "-L native=$(Join-Path $stdcxxRoot 'arm64-v8a') $libcxxFlags"
$env:CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS = "-L native=$(Join-Path $stdcxxRoot 'armeabi-v7a') $libcxxFlags"
$env:CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS = "-L native=$(Join-Path $stdcxxRoot 'x86_64') $libcxxFlags"

cargo ndk `
    --target aarch64-linux-android `
    --target armv7-linux-androideabi `
    --target x86_64-linux-android `
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

# The freshly rebuilt bridge has different contents from the last build, while
# Gradle keeps state snapshots for the jniLibs merges. Two things can then go
# wrong, and this reset prevents both:
#
#   * mergeReleaseJniLibFolders fails to hash its stale output --
#     "Cannot access output property 'outputDir' ... Failed to create MD5 hash
#     for file '...merged_jni_libs\release\...\librcrm_flutter_bridge.so' as it
#     does not exist" -- and takes the whole APK build down with it;
#   * worse, silently: mergeReleaseNativeLibs and packageRelease stay UP-TO-DATE
#     against a stale merge, the build reports SUCCESS, and the APK ships WITHOUT
#     libapp.so and librcrm_flutter_bridge.so (a 25MB APK instead of 42MB), so the
#     app cannot load the bridge at all.
#
# Dropping both merge outputs makes them re-run from a clean slate; Gradle's
# incremental tracking stays intact everywhere else. (doNotTrackState is NOT the
# fix: the packaging task then fails with "Changes are not tracked, unable
# determine incremental changes".)
foreach ($staleMerge in @(
        "crates\rcrm-gui\build\app\intermediates\merged_jni_libs",
        "crates\rcrm-gui\build\app\intermediates\merged_native_libs")) {
    if (Test-Path $staleMerge) {
        Remove-Item -Recurse -Force $staleMerge
        Write-Host "  -> Reset Gradle state: $staleMerge" -ForegroundColor Gray
    }
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
# GitHub is unreliable from CN networks; fall back to the gh-proxy mirror
# (same content, MD5-verified by media_kit at build time).
$mirrorBaseUrl = "https://gh-proxy.org/$baseUrl"

foreach ($j in $mkJars) {
    $dest = "$mkJarsDir\$j"
    if (-not (Test-Path $dest) -or (Get-Item $dest).Length -eq 0) {
        Write-Host "  Downloading $j..." -ForegroundColor Gray
        try {
            Invoke-WebRequest -Uri "$baseUrl/$j" -OutFile $dest -UseBasicParsing
            Write-Host "  $j [OK]" -ForegroundColor Green
        } catch {
            Write-Host "  GitHub direct failed ($_), retrying via gh-proxy..." -ForegroundColor Yellow
            try {
                Invoke-WebRequest -Uri "$mirrorBaseUrl/$j" -OutFile $dest -UseBasicParsing
                Write-Host "  $j [OK via mirror]" -ForegroundColor Green
            } catch {
                Write-Host "  ERROR: Failed to download $j --- $_" -ForegroundColor Red
                exit 1
            }
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
