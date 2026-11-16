# build_ios.ps1
# Full iOS build pipeline: Rust static lib -> Flutter .app
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   Xcode + CocoaPods installed
#   Must be run on macOS (cargo target aarch64-apple-ios only works there)
# Usage:
#   .\scripts\build_ios.ps1                 # debug (device; the copied .a is the device build)
#   .\scripts\build_ios.ps1 -Release        # release (device)
#   .\scripts\build_ios.ps1 -Release -NoSign # release without codesign
#   .\scripts\build_ios.ps1 -MobileDecode   # on by default; kept for symmetry
param(
    [switch]$Release,
    [switch]$NoSign,  # Skip code signing
    [switch]$MobileDecode = $true   # AVIF/JXL/HEIC software decode
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

# zxing-cpp's bundled CMake build needs the iOS platform stated explicitly (a
# toolchain file turns off cmake-rs's own cross-compile defaults, by design).
$env:CMAKE_TOOLCHAIN_FILE_aarch64_apple_ios = "$root\scripts\cmake\ios-device.cmake"
$env:CMAKE_TOOLCHAIN_FILE_aarch64_apple_ios_sim = "$root\scripts\cmake\ios-sim.cmake"

$cargoArgs = @("build", "--release", "-p", "rcrm-flutter-bridge")
# libmpv-poster is required on iOS too: media_kit ships libmpv as an embedded,
# code-signed `Mpv.framework/Mpv` (a real MH_DYLIB), which the poster client
# opens by name. Without the feature there is no poster renderer at all.
$features = @("libmpv-poster")
if ($MobileDecode) { $features += "mobile-decode" }
if ($features.Count -gt 0) {
    $cargoArgs += @("--features", ($features -join ","))
}

$deviceArgs = $cargoArgs + @("--target", "aarch64-apple-ios")
& cargo @deviceArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust iOS device build failed!" -ForegroundColor Red
    Pop-Location; exit 1
}
Write-Host "  -> librcrm_flutter_bridge.a (device)" -ForegroundColor Green

$simArgs = $cargoArgs + @("--target", "aarch64-apple-ios-sim")
& cargo @simArgs 2>$null
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

# ── Step 3: libmpv frameworks (SPM-aware) ──────────────────────
Write-Host "[3/4] Preparing media_kit's libmpv frameworks..." -ForegroundColor Yellow
# Locate the plugin through pub's package_config (version/mirror agnostic). The
# old step wrote into ios/.symlinks, which CocoaPods recreates from scratch, so
# its pre-download was thrown away.
$pluginDir = $null
$pkgConfig = "$gui\.dart_tool\package_config.json"
if (Test-Path $pkgConfig) {
    try {
        $cfg = Get-Content $pkgConfig -Raw | ConvertFrom-Json
        $pkg = $cfg.packages | Where-Object { $_.name -eq 'media_kit_libs_ios_video' } | Select-Object -First 1
        if ($pkg) {
            $pluginDir = ([System.Uri]([string]$pkg.rootUri)).LocalPath.TrimEnd('\', '/')
        }
    } catch {
        $pluginDir = $null
    }
}

if (-not $pluginDir) {
    Write-Host "  WARNING: media_kit_libs_ios_video is not in .dart_tool/package_config.json" -ForegroundColor Yellow
    Write-Host "           (run 'flutter pub get'); leaving the download to the build" -ForegroundColor Yellow
} elseif ((Test-Path "$pluginDir\ios\media_kit_libs_ios_video\Package.swift") -or
          (Test-Path "$pluginDir\ios\Package.swift")) {
    # SPM: the package declares the xcframeworks as REMOTE binary targets, and
    # Flutter prefetches them with 'xcodebuild -resolvePackageDependencies'.
    # Xcode owns the download and its artifact cache.
    Write-Host "  SPM package: binary targets are downloaded by Xcode/SwiftPM" -ForegroundColor Green
} else {
    # CocoaPods path (media_kit_libs_ios_video 1.1.4 ships only a podspec): its
    # podspec runs the Makefile during pod install, and that Makefile downloads
    # into this cache and verifies sha256. Pre-seed the SAME file/hash so a
    # blocked GitHub fails here with a readable message.
    $makefile = "$pluginDir\ios\Makefile"
    $libmpvVer = $null
    $libmpvSha = $null
    if (Test-Path $makefile) {
        foreach ($line in Get-Content $makefile) {
            if ($line -match '^MPV_XCFRAMEWORKS_VERSION=(.+)$') { $libmpvVer = $Matches[1].Trim() }
            if ($line -match '^MPV_XCFRAMEWORKS_SHA256SUM=(.+)$') { $libmpvSha = $Matches[1].Trim() }
        }
    }
    if (-not $libmpvVer -or -not $libmpvSha) {
        Write-Host "  WARNING: no SPM manifest and no usable Makefile; skipping pre-download" -ForegroundColor Yellow
    } else {
        $cacheDir = "$pluginDir\ios\.cache\xcframeworks"
        $libmpvFile = "libmpv-xcframeworks-$libmpvVer-ios-universal.tar.gz"
        $libmpvUrl = "https://github.com/media-kit/libmpv-darwin-build/releases/download/$libmpvVer/libmpv-xcframeworks_$($libmpvVer)_ios-universal-video-default.tar.gz"
        $tarball = "$cacheDir\$libmpvFile"
        try { New-Item -ItemType Directory -Force $cacheDir | Out-Null } catch { }
        if (-not (Test-Path $cacheDir)) {
            Write-Host "  WARNING: cannot write $cacheDir; leaving the download to pod install" -ForegroundColor Yellow
        } elseif ((Test-Path $tarball) -and
                  ((Get-FileHash -Algorithm SHA256 -LiteralPath $tarball).Hash.ToLower() -eq $libmpvSha)) {
            Write-Host "  libmpv xcframework [cached, sha256 ok]" -ForegroundColor Gray
        } else {
            Remove-Item -Force -ErrorAction SilentlyContinue $tarball, "$tarball.tmp"
            Write-Host "  Downloading libmpv xcframework ($libmpvVer)..." -ForegroundColor Gray
            $source = $null
            try {
                Invoke-WebRequest -Uri $libmpvUrl -OutFile "$tarball.tmp" -UseBasicParsing
                $source = "github"
            } catch {
                Write-Host "  GitHub direct failed, retrying via gh-proxy..." -ForegroundColor Yellow
                try {
                    Invoke-WebRequest -Uri "https://gh-proxy.org/$libmpvUrl" -OutFile "$tarball.tmp" -UseBasicParsing
                    $source = "gh-proxy"
                } catch { $source = $null }
            }
            if (-not $source) {
                Remove-Item -Force -ErrorAction SilentlyContinue "$tarball.tmp"
                Write-Host "  ERROR: could not download $libmpvUrl" -ForegroundColor Red
                Write-Host "         Fetch it by hand into: $tarball" -ForegroundColor Red
                exit 1
            }
            $got = (Get-FileHash -Algorithm SHA256 -LiteralPath "$tarball.tmp").Hash.ToLower()
            if ($got -ne $libmpvSha) {
                Remove-Item -Force -ErrorAction SilentlyContinue "$tarball.tmp"
                Write-Host "  ERROR: $source tarball sha256 does not match the Makefile's $libmpvSha" -ForegroundColor Red
                exit 1
            }
            Move-Item -Force "$tarball.tmp" $tarball
            Write-Host "  libmpv xcframework [OK, $source, sha256 ok]" -ForegroundColor Green
        }
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
    # The poster renderer opens Mpv.framework at runtime and has no fallback.
    $app = "$gui\build\ios\iphoneos\Runner.app"
    if (Test-Path "$app\Frameworks\Mpv.framework\Mpv") {
        Write-Host "  -> Mpv.framework embedded (poster renderer)" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Mpv.framework is not in Runner.app/Frameworks; posters will be unavailable" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " BUILD SUCCESSFUL" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  App: $app" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host " BUILD FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}
