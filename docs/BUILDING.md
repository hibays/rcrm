# Building RCrm

## Version Matrix (MUST MATCH)

Changing any version independently WILL break the build. All components are interlocked.

| Component | Version | Verified | File |
|-----------|---------|----------|------|
| Flutter SDK | **3.47.6** (3.44.2 is the last matrix-verified release) | ⚠️ | `flutter --version` |
| Dart SDK | **3.13.5** (ships with the above) | ✅ | `dart --version` |
| Rust | stable ≥ **1.89** | ✅ | `rustup show` — `heic` requires 1.89, edition 2024 everywhere |
| Gradle | **9.1.0** | ✅ | `android/gradle/wrapper/gradle-wrapper.properties` |
| AGP | **9.0.1** | ✅ | `android/settings.gradle.kts` |
| Kotlin | **2.3.20** | ✅ | `android/settings.gradle.kts` |
| NDK | **28.2.13676358** | ✅ | `$env:ANDROID_NDK_HOME` |
| Compile SDK | **36** | ✅ | `android/app/build.gradle.kts` |
| Min SDK | **24** | ✅ | `android/app/build.gradle.kts` |
| MSVC | VS 2022 Build Tools v18 | ✅ | Visual Studio Installer |
| ffmpeg | MSYS2 ucrt64 (system PATH), **9.x** | ⚠️ see Known issues | `ffmpeg -version` |
| file_picker | 10.3.10 resolved (Android) | ✅ | `pubspec.lock` |
| `rav1d` (git) | rev `9f00b03b…` | ✅ | `crates/rcrm-flutter-bridge/Cargo.toml` |
| `heic` (git) | rev `db52055b…` | ✅ | `crates/rcrm-flutter-bridge/Cargo.toml` |

**If Gradle/AGP/Kotlin must be upgraded:**

1. Match the version groups in `D:\Dev\flutter\packages\flutter_tools\lib\src\android\gradle_utils.dart`
2. Update all three (Gradle, AGP, Kotlin) simultaneously
3. The Flutter SDK included build must be compatible (see `D:\Dev\flutter\packages\flutter_tools\gradle\build.gradle.kts`)
4. `checkAarMetadata` must be removed from `android/build.gradle.kts` (AGP 9.0 incompatible)

## Prerequisites

### All Platforms

- Flutter 3.47.x with desktop + Android support
- Rust stable ≥ 1.89: `rustup toolchain install stable`
- ffmpeg in PATH (video posters/previews) — see Known issues for ffmpeg ≥ 9
- Two **git** dependencies are fetched on first build: `rav1d` (AVIF) and `heic`
  (HEIC/HEIF), both behind the `mobile-decode` feature. On a restricted network
  add mirror entries to the local, gitignored `.cargo/config.toml` the way
  `rav1d` is already redirected there.

### Windows

- MSVC Build Tools (Visual Studio 2022) with C++ workload
- OpenSSL dev libraries (for Rust TLS)

### Android

- Android SDK with NDK 28.2.13676358 exactly: `sdkmanager "ndk;28.2.13676358"`
- Rust Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`
- `cargo-ndk`: `cargo install cargo-ndk`
- The mobile bridge build enables `mobile-decode` (AVIF + JXL + HEIC software
  decoding). `heic` is a pure-Rust HEVC decoder (`backend-rust`), chosen so no
  platform SDK is involved and cross-compilation keeps working; it is
  AGPL-3.0-only-or-commercial and HEVC/HEIF is patent-encumbered, so read its
  notices before shipping a build.

### Linux

- `sudo apt install libgtk-3-dev libmpv-dev ffmpeg`

## China Network Setup

If Google/MavenCentral are blocked, the global Gradle init script at `%USERPROFILE%\.gradle\init.gradle` uses Aliyun mirrors:

```groovy
beforeSettings { settings ->
    def rootDir = settings.rootDir.toString()
    if (rootDir.contains("flutter_tools")) return  // don't touch Flutter SDK
}
allprojects { project ->
    def rootDir = project.rootDir.toString()
    if (rootDir.contains("flutter_tools")) return
    project.buildscript {
        repositories {
            maven { url = "https://maven.aliyun.com/repository/public" }
            maven { url = "https://maven.aliyun.com/repository/google" }
            maven { url = "https://maven.aliyun.com/repository/central" }
            maven { url = "https://maven.aliyun.com/repository/gradle-plugin" }
        }
    }
    project.repositories {
        maven { url = "https://maven.aliyun.com/repository/public" }
        maven { url = "https://maven.aliyun.com/repository/google" }
        maven { url = "https://maven.aliyun.com/repository/central" }
        maven { url = "https://maven.aliyun.com/repository/gradle-plugin" }
    }
}
```

**Key rule**: the init script must skip `flutter_tools` paths — the Flutter SDK's own `settings.gradle.kts` uses `google()`/`mavenCentral()` and must be left alone.

Also set `DEFAULT_MAVEN_HOST = "https://storage.flutter-io.cn"` in flutter SDK (`D:\Dev\flutter\packages\flutter_tools\gradle\src\main\kotlin\FlutterPluginConstants.kt`) and run `flutter config --android-studio-dir`.

## Build Commands

### Windows

```powershell
# Release
.\scripts\build_windows.ps1 -Release
# Output: build\windows\x64\runner\Release\rcrm_gui.exe

# Debug
.\scripts\build_windows.ps1
```

Pipeline: cargo build `--release` `-p rcrm-flutter-bridge` (with `RUSTFLAGS=-C target-cpu=native`) → download mpv-dev + ANGLE DLLs → `flutter build windows` → copy DLLs + app.so + flutter_assets to runner output.

### Android

```powershell
$env:ANDROID_NDK_HOME = "D:\Dev\Android\Sdk\ndk\28.2.13676358"
.\scripts\build_android.ps1 -Release -SplitAbi
```

Pipeline: `cargo-ndk` for 3 ABIs (aarch64, armv7, x86_64) → download libmpv Android JARs → `flutter build apk --split-per-abi`. Output: `build/app/outputs/flutter-apk/app-*-release.apk`.

### Linux

```bash
./scripts/build_linux.sh -r
# Output: build/linux/x64/{debug,release}/bundle/rcrm_gui
```

### macOS

```bash
./scripts/build_macos.sh -r
# Output: build/macos/Build/Products/{Debug,Release}/rcrm_gui.app
```

### iOS

```bash
./scripts/build_ios.sh -r --no-codesign
# Output: build/ios/iphoneos/Runner.app
```

## Known toolchain issues

Two environment-level changes bite builds even though the source is unchanged.
Neither is a code bug in this repo; both were reproduced and diagnosed locally.

### ffmpeg ≥ 9 verifies TLS peers by default

FFmpeg 9.0 flipped the `tls_verify` default from `0` to `1`, so any HTTPS
request now validates the certificate. RCrm's HTTPS server uses a **self-signed**
ephemeral certificate (pinned by the app, which ffmpeg has no way to know
about), so video poster generation over HTTPS fails with:

```
[tls @ …] Peer certificate failed verification
Error opening input: I/O error
```

Plain-HTTP (local mode) is unaffected by that default flip. Mobile posters use
`media_kit` and are unaffected. The desktop video-thumbnail path passes
`-hide_banner` on every fetch and `-tls_verify 0` **only for an `https://` URL**
(`lib/utils/ffmpeg_thumb_args.dart`): option 3 below, scoped to that one
subprocess — the Dart client still pins.

The flag has to be conditional. ffmpeg resolves the *name* of an input option
against the protocol the URL selects, after choosing it, and aborts the whole
command when that protocol does not define the name:

```
file:     + -tls_verify 0  →  Option tls_verify not found.   (exit != 0, no output)
http://   + -tls_verify 0  →  Option tls_verify not found.   (exit != 0, no output)
http://   (no flag)        →  exit 0, JPEG
https://  + -tls_verify 0  →  exit 0, JPEG
https://  (no flag)        →  exit -5, Peer certificate failed verification
```

Measured on ffmpeg 9.0.2 with one file served over both schemes. The desktop
app's own server is `http://127.0.0.1:<port>`, so an unconditional flag leaves
*every* poster empty. The alternatives for the HTTPS case remain:

1. Route ffmpeg to a loopback HTTP relay that performs the pinned HTTPS upstream.
2. Pass `-ca_file <pem>` when the server's certificate is file-backed and its
   hostname matches (the ephemeral certificate only covers `localhost`/`127.0.0.1`).
3. Pass `-tls_verify 0` to keep the pre-9 behaviour (the subprocess then accepts
   any certificate; the Dart side still pins).

### Flutter 3.47 makes Impeller the default desktop renderer

Impeller's image decoder (`ImageDecoderImpeller`) handles PNG/JPEG/WebP/GIF/BMP
but has **no WIC fallback**, so on Windows AVIF/JXL/HEIC fail with
`Could not decompress image`. Skia (`ImageDecoderSkia` → Windows WIC codecs, i.e.
the Store's AV1 / JPEG XL / HEIF extensions) decodes them fine, which is why the
regression appeared with the SDK upgrade (3.44.8 → 3.47.x).

- Verify with: `flutter run -d windows --no-enable-impeller` (all formats decode)
- Workarounds: ship the app with Impeller disabled
  (`project.set_impeller_switch(flutter::ImpellerSwitch::Disabled)` in
  `windows/runner/main.cpp`), or decode these formats through the Rust bridge —
  which the **Android** build already does (`mobile-decode`).

## Test & Analyze

```bash
# From crates/rcrm-gui/
flutter analyze lib test                     # ZERO warnings enforced

# MUST use `flutter test` — plain `dart test` fails to load the suite
# (the app imports Flutter packages, which import dart:ui, unavailable
# on the bare Dart VM).
flutter test                                 # the whole suite (~250 tests)
flutter test test/rcrm_gui_test.dart         # just the core unit tests
flutter test test/viewer_zoom_test.dart      # one file, while iterating

# From repo root
cargo test
cargo clippy --all                           # ZERO warnings enforced

# Bridge, including the mobile-only software decoders (AVIF/JXL/HEIC)
cargo test -p rcrm-flutter-bridge --features mobile-decode --release
cargo clippy -p rcrm-flutter-bridge --features mobile-decode --all-targets
```

### Bridge Build

```bash
# Desktop (no software decoders — Flutter's engine supplies pixels)
cargo build --release -p rcrm-flutter-bridge
# Output: target/release/rcrm_flutter_bridge.dll (.so/.dylib)

# Android (via cargo-ndk, with the software decoders)
cargo ndk --target aarch64-linux-android --target armv7-linux-androideabi \
  --target x86_64-linux-android \
  -o crates/rcrm-gui/android/app/src/main/jniLibs \
  build -p rcrm-flutter-bridge --features mobile-decode --release
```

Cross-compile check without the NDK link step:

```bash
RUSTC_BOOTSTRAP=rav1d cargo ndk --target aarch64-linux-android check \
  -p rcrm-flutter-bridge --features mobile-decode
```

## Troubleshooting

### All Platforms

| Error | Cause | Fix |
|-------|-------|-----|
| `rcrm_flutter_bridge.dll` locked | Process holds bridge | Kill all `rcrm_gui.exe` before rebuild |
| Videos won't play | Missing mpv DLLs | Build script downloads them automatically |
| No thumbnails/previews | ffmpeg not in PATH | `ffmpeg -version` to verify |
| No video posters over **https://** | ffmpeg ≥ 9 verifies the self-signed peer | See Known toolchain issues above |
| AVIF/JXL/HEIC broken in the **Windows** app | Impeller is the default desktop renderer | See Known toolchain issues above |
| Missing DLLs at runtime | DLL copy step failed | Re-run build or manually copy DLLs to runner dir |
| Cargo can't fetch `rav1d`/`heic` | Restricted network | Add mirror entries to the local `.cargo/config.toml` |

### Windows

| Error | Cause | Fix |
|-------|-------|-----|
| MSB3073 INSTALL fails | CMake post-build error | Harmless — `.exe` already built. Build script handles copy |
| Release exe fails to start | `app.so` not copied | Build script now copies it automatically |

### Android

| Error | Cause | Fix |
|-------|-------|-----|
| `Error resolving plugin` | Flutter SDK's `google()`/`mavenCentral()` blocked | Global `init.gradle` (see China setup above) |
| `repository 'maven' was added by settings` | Repo config conflict | Remove `allprojects { repositories {} }` or use `RepositoriesMode.PREFER_PROJECT` |
| Silent NDK link failures | Wrong NDK version | Use exactly 28.2.13676358 |
| Gradle download fails | Missing version on mirror | Check mirror URL or use official Gradle site |
| APK hangs at splash | `flutter_vlc_player` installed | Remove from `pubspec.yaml` |

### Bridge Build

```bash
# Desktop
cargo build --release -p rcrm-flutter-bridge
# Output: target/release/rcrm_flutter_bridge.dll (.so/.dylib)

# Android (via cargo-ndk)
cargo ndk --target aarch64-linux-android --target armv7-linux-androideabi \
  --target x86_64-linux-android \
  -o crates/rcrm-gui/android/app/src/main/jniLibs \
  build -p rcrm-flutter-bridge --release
```
