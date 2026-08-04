# Building RCrm

## Version Matrix (MUST MATCH)

Changing any version independently WILL break the build. All components are interlocked.

| Component | Version | Verified | File |
|-----------|---------|----------|------|
| Flutter SDK | **3.44.2** | ✅ | `flutter --version` |
| Gradle | **9.1.0** | ✅ | `android/gradle/wrapper/gradle-wrapper.properties` |
| AGP | **9.0.1** | ✅ | `android/settings.gradle.kts` |
| Kotlin | **2.3.20** | ✅ | `android/settings.gradle.kts` |
| NDK | **28.2.13676358** | ✅ | `$env:ANDROID_NDK_HOME` |
| Compile SDK | **36** | ✅ | `android/app/build.gradle.kts` |
| Min SDK | **24** | ✅ | `android/app/build.gradle.kts` |
| Rust | stable (current) | ✅ | `rustup show` |
| MSVC | VS 2022 Build Tools v18 | ✅ | Visual Studio Installer |
| ffmpeg | MSYS2 ucrt64 (system PATH) | ✅ | `ffmpeg -version` |
| file_picker | 10.3.10 resolved (Android) | ✅ | `pubspec.lock` |

**If Gradle/AGP/Kotlin must be upgraded:**

1. Match the version groups in `D:\Dev\flutter\packages\flutter_tools\lib\src\android\gradle_utils.dart`
2. Update all three (Gradle, AGP, Kotlin) simultaneously
3. The Flutter SDK included build must be compatible (see `D:\Dev\flutter\packages\flutter_tools\gradle\build.gradle.kts`)
4. `checkAarMetadata` must be removed from `android/build.gradle.kts` (AGP 9.0 incompatible)

## Prerequisites

### All Platforms

- Flutter 3.44.2 with desktop + Android support
- Rust stable toolchain: `rustup toolchain install stable`
- ffmpeg in PATH (thumbnails/previews)

### Windows

- MSVC Build Tools (Visual Studio 2022) with C++ workload
- OpenSSL dev libraries (for Rust TLS)

### Android

- Android SDK with NDK 28.2.13676358 exactly: `sdkmanager "ndk;28.2.13676358"`
- Rust Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`
- `cargo-ndk`: `cargo install cargo-ndk`

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

## Test & Analyze

```bash
# From crates/rcrm-gui/
flutter analyze lib                          # ZERO warnings enforced

# MUST use `flutter test` — plain `dart test` fails to load the suite
# (the app imports Flutter packages, which import dart:ui, unavailable
# on the bare Dart VM).
flutter test test/rcrm_gui_test.dart         # unit tests (23)
flutter test test/widget_test.dart           # widget smoke test

# From repo root
cargo test
cargo clippy --all                           # ZERO warnings enforced
```

## Troubleshooting

### All Platforms

| Error | Cause | Fix |
|-------|-------|-----|
| `rcrm_flutter_bridge.dll` locked | Process holds bridge | Kill all `rcrm_gui.exe` before rebuild |
| Videos won't play | Missing mpv DLLs | Build script downloads them automatically |
| No thumbnails/previews | ffmpeg not in PATH | `ffmpeg -version` to verify |
| Missing DLLs at runtime | DLL copy step failed | Re-run build or manually copy DLLs to runner dir |

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
