# Building RCrm

## Version Matrix (MUST MATCH)

Move the Android toolchain versions together; verify a release APK, not just `gradlew help`.

| Component | Version | Verified | File |
|-----------|---------|----------|------|
| Flutter SDK | **3.50.0** — pinned by `pubspec.yaml` (`flutter: ">=3.50.0"`) | ✅ analyze/test | `flutter --version` |
| Dart SDK | **3.14.0** (ships with the above; `sdk: ">=3.14.0 <4.0.0"`) | ✅ | `dart --version` |
| Rust | stable ≥ **1.89** | ✅ | `rustup show` — `heic` requires 1.89, edition 2024 everywhere |
| Gradle | **9.9.1** | ✅ release APK | `android/gradle/wrapper/gradle-wrapper.properties` |
| AGP | **9.3.1** | ✅ release APK | `android/settings.gradle.kts` |
| Kotlin (KGP) | **2.4.21** | ✅ release APK | `android/settings.gradle.kts` |
| NDK | **28.2.13676358** | ✅ | `$env:ANDROID_NDK_HOME` |
| Compile SDK | **36** | ✅ | `android/app/build.gradle.kts` |
| Min SDK | **24** | ✅ | `android/app/build.gradle.kts` |
| MSVC | VS 2022 Build Tools v18 | ✅ | Visual Studio Installer |
| libmpv (posters) | the build media_kit already ships (0.36+) | ✅ | §libmpv-2.dll§ / §libmpv.so.2§ / §libmpv.dylib§ beside the app |
| file_picker | 13.1.0 resolved (Android APK + Windows exe built) | ✅ | `pubspec.lock` |
| `rav1d` (git) | rev `9f00b03b…` | ✅ | `crates/rcrm-flutter-bridge/Cargo.toml` |
| `heic` (git) | rev `db52055b…` | ✅ | `crates/rcrm-flutter-bridge/Cargo.toml` |
| `zxing-cpp` | wrapper **0.5.3** (C++ **3.1.1**, `bundled`) | ✅ host + Android | `crates/rcrm-flutter-bridge/Cargo.toml` |
| CMake / Ninja | CMake **≥ 3.21**; Ninja **required** for Windows→Android | ✅ 4.4.4 / 1.13.2 | `cmake --version`, `ninja --version` |

**`file_picker` 13.x and our AGP 9 flags.** The Android build runs with
`android.newDsl=false` + `android.builtInKotlin=false` (both written by the Flutter template), so
every Android plugin has to cope with Kotlin being applied on its behalf. 13.x does: its Android
module declares its own buildscript classpath and applies KGP only when built-in Kotlin is off, and
the Windows implementation is Dart-only (`windows_file_picker`, `win32` FFI), so it needs no native
module. The 11.x line was unusable here — its Android build applied KGP in a way the
then-current Kotlin 2.3.20 rejected. The 12.0 federated rewrite also split the plugin into per-platform packages
(`android_file_picker`, `windows_file_picker`, `file_picker_darwin/linux/web`) and made the API
**static**: `FilePicker.getDirectoryPath()`, never `FilePicker.platform.*` (that accessor is gone,
not deprecated). With this set (file_picker 13.1.0, package_info_plus 10.2.2, wakelock_plus 1.8.1)
**no Android plugin declares KGP any more**, so Flutter's "plugins that apply Kotlin Gradle Plugin —
future versions of Flutter will fail to build" warning no longer appears.

**Flutter 3.50's Android floors.** Thresholds live in
`DependencyVersionChecker.kt`; `checkDependencyVersions` checks lower bounds
only, so crossing the warn threshold silences `will soon be dropped`:

| Check | Error | Warn | Current |
|---|---|---|---|
| Gradle | 9.3.1 | 9.5.0 | **9.9.1** |
| AGP | 9.1.1 | 9.3.1 | **9.3.1** |
| KGP | 2.4.10 | 2.4.20 | **2.4.21** |
| Java | 17 | 17 | 17 |
| minSdk | 23 | 24 | 24 |

On 2026-11-13 the set moved from 9.3.1 / 9.1.1 / 2.4.10 to
**9.9.1 / 9.3.1 / 2.4.21** in one step; all three version warnings are gone.
AGP 9.3.1 is the 3.50 template default and the top of KGP 2.4.20–2.4.21's
fully-supported AGP range (8.5.2–9.3.1); AGP 9.5.0 was skipped (two minors
past the Flutter included build's `compileOnly` AGP 9.1.1 / KGP 2.4.10).
Kotlin fully supports Gradle ≤ 9.7.0 for those KGP versions and allows newer
Gradle with deprecation warnings. The Tencent Gradle zip and Aliyun AGP/KGP POMs were verified HTTP
200. All three steps were verified with full `flutter build apk --release`
builds (125.7MB), not just `gradlew help`.

`flutter analyze --suggestions` still prints one
`Incompatible Gradle/AGP versions` line: `validateGradleAndAgp` caps AGP 9.3.x
at Gradle 9.5.0. That validator feeds only the suggestions report (SDK: "does
not imply broader Flutter support"); `flutter analyze lib test` and the APK
build are green.
KGP 2.4.21 also removes the `Incompatible KGP/Gradle versions` line that
2.4.20 produced, because `validateGradleAndKGP` treats any KGP strictly newer
than `maxKnownAndSupportedKgpVersion = 2.4.20` as valid — diagnostic only,
2.4.20 and 2.4.21 share the same real compatibility band. Never use
`--android-skip-build-dependency-validation`.

**Upgrading again:** move all three together (AGP 9.1 → Gradle 9.3.1, 9.2 →
9.4.1, 9.3 → 9.5.0, 9.4/9.5 → 9.6.0); check Kotlin's
`gradle-configure-project.html` table for the KGP band, keep the Flutter
included build's `compileOnly` versions in mind, and pre-check the Tencent
Gradle zip / Aliyun AGP+KGP POMs. `injectGradleWrapperIfNeeded` only writes
`gradle-wrapper.properties` when missing, so our mirror URL is safe.

### Configuration-time warnings under Flutter 3.50 (expected; don't "fix" the flags)

On 9.9.1 / 9.3.1 / 2.4.21 the three version warnings are gone.
`./gradlew help --no-daemon` still ends `BUILD SUCCESSFUL in 1m 9s` with
non-fatal warnings that no version bump will remove:

| Message | Source | Why |
|---|---|---|
| `android.builtInKotlin=false` / `android.newDsl=false` deprecated; `applicationVariants` / `testVariants` / `unitTestVariants` / `libraryVariants` obsolete | AGP 9.3.1 | **Flutter 3.50's template writes both flags as `false`**; the Variant API warnings are new in 9.3.1. Both belong to the unfinished upstream migration (flutter/flutter#180137). |
| `org.jetbrains.kotlin.android` no longer required | KGP | Template still declares the separate plugin; `isBuiltInKotlinEnabled` reads `false`, so Flutter keeps validating it too. |
| `w:` lines, `Deprecated Gradle features … incompatible with Gradle 10`, javac `source/target value 8 is obsolete` | Gradle 9.9 / plugins | Gradle 9.9 recompiles all Kotlin DSL scripts; the APK build adds javac warnings. |

Keep the template flags: `android_file_picker` 2.1.6 still pins an AGP 8.5.2 /
KGP 1.8.22 classpath for `android.newDsl=false`, and a green `help` does not
compile Kotlin. Historically (on 9.3.1 / 9.1.1 / 2.4.10) overriding
`-Pandroid.builtInKotlin=true -Pandroid.newDsl=true` silenced four warnings in
45s but only configures; that set's `will soon be dropped` message came from
`getWarnMessage` sharing `getErrorMessage`'s template, so its bypass flag and
"Potential fix" were boilerplate. The only known cost of the current set is the
single `--suggestions` diagnostic described above.

## Prerequisites

### All Platforms

- Flutter **≥ 3.50.0** with desktop + Android support. The Material library now
  lives in the official `material_ui` package; `package:flutter/material.dart`
  is deprecated, so every Dart file imports `package:material_ui/material_ui.dart`
  (migrated with `dart fix --apply`). Do not add new `flutter/material.dart` imports.
- Rust stable ≥ 1.89: `rustup toolchain install stable`
- **CMake ≥ 3.21 and a C++ toolchain**: QR encode/decode is the C++ zxing-cpp,
  built by its official Rust wrapper (`zxing-cpp`, feature `bundled`). Desktop
  builds use the host compiler; Android and iOS add the toolchain shims in
  `scripts/cmake/` (the build scripts set them).
- Two **git** dependencies are fetched on first build: `rav1d` (AVIF) and `heic`
  (HEIC/HEIF), both behind the `mobile-decode` feature. On a restricted network
  add mirror entries to the local, gitignored `.cargo/config.toml` the way
  `rav1d` is already redirected there.

### Windows

- MSVC Build Tools (Visual Studio 2022) with C++ workload
- CMake and Ninja on PATH (the bundled zxing-cpp build; Ninja is also what the
  NDK toolchain needs for the Android cross-build)
- OpenSSL dev libraries (for Rust TLS)

### Android

- Android SDK with NDK 28.2.13676358 exactly: `sdkmanager "ndk;28.2.13676358"`
- Rust Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`
- `cargo-ndk`: `cargo install cargo-ndk`
- CMake + Ninja on PATH. The script points cmake-rs at the per-ABI shims in
  `scripts/cmake/` and adds the static C++ runtime link flags itself — a manual
  `cargo ndk` invocation has to do the same (see the script).
- **`libmpv-poster`** (libmpv renders the poster itself) is enabled by every
  platform's script, INCLUDING iOS: media_kit ships libmpv there as an
  embedded, code-signed `Mpv.framework/Mpv` — a real, dynamic Mach-O framework
  (`MH_DYLIB`) that `libmpv.rs` opens by name. iOS forbids executable code from
  outside the signed bundle, not the bundle's own frameworks. There is no
  screenshot poster encoder and no fallback backend any more.
  `mobile-decode` (AVIF + JXL + HEIC software decoding) is independent of it.
  The desktop scripts accept `-MobileDecode` / `--mobile-decode` for local
  testing only. `heic` is a pure-Rust HEVC decoder
  (`backend-rust`), chosen so no platform SDK is involved and
  cross-compilation keeps working; it is AGPL-3.0-only-or-commercial and
  HEVC/HEIF is patent-encumbered, so read its notices before shipping a build.

### Linux

- §sudo apt install libgtk-3-dev libmpv-dev§ (the poster renderer loads the
  same libmpv the player does)

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

# Optional: include the mobile software decoders for local testing
.\scripts\build_windows.ps1 -Release -MobileDecode
# (libmpv-poster is always on here: posters are rendered by libmpv itself)
```

Pipeline: cargo build `--release` `-p rcrm-flutter-bridge` (with `RUSTFLAGS=-C target-cpu=native`) → download mpv-dev + ANGLE DLLs → `flutter build windows` → copy DLLs + app.so + flutter_assets to runner output.

### Android

```powershell
$env:ANDROID_NDK_HOME = "D:\Dev\Android\Sdk\ndk\28.2.13676358"
# mobile-decode (AVIF/JXL/HEIC) and libmpv-poster are on by default
.\scripts\build_android.ps1 -Release -SplitAbi
```

Pipeline: `cargo-ndk` for 3 ABIs (aarch64, armv7, x86_64; zxing-cpp's C++ core is compiled per ABI by CMake with the `scripts/cmake/android-*.cmake` shims) → download libmpv Android JARs → `flutter build apk --split-per-abi`. Output: `build/app/outputs/flutter-apk/app-*-release.apk`.

### Linux

```bash
./scripts/build_linux.sh -r
# Optional: add --mobile-decode for the AVIF/JXL/HEIC Rust decoders.
# libmpv-poster (posters rendered by libmpv itself) is always on.
# Output: build/linux/x64/{debug,release}/bundle/rcrm_gui
```

### macOS

```bash
./scripts/build_macos.sh -r
# Optional: add --mobile-decode for the AVIF/JXL/HEIC Rust decoders.
# libmpv-poster (posters rendered by libmpv itself) is always on.
# Output: build/macos/Build/Products/{Debug,Release}/rcrm_gui.app
```

### iOS

```bash
# mobile-decode (AVIF/JXL/HEIC) and libmpv-poster are enabled by default.
# The poster renderer opens media_kit's embedded `Mpv.framework/Mpv` (a dynamic,
# code-signed framework in the app bundle) — the same library the player uses.
./scripts/build_ios.sh -r --no-codesign
# Output: build/ios/iphoneos/Runner.app
```

The libmpv frameworks come from media_kit's iOS package, and the build script
detects how that package is integrated. With a Swift Package
(`ios/<name>/Package.swift`) the xcframeworks are **remote binary targets**:
Xcode/SwiftPM resolves and downloads them itself (Flutter prefetches them with
`xcodebuild -resolvePackageDependencies`), and the script does not download
anything. With the CocoaPods-only package `media_kit_libs_ios_video 1.1.4`
(today's pinned version; it ships a podspec and a Makefile, no `Package.swift`)
the Makefile downloads them during `pod install`, so the script pre-seeds that
**same** cache file using the version and sha256 parsed from the Makefile
(GitHub first, then the gh-proxy mirror). A mismatched or truncated tarball is
rejected before `pod install` sees it. The old step wrote into
`ios/.symlinks/...` — a tree CocoaPods owns and rewrites — so the file it
placed there was not the one the Makefile later looked for.

The iOS bridge is a static library and contains zxing-cpp's C++ objects. The
Runner target therefore links it with `-force_load` (NOT a plain “Link Binary
With Libraries” entry): the `rcrm_*` exports are reached at runtime through
`DynamicLibrary.process()` (`dlsym`), so native code references none of them and
the linker would archive every object away. `OTHER_LDFLAGS` in
`ios/Runner.xcodeproj/project.pbxproj` carries:

```
"-lc++",
"-force_load", "$(SRCROOT)/Runner/librcrm_flutter_bridge.a"
```

The `.a` is copied into `ios/Runner/` by the build script before Xcode runs; a
build that skips the script fails the link with a missing-file error rather than
shipping a bridge with no symbols. This has not been verified on a Mac (the iOS
toolchain shims are in `scripts/cmake/`).

## Brand assets / app icons

All platform icons are generated from the artwork in `brands/design/` — the
Flutter template's icons are gone, so this is the only place an icon is edited:

```bash
python brands/build_icons.py            # every platform + the README banner
python brands/build_icons.py --only android,windows
```

Requires Python 3.9+ and ffmpeg; the SVG is rasterised by ffmpeg's `librsvg`
decoder (or `rsvg-convert` when that build lacks it), and every size is a
lossless ffmpeg scale of one 4096px master. It writes Android legacy + adaptive +
monochrome, iOS, macOS, the Windows `.ico`, the Linux window icon and
`brands/out/`. See `brands/README.md` for the design rules and for what to
commit after switching the logo.

The Linux icon is loaded at runtime by `linux/runner/my_application.cc` from
`<bundle>/data/app_icon.png` (installed by `linux/CMakeLists.txt`), because GTK
wants a file path rather than a Flutter asset.

## Known toolchain issues

Three environment-level changes bite builds even though the source is unchanged.
None is a code bug in this repo; all were reproduced and diagnosed locally.

### libmpv posters verify TLS peers (and why the generator opts out)

The poster renderer makes its own HTTPS request to the app's server, which
presents a **self-signed, ephemeral** certificate that the Dart client pins
(§net.dart§). libmpv cannot know about that pin, so `rcrm_generate_poster_async`
sets `tls-verify=no` for its one client — the same scoped relaxation the removed
ffmpeg poster command made, and nothing else in the app relaxes TLS. The player
keeps its own settings.

The alternatives, if that posture is ever revisited:

1. Route the renderer through a loopback relay that performs the pinned HTTPS
   upstream (what the cast receiver's proxy already does).
2. Give the server a file-backed certificate and point libmpv at it with
   `--ca-file` (the ephemeral certificate only covers `localhost`/`127.0.0.1`).
3. Keep `tls-verify=no` (the status quo: the Rust side accepts any certificate
   for this one fetch; the Dart side still pins everything else).

Note for anyone porting the old ffmpeg knowledge: ffmpeg ≥ 9 flipped
`tls_verify` to 1 and its `-tls_verify` flag was an input option *of the tls
protocol*, so it had to be conditional on `https://`. libmpv's `tls-verify` is a
plain network option and is safe to set unconditionally — there is no per-protocol
name resolution to trip over.

### Flutter 3.47+ (including 3.50) keeps Impeller as the default desktop renderer

Impeller's image decoder (`ImageDecoderImpeller`) handles PNG/JPEG/WebP/GIF/BMP
but has **no WIC fallback**, so on Windows AVIF/JXL/HEIC fail with
`Could not decompress image`. Skia (`ImageDecoderSkia` → Windows WIC codecs, i.e.
the Store's AV1 / JPEG XL / HEIF extensions) decodes them fine, which is why the
regression appeared with the SDK upgrade (3.44.8 → 3.47.x). It is still
assumed present on 3.50.0 — the 3.50 migration verified `flutter analyze`
and the widget suite, but did not re-run a Windows desktop decode check.

- Verify with: `flutter run -d windows --no-enable-impeller` (all formats decode)
- Workarounds: ship the app with Impeller disabled
  (`project.set_impeller_switch(flutter::ImpellerSwitch::Disabled)` in
  `windows/runner/main.cpp`), or decode these formats through the Rust bridge —
  which the **Android** build already does (`mobile-decode`).

### Flutter 3.50 Linux regression: engine exports `_Unwind_*` and breaks C++ exceptions in plugins

Flutter 3.50's Linux engine started exporting `_Unwind_*` symbols. A Linux
plugin that throws and catches C++ exceptions can then fail to unwind and abort
with `SIGABRT`; the reported case is `flutter_secure_storage_linux` starting on
a machine with an unlocked keyring. Flutter 3.47.9 was unaffected. This is an
engine/plugin interaction, **not** an error in our code, and it cannot be
reproduced from this Windows host.

**Audit of the current dependency set** (static source audit of the pub cache,
2026-11-13). `linux/flutter/generated_plugin_registrant.cc` registers exactly
five native Linux plugins: `dynamic_color`, `media_kit_libs_linux`,
`media_kit_video`, `screen_retriever_linux`, `window_manager` 0.5.2. All five
are C-style GTK/GLib plugin code — **zero `try {` / `catch (` in any `linux/`
source**. `flutter_secure_storage` is not in `pubspec.lock`, and
`linux/runner/*.cc` uses no C++ exceptions. **Conclusion: no current exposure**,
so the Linux build is not blocked by this regression today.

Unverified edges: `librcrm_flutter_bridge.so` statically links zxing-cpp
(C++, `bundled`) on desktop too, and `media_kit_libs_linux` ships a prebuilt
libmpv `.so` — neither is covered by a source audit. Whether a QR path throws
across the C++ boundary on Linux must be checked on a real Linux build.

**Guard rule before adding or upgrading any Linux plugin**: grep its `linux/`
tree for C++ `try`/`catch`/`throw`. If present, verify startup under Flutter
3.50 on a Linux branch before merging; a green Windows CI run proves nothing
about unwinding. Do not work around it by disabling exceptions globally.

**Concrete consequence — `window_manager` stays at 0.5.x.** `flutter pub
outdated` reports 0.7.0 available, and 0.7.0 does require Flutter 3.50 / Dart
3.14 (which we now have). It is still held back deliberately:

- 0.6/0.7 removes all per-platform plugin code in favour of
  `nativeapi` + `cnativeapi`, **one C++ core built from source** into the Linux
  app by a Dart build hook. `cnativeapi` 0.6.0 uses `try`/`catch` in roughly 70
  C++ files, including `src/platform/linux/secure_storage_linux.cpp` and every
  C-ABI wrapper. Upgrading would *introduce* exactly the class of plugin this
  regression breaks.
- It is a breaking API rewrite: the 0.5.x API (`windowManager`,
  `WindowListener`, `WindowOptions`) moved to
  `package:window_manager/legacy.dart`, where everything is `@Deprecated` and
  slated for removal — that alone would produce analyzer warnings against our
  zero-warning gate. The new native API uses
  `WindowManager.instance.getCurrent()`, synchronous properties and an event
  stream instead of a listener mixin.
- Extra requirements: `material_ui ^1.11.0`, `nativeapi ^0.6.0`,
  `nativeapi_flutter ^0.6.0`, and GTK 3 / X11 / Xi development headers on Linux
  build machines (our `scripts/build_linux.sh` does not install them).
- `^0.5.2` already excludes 0.6+/0.7+, so `flutter pub upgrade` cannot drag it
  in accidentally.

Migration checklist for when the regression is fixed: (1) prove startup on a
Linux branch; (2) migrate the ~30 call sites in `main.dart`,
`screens/video_player_screen.dart`, `services/window_drag.dart` and
`widgets/desktop_title_bar.dart` to the native API (or accept the legacy bridge
plus explicit ignores); (3) regenerate the plugin registrants and remove the
runner-side `window_manager` setup; (4) re-run the title-bar/fullscreen widget
tests and the visual golden probes.

### zxing-cpp is C++ (CMake), not a Rust crate

The QR reader/writer is zxing-cpp 3.1.1, compiled by the `zxing-cpp` wrapper's
`bundled` feature. Three things bite:

- **Build profile**: cmake-rs maps cargo `opt-level=0` to CMake `Debug`, which
  compiles the C++ against the debug CRT (`/MDd`); Rust always links the release
  CRT, so `cargo test` then fails with `__imp__CrtDbgReport` / `calloc_dbg`.
  The root `Cargo.toml` therefore pins
  `[profile.dev.package.zxing-cpp] opt-level = 3` — the C++ is optimized even in
  dev/test builds, the Rust side stays debug.
- **Android C++ runtime**: the wrapper's build script emits `-lstdc++` for
  every `*-linux*` target. The NDK's `libstdc++.a` is only a compatibility
  stub, so the real runtime is linked by the build scripts through
  target-scoped `-lc++_static -lc++abi -lunwind` rustflags (the shim sets
  `ANDROID_STL=c++_static`). Without them the link ends in hundreds of
  undefined `std::__ndk1::…` symbols. The NDK ALSO ships a legacy
  `libstdc++.so` stub in the API-level directory, which the linker finds
  first and records as a `DT_NEEDED`; the scripts prepend the ABI's sysroot
  directory with `-L native=…` so `-lstdc++` resolves to the static stub
  instead. RUSTFLAGS are whitespace-split, so **the Android SDK/NDK path must
  not contain spaces** (the scripts use it unquoted).
- **Toolchain shims**: the NDK toolchain file needs `ANDROID_ABI` set before it
  is included, and cmake-rs only exposes a per-target toolchain hook. Each ABI
  has a shim in `scripts/cmake/`; iOS has device/simulator shims for the same
  reason. Changes at the CMake level belong in those files, not in the crate.

The `bundled` build compiles readers AND writers (with zint), so a full C++
rebuild happens once per target/profile under `target/<triple>/…/build/`.

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

# The poster renderer is its own feature — must build with no AVIF/JXL/HEIC deps
cargo test -p rcrm-flutter-bridge --features libmpv-poster
cargo clippy -p rcrm-flutter-bridge --features libmpv-poster --all-targets

# The libmpv poster renderer's end-to-end test skips unless a local video is
# named; point it at one to exercise load → seek → render → encode:
$env:RCRM_MPV_POSTER_TEST_VIDEO = "D:\some\video.mp4"
$env:PATH = "$PWD\crates\rcrm-gui\build\windows\x64\libmpv;$env:PATH"
cargo test -p rcrm-flutter-bridge --features libmpv-poster renders_a_poster -- --nocapture
```

### Bridge Build

```bash
# Desktop (no software decoders — Flutter's engine supplies pixels; libmpv
# renders the posters, so the feature is on)
cargo build --release -p rcrm-flutter-bridge --features libmpv-poster
# Output: target/release/rcrm_flutter_bridge.dll (.so/.dylib)

# Android (via cargo-ndk, with the software decoders)
cargo ndk --target aarch64-linux-android --target armv7-linux-androideabi \
  --target x86_64-linux-android \
  -o crates/rcrm-gui/android/app/src/main/jniLibs \
  build -p rcrm-flutter-bridge --features mobile-decode,libmpv-poster --release
```

Cross-compile check without the NDK link step. `check` still runs
zxing-cpp's CMake build, so the per-ABI toolchain shim must be set even though
nothing is linked (the build script sets it; for a one-off command):

```powershell
$env:CMAKE_TOOLCHAIN_FILE_aarch64_linux_android = "$PWD/scripts/cmake/android-arm64-v8a.cmake"
$env:CMAKE_GENERATOR = "Ninja"
RUSTC_BOOTSTRAP=rav1d cargo ndk --target aarch64-linux-android check \
  -p rcrm-flutter-bridge --features mobile-decode,libmpv-poster
```

## Troubleshooting

### All Platforms

| Error | Cause | Fix |
|-------|-------|-----|
| `rcrm_flutter_bridge.dll` locked | Process holds bridge | Kill all `rcrm_gui.exe` before rebuild |
| Videos won't play | Missing mpv DLLs | Build script downloads them automatically |
| No video posters, players fine | libmpv could not be loaded or is too old | Run with Rust log level 3 (`rcrm_set_log_level(3)`) and look for `[poster] libmpv`; there is no fallback renderer, so a load failure means no posters |
| No video posters over **https://** | libmpv verifying the self-signed peer | The renderer already passes `tls-verify=no`; see Known toolchain issues above |
| AVIF/JXL/HEIC broken in the **Windows** app | Impeller is the default desktop renderer | See Known toolchain issues above |
| Missing DLLs at runtime | DLL copy step failed | Re-run build or manually copy DLLs to runner dir |
| Cargo can't fetch `rav1d`/`heic` | Restricted network | Add mirror entries to the local `.cargo/config.toml` |
| `cmake` not found / no C++ compiler | zxing-cpp is C++ | Install CMake ≥ 3.21 + the platform C++ toolchain (MSVC workload on Windows, `build-essential` on Linux) |
| `__imp__CrtDbgReport` / `calloc_dbg` at link | cmake-rs configured the C++ as Debug (/MDd) | Ensure `[profile.dev.package.zxing-cpp] opt-level = 3` is in the root `Cargo.toml` (it is) |
| `undefined symbol: std::__ndk1::…` on Android | C++ runtime not linked | Use `scripts/build_android.*` (adds the static C++ runtime); a manual `cargo ndk` needs the same flags |

### Windows

| Error | Cause | Fix |
|-------|-------|-----|
| MSB3073 INSTALL fails | CMake post-build error | Harmless — `.exe` already built. Build script handles copy |
| Release exe fails to start | `app.so` not copied | Build script now copies it automatically |

### Android

| Error | Cause | Fix |
|-------|-------|-----|
| `Gradle version (9.1.0) is lower than Flutter's minimum supported version of 9.3.1` | Flutter 3.50 raised the Android floors; a 3.44/3.47 template cannot configure | Set Gradle / AGP / KGP to at least 9.3.1 / 9.1.1 / 2.4.10 **together** (current pins: 9.9.1 / 9.3.1 / 2.4.21, see Version Matrix). Do not use `--android-skip-build-dependency-validation` |
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
