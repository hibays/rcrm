#!/usr/bin/env bash
# build_android.sh
# Full Android build pipeline: Rust .so for 3 ABIs → Flutter APK
# Prerequisites:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME="/path/to/ndk"
# Usage:
#   ./scripts/build_android.sh              # debug
#   ./scripts/build_android.sh -r           # release
#   ./scripts/build_android.sh -r -s        # release + split APKs
set -euo pipefail

MODE="debug"
SPLIT=false
while [[ $# -gt 0 ]]; do case "$1" in
  -r|--release) MODE="release"; shift ;;
  -s|--split)   SPLIT=true; shift ;;
  *) echo "Usage: $0 [-r|--release] [-s|--split]"; exit 1 ;;
esac; done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUI="$ROOT/crates/rcrm-gui"

CARGO_FLAG="--release"
FLUTTER_FLAG="--$MODE"

echo "========================================"
echo " RCrm GUI --- Android Build ($MODE)"
echo "========================================"
echo ""

# ── Step 1: Build Rust for Android ABIs ─────────────────────────
echo "[1/4] Building Rust bridge for Android ($MODE)..."
JNI_LIBS="$GUI/android/app/src/main/jniLibs"
mkdir -p "$JNI_LIBS/arm64-v8a" "$JNI_LIBS/armeabi-v7a" "$JNI_LIBS/x86_64"

# RUSTC_BOOTSTRAP=rav1d: unlock only the stdarch_arm_feature_detection
# nightly gate that rav1d's ARM asm needs on armv7. MUST be identical in
# every build script: cargo folds RUSTC_BOOTSTRAP into the fingerprint
# config hash, so a mismatch between scripts forces a full rebuild.
export RUSTC_BOOTSTRAP=rav1d

# ── zxing-cpp (C++ through its official Rust wrapper) ──────────
# The wrapper's `bundled` build compiles the C++ core with CMake; cmake-rs
# picks a toolchain file per Rust target, so each ABI has its own shim (the NDK
# toolchain needs ANDROID_ABI before it is included).
export CMAKE_TOOLCHAIN_FILE_aarch64_linux_android="$ROOT/scripts/cmake/android-arm64-v8a.cmake"
export CMAKE_TOOLCHAIN_FILE_armv7_linux_androideabi="$ROOT/scripts/cmake/android-armeabi-v7a.cmake"
export CMAKE_TOOLCHAIN_FILE_x86_64_linux_android="$ROOT/scripts/cmake/android-x86_64.cmake"

# zxing-cpp is C++. The wrapper links `-lstdc++`, which on Android resolves to
# the NDK's small compatibility stub rather than the C++ runtime, so the real
# one is linked here — statically, so the APK does not need libc++_shared.so.
# Target-scoped rustflags keep host-side build scripts clean.
LIBCXX_FLAGS="-C link-arg=-lc++_static -C link-arg=-lc++abi -C link-arg=-lunwind"

# The NDK ships BOTH a legacy `libstdc++.so` stub (API-level dir, found first
# by default) and a static `libstdc++.a` (ABI dir). A dir holding ONLY the
# static stub makes the wrapper's `-lstdc++` resolve to it without changing
# how `-lc`/`-lm` resolve (pointing at the whole ABI dir links static libc and
# breaks armv7's versioned __aeabi_* symbols).
#
# RUSTFLAGS are whitespace-split: keep the checkout path free of spaces.
LLVM_PREBUILT=$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d | head -n1)
NDK_LIB="$LLVM_PREBUILT/sysroot/usr/lib"
STDCXX_ROOT="$ROOT/target/android-stdcxx"
for pair in "arm64-v8a:aarch64-linux-android" "armeabi-v7a:arm-linux-androideabi" "x86_64:x86_64-linux-android"; do
  abi="${pair%%:*}"; triple="${pair#*:}"
  mkdir -p "$STDCXX_ROOT/$abi"
  cp "$NDK_LIB/$triple/libstdc++.a" "$STDCXX_ROOT/$abi/libstdc++.a"
done
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-L native=$STDCXX_ROOT/arm64-v8a $LIBCXX_FLAGS"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="-L native=$STDCXX_ROOT/armeabi-v7a $LIBCXX_FLAGS"
export CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS="-L native=$STDCXX_ROOT/x86_64 $LIBCXX_FLAGS"

cargo ndk \
    --target aarch64-linux-android \
    --target armv7-linux-androideabi \
    --target x86_64-linux-android \
    -o "$JNI_LIBS" \
    build -p rcrm-flutter-bridge --features mobile-decode $CARGO_FLAG

find "$JNI_LIBS" -name "*.so" -exec echo "  -> {}" \;

# The freshly rebuilt bridge has different contents from the last build, while
# Gradle keeps state snapshots for the jniLibs merges. Two things can then go
# wrong, and this reset prevents both:
#
#   * mergeReleaseJniLibFolders fails to hash its stale output --
#     "Cannot access output property 'outputDir' ... Failed to create MD5 hash
#     for file '...merged_jni_libs/release/.../librcrm_flutter_bridge.so' as it
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
for stale_merge in \
    "$GUI/build/app/intermediates/merged_jni_libs" \
    "$GUI/build/app/intermediates/merged_native_libs"; do
  if [[ -d "$stale_merge" ]]; then
    rm -rf "$stale_merge"
    echo "  -> Reset Gradle state: $stale_merge"
  fi
done

echo ""

# ── Step 2: Pre-download media_kit Android JARs ────────────────
echo "[2/4] Pre-downloading media_kit Android JARs..."
JARS_DIR="$GUI/build/media_kit_libs_android_video/v1.1.7"
mkdir -p "$JARS_DIR"

JARS=("default-arm64-v8a.jar" "default-armeabi-v7a.jar" "default-x86_64.jar" "default-x86.jar")
BASE_URL="https://github.com/media-kit/libmpv-android-video-build/releases/download/v1.1.7"
# GitHub is unreliable from CN networks; fall back to the gh-proxy mirror
# (same content, MD5-verified by media_kit at build time).
MIRROR_BASE_URL="https://gh-proxy.org/$BASE_URL"

for j in "${JARS[@]}"; do
  dest="$JARS_DIR/$j"
  if [[ ! -f "$dest" || ! -s "$dest" ]]; then
    echo "  Downloading $j..."
    if curl -kL -o "$dest" "$BASE_URL/$j" 2>/dev/null; then
      echo "  $j [OK]"
    elif curl -kL -o "$dest" "$MIRROR_BASE_URL/$j" 2>/dev/null; then
      echo "  $j [OK via mirror]"
    else
      echo "  ERROR: Failed to download $j"
      exit 1
    fi
  else
    echo "  $j [cached]"
  fi
done
echo ""

# ── Step 3: Flutter pub get ─────────────────────────────────────
echo "[3/4] Resolving Flutter dependencies..."
(cd "$GUI" && flutter pub get)
echo ""

# ── Step 4: Flutter build APK ───────────────────────────────────
echo "[4/4] Building Flutter APK ($MODE)..."
(
  cd "$GUI"
  if $SPLIT; then
    flutter build apk $FLUTTER_FLAG --split-per-abi
  else
    flutter build apk $FLUTTER_FLAG
  fi
)
echo ""

echo "========================================"
echo " BUILD SUCCESSFUL"
echo "========================================"
echo " APK(s) in: $GUI/build/app/outputs/flutter-apk/"
ls -lh "$GUI/build/app/outputs/flutter-apk/"*.apk 2>/dev/null || true
