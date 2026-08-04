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
cargo ndk \
    --target aarch64-linux-android \
    --target armv7-linux-androideabi \
    --target x86_64-linux-android \
    -o "$JNI_LIBS" \
    build -p rcrm-flutter-bridge --features mobile-decode $CARGO_FLAG

find "$JNI_LIBS" -name "*.so" -exec echo "  -> {}" \;
echo ""

# ── Step 2: Pre-download media_kit Android JARs ────────────────
echo "[2/4] Pre-downloading media_kit Android JARs..."
JARS_DIR="$GUI/build/media_kit_libs_android_video/v1.1.7"
mkdir -p "$JARS_DIR"

JARS=("default-arm64-v8a.jar" "default-armeabi-v7a.jar" "default-x86_64.jar")
BASE_URL="https://github.com/media-kit/libmpv-android-video-build/releases/download/v1.1.7"

for j in "${JARS[@]}"; do
  dest="$JARS_DIR/$j"
  if [[ ! -f "$dest" || ! -s "$dest" ]]; then
    echo "  Downloading $j..."
    curl -kL -o "$dest" "$BASE_URL/$j" 2>/dev/null && echo "  $j [OK]" || { echo "  ERROR: Failed to download $j"; exit 1; }
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
