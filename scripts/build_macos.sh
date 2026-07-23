#!/usr/bin/env bash
# build_macos.sh
# Full macOS build pipeline: Rust .dylib → Flutter app bundle
# Prerequisites:
#   rustup target add aarch64-apple-darwin x86_64-apple-darwin
# Usage: ./scripts/build_macos.sh [-r|--release]
set -euo pipefail

MODE="debug"
while [[ $# -gt 0 ]]; do case "$1" in
  -r|--release) MODE="release"; shift ;;
  *) echo "Usage: $0 [-r|--release]"; exit 1 ;;
esac; done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUI="$ROOT/crates/rcrm-gui"
BRIDGE="$ROOT/crates/rcrm-flutter-bridge"

FLUTTER_FLAG="--$MODE"
CARGO_FLAG="--release"

echo "========================================"
echo " RCrm GUI --- macOS Build ($MODE)"
echo "========================================"
echo ""

# ── Step 1: Rust bridge (always release) ──────────────────────
echo "[1/5] Building Rust bridge (release)..."
(
  cd "$BRIDGE"
  cargo build $CARGO_FLAG
)
echo "  -> librcrm_flutter_bridge.dylib built"
echo ""

# ── Step 2: Tests (debug only) ──────────────────────────────────
if [[ "$MODE" != "release" ]]; then
  echo "[2/5] Running tests..."
  (cd "$GUI" && flutter test test/rcrm_gui_test.dart)
  echo ""
fi

# ── Step 3: Pre-download libmpv xcframeworks ───────────────────
echo "[3/5] Pre-downloading libmpv xcframeworks..."
CACHE_DIR="$GUI/macos/Pods/.symlinks/plugins/media_kit_libs_macos_video/macos/.cache/xcframeworks"
LIBMPV_VER="v0.6.0"
LIBMPV_URL="https://github.com/media-kit/libmpv-darwin-build/releases/download/${LIBMPV_VER}/libmpv-xcframeworks_${LIBMPV_VER}_macos-universal-video-default.tar.gz"
LIBMPV_FILE="libmpv-xcframeworks-${LIBMPV_VER}-macos-universal.tar.gz"

mkdir -p "$CACHE_DIR"
if [[ -f "$CACHE_DIR/$LIBMPV_FILE" ]]; then
  echo "  libmpv xcframework [cached]"
else
  echo "  Downloading libmpv xcframework..."
  curl -kL -o "$CACHE_DIR/$LIBMPV_FILE" "$LIBMPV_URL" \
    && echo "  libmpv xcframework [OK]" \
    || { echo "  ERROR: Failed to download libmpv xcframework"; exit 1; }
fi
echo ""

# ── Step 4: Flutter build ───────────────────────────────────────
echo "[4/5] Building Flutter ($MODE)..."
(
  cd "$GUI"
  flutter build macos $FLUTTER_FLAG
)
echo ""

# ── Step 5: Copy bridge into app bundle ─────────────────────────
echo "[5/5] Copying Rust bridge into app bundle..."
DYLIB="$ROOT/target/release/librcrm_flutter_bridge.dylib"
APP_DIR="$GUI/build/macos/Build/Products"
if [[ "$MODE" == "release" ]]; then
  DEST="$APP_DIR/Release/rcrm_gui.app/Contents/Frameworks"
else
  DEST="$APP_DIR/Debug/rcrm_gui.app/Contents/Frameworks"
fi
mkdir -p "$DEST"
cp "$DYLIB" "$DEST/"
install_name_tool -id "@executable_path/../Frameworks/librcrm_flutter_bridge.dylib" "$DEST/librcrm_flutter_bridge.dylib" 2>/dev/null || true
echo "  -> Copied to $DEST/librcrm_flutter_bridge.dylib"
echo ""

echo "========================================"
echo " BUILD SUCCESSFUL"
echo "========================================"
echo "  $DEST/../MacOS/rcrm_gui"
