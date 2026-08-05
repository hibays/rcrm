#!/usr/bin/env bash
# build_ios.sh
# Full iOS build pipeline: Rust static lib → Flutter .app
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   Xcode + CocoaPods installed
# Usage:
#   ./scripts/build_ios.sh              # debug (simulator)
#   ./scripts/build_ios.sh -r           # release (device)
#   ./scripts/build_ios.sh -r --no-codesign  # release without signing
set -euo pipefail

MODE="debug"
CODESIGN=true
while [[ $# -gt 0 ]]; do case "$1" in
  -r|--release)     MODE="release"; shift ;;
  --no-codesign)   CODESIGN=false; shift ;;
  *) echo "Usage: $0 [-r|--release] [--no-codesign]"; exit 1 ;;
esac; done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUI="$ROOT/crates/rcrm-gui"
BRIDGE="$ROOT/crates/rcrm-flutter-bridge"

echo "========================================"
echo " RCrm GUI --- iOS Build ($MODE)"
echo "========================================"
echo ""

# ── Step 1: Rust bridge for iOS ─────────────────────────────────
echo "[1/4] Building Rust bridge for iOS..."
(
  cd "$BRIDGE"
  # RUSTC_BOOTSTRAP=rav1d: keep identical to other build scripts — cargo folds
  # it into the fingerprint config hash; any mismatch forces a full rebuild.
  export RUSTC_BOOTSTRAP=rav1d
  cargo build --release -p rcrm-flutter-bridge --features mobile-decode --target aarch64-apple-ios
  cargo build --release -p rcrm-flutter-bridge --features mobile-decode --target aarch64-apple-ios-sim 2>/dev/null || echo "  (simulator target skipped)"
)
echo "  -> Static libs built"
echo ""

# ── Step 2: Copy static lib into Xcode project ─────────────────
echo "[2/4] Linking Rust static lib into Xcode project..."
STATIC_LIB="$ROOT/target/aarch64-apple-ios/release/librcrm_flutter_bridge.a"
if [[ -f "$STATIC_LIB" ]]; then
  cp "$STATIC_LIB" "$GUI/ios/Runner/librcrm_flutter_bridge.a"
  echo "  -> librcrm_flutter_bridge.a copied to Runner/"
else
  echo "  WARNING: librcrm_flutter_bridge.a not found at $STATIC_LIB"
fi
echo ""

# ── Step 3: Pre-download libmpv xcframeworks ───────────────────
echo "[3/4] Pre-downloading libmpv xcframeworks..."
CACHE_DIR="$GUI/ios/.symlinks/plugins/media_kit_libs_ios_video/ios/.cache/xcframeworks"
LIBMPV_VER="v0.6.0"
LIBMPV_URL="https://github.com/media-kit/libmpv-darwin-build/releases/download/${LIBMPV_VER}/libmpv-xcframeworks_${LIBMPV_VER}_ios-universal-video-default.tar.gz"
LIBMPV_FILE="libmpv-xcframeworks-${LIBMPV_VER}-ios-universal.tar.gz"

mkdir -p "$CACHE_DIR"
if [[ -f "$CACHE_DIR/$LIBMPV_FILE" ]]; then
  echo "  libmpv xcframework [cached]"
else
  echo "  Downloading libmpv xcframework..."
  # GitHub is unreliable from CN networks; fall back to the gh-proxy mirror.
  if curl -kL -o "$CACHE_DIR/$LIBMPV_FILE" "$LIBMPV_URL" 2>/dev/null; then
    echo "  libmpv xcframework [OK]"
  elif curl -kL -o "$CACHE_DIR/$LIBMPV_FILE" "https://gh-proxy.org/$LIBMPV_URL" 2>/dev/null; then
    echo "  libmpv xcframework [OK via mirror]"
  else
    echo "  ERROR: Failed to download libmpv xcframework"
    exit 1
  fi
fi
echo ""

# ── Step 4: Flutter build ───────────────────────────────────────
echo "[4/4] Building Flutter ($MODE)..."
(
  cd "$GUI"
  if $CODESIGN; then
    flutter build ios --$MODE
  else
    flutter build ios --$MODE --no-codesign
  fi
)
echo ""

echo "========================================"
echo " BUILD SUCCESSFUL"
echo "========================================"
echo "  App: $GUI/build/ios/iphoneos/Runner.app"
