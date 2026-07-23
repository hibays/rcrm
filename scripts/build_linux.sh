#!/usr/bin/env bash
# build_linux.sh
# Full Linux build pipeline: Rust .so → Flutter app bundle
# Prerequisites:
#   sudo apt install libgtk-3-dev libmpv-dev mpv  (or equivalent)
# Usage: ./scripts/build_linux.sh [-r|--release]
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
echo " RCrm GUI --- Linux Build ($MODE)"
echo "========================================"
echo ""

# ── Step 1: Rust bridge (always release) ──────────────────────
echo "[1/4] Building Rust bridge (release)..."
(
  cd "$BRIDGE"
  cargo build $CARGO_FLAG
)
echo "  -> librcrm_flutter_bridge.so built"
echo ""

# ── Step 2: Tests (debug only) ──────────────────────────────────
if [[ "$MODE" != "release" ]]; then
  echo "[2/4] Running tests..."
  (cd "$GUI" && flutter test test/rcrm_gui_test.dart)
  echo ""
fi

# ── Step 3: Flutter build ───────────────────────────────────────
echo "[3/4] Building Flutter ($MODE)..."
(
  cd "$GUI"
  flutter build linux $FLUTTER_FLAG
)
echo ""

# ── Step 4: Copy bridge into app bundle ─────────────────────────
echo "[4/4] Copying Rust bridge into app bundle..."
SO="$ROOT/target/release/librcrm_flutter_bridge.so"
APP_DIR="$GUI/build/linux/x64/$MODE/bundle"
mkdir -p "$APP_DIR/lib"
cp "$SO" "$APP_DIR/lib/librcrm_flutter_bridge.so"
echo "  -> Copied to $APP_DIR/lib/librcrm_flutter_bridge.so"
echo ""

echo "========================================"
echo " BUILD SUCCESSFUL"
echo "========================================"
echo "  $APP_DIR/rcrm_gui"
