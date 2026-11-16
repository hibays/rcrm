#!/usr/bin/env bash
# build_ios.sh
# Full iOS build pipeline: Rust static lib → Flutter .app
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   Xcode + CocoaPods installed
# Usage:
#   ./scripts/build_ios.sh              # debug (device; the copied .a is the device build)
#   ./scripts/build_ios.sh -r           # release (device)
#   ./scripts/build_ios.sh -r --no-codesign  # release without signing
#   ./scripts/build_ios.sh --mobile-decode   # on by default; kept for symmetry
set -euo pipefail

MODE="debug"
CODESIGN=true
MOBILE_DECODE=true
while [[ $# -gt 0 ]]; do case "$1" in
  -r|--release)     MODE="release"; shift ;;
  --no-codesign)   CODESIGN=false; shift ;;
  --mobile-decode) MOBILE_DECODE=true; shift ;;
  *) echo "Usage: $0 [-r|--release] [--no-codesign] [--mobile-decode]"; exit 1 ;;
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
  # zxing-cpp's bundled CMake build needs the iOS platform stated explicitly
  # (a toolchain file turns off cmake-rs's own cross-compile defaults).
  export CMAKE_TOOLCHAIN_FILE_aarch64_apple_ios="$ROOT/scripts/cmake/ios-device.cmake"
  export CMAKE_TOOLCHAIN_FILE_aarch64_apple_ios_sim="$ROOT/scripts/cmake/ios-sim.cmake"
  CARGO_ARGS=(build --release -p rcrm-flutter-bridge)
  # libmpv-poster is required on iOS too: media_kit ships libmpv as an embedded,
  # code-signed `Mpv.framework/Mpv` (a real MH_DYLIB), which the poster client
  # opens by name. Without the feature there is no poster renderer at all.
  FEATURES=(libmpv-poster)
  if $MOBILE_DECODE; then FEATURES+=(mobile-decode); fi
  if [[ ${#FEATURES[@]} -gt 0 ]]; then
    FEATURE_LIST=$(IFS=,; echo "${FEATURES[*]}")
    CARGO_ARGS+=(--features "$FEATURE_LIST")
  fi
  cargo "${CARGO_ARGS[@]}" --target aarch64-apple-ios
  cargo "${CARGO_ARGS[@]}" --target aarch64-apple-ios-sim 2>/dev/null || echo "  (simulator target skipped)"
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

# ── Step 3: libmpv frameworks (SPM-aware) ──────────────────────
echo "[3/4] Preparing media_kit's libmpv frameworks..."
# Locate the plugin through pub's own package_config, so a version bump or a
# mirror host needs no edit here. (The old step wrote into ios/.symlinks, which
# CocoaPods recreates from scratch — the pre-download was thrown away.)
PKG_CONFIG="$GUI/.dart_tool/package_config.json"
PLUGIN_DIR=""
if [[ -f "$PKG_CONFIG" ]]; then
  PLUGIN_DIR=$(/usr/bin/python3 - "$PKG_CONFIG" <<'PY' 2>/dev/null || true
import json, os, sys, urllib.parse
cfg = json.load(open(sys.argv[1]))
for p in cfg.get("packages", []):
    if p.get("name") == "media_kit_libs_ios_video":
        uri = p.get("rootUri", "")
        if uri.startswith("file://"):
            print(urllib.parse.unquote(uri[len("file://"):]))
        elif uri:
            print(os.path.normpath(os.path.join(os.path.dirname(sys.argv[1]), uri)))
        break
PY
)
fi

# Fallback for a missing/unreadable package_config (or no python3): pub's own
# cache layout is stable enough for this one lookup.
if [[ -z "$PLUGIN_DIR" ]]; then
  for root in "$HOME/.pub-cache/hosted/pub.dev" "$HOME/.pub-cache/hosted/pub.flutter-io.cn"; do
    for candidate in "$root"/media_kit_libs_ios_video-*; do
      if [[ -d "$candidate" ]]; then PLUGIN_DIR="$candidate"; fi
    done
  done
fi

if [[ -z "$PLUGIN_DIR" ]]; then
  echo "  WARNING: media_kit_libs_ios_video was not found (package_config/pub cache)"
  echo "           (run 'flutter pub get'); leaving the download to the build"
elif [[ -f "$PLUGIN_DIR/ios/media_kit_libs_ios_video/Package.swift" ]] || \
     [[ -f "$PLUGIN_DIR/ios/Package.swift" ]]; then
  # SPM: the package declares the xcframeworks as REMOTE binary targets, and
  # Flutter prefetches them with 'xcodebuild -resolvePackageDependencies' before
  # building. Xcode owns the download and its artifact cache; a curl here would
  # only create a second copy nothing reads.
  echo "  SPM package: binary targets are downloaded by Xcode/SwiftPM"
else
  # CocoaPods path (media_kit_libs_ios_video 1.1.4 ships only a podspec): the
  # podspec runs its Makefile during pod install, and that Makefile downloads
  # the tarball into this cache and verifies its sha256. Pre-seed the SAME file
  # with the SAME hash, so a blocked GitHub fails HERE with a readable message
  # instead of halfway through pod install. Version and hash are read from the
  # Makefile, so a plugin bump cannot silently desynchronise this step.
  MAKEFILE="$PLUGIN_DIR/ios/Makefile"
  LIBMPV_VER=""
  LIBMPV_SHA=""
  if [[ -f "$MAKEFILE" ]]; then
    # Checked first: under 'set -e' a failed parse would abort the script before
    # the readable warning below could run. awk (not sed|head) because under
    # 'set -o pipefail' a SIGPIPE from head would also abort it.
    LIBMPV_VER=$(awk -F= '/^MPV_XCFRAMEWORKS_VERSION=/{sub(/\r$/,"",$2); print $2; exit}' "$MAKEFILE")
    LIBMPV_SHA=$(awk -F= '/^MPV_XCFRAMEWORKS_SHA256SUM=/{sub(/\r$/,"",$2); print $2; exit}' "$MAKEFILE")
  fi
  if [[ -z "$LIBMPV_VER" || -z "$LIBMPV_SHA" ]]; then
    echo "  WARNING: no SPM manifest and no usable Makefile; skipping pre-download"
  else
    CACHE_DIR="$PLUGIN_DIR/ios/.cache/xcframeworks"
    LIBMPV_FILE="libmpv-xcframeworks-${LIBMPV_VER}-ios-universal.tar.gz"
    LIBMPV_URL="https://github.com/media-kit/libmpv-darwin-build/releases/download/${LIBMPV_VER}/libmpv-xcframeworks_${LIBMPV_VER}_ios-universal-video-default.tar.gz"
    TARBALL="$CACHE_DIR/$LIBMPV_FILE"
    if ! mkdir -p "$CACHE_DIR" 2>/dev/null || [[ ! -w "$CACHE_DIR" ]]; then
      echo "  WARNING: cannot write $CACHE_DIR; leaving the download to pod install"
    else
      file_sha() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
      if [[ -f "$TARBALL" && "$(file_sha "$TARBALL")" == "$LIBMPV_SHA" ]]; then
        echo "  libmpv xcframework [cached, sha256 ok]"
      else
        rm -f "$TARBALL" "$TARBALL.tmp"
        echo "  Downloading libmpv xcframework ($LIBMPV_VER)..."
        # GitHub is unreliable from CN networks; fall back to the gh-proxy mirror.
        if curl -kL --fail -o "$TARBALL.tmp" "$LIBMPV_URL" 2>/dev/null; then
          SOURCE="github"
        elif curl -kL --fail -o "$TARBALL.tmp" "https://gh-proxy.org/$LIBMPV_URL" 2>/dev/null; then
          SOURCE="gh-proxy"
        else
          SOURCE=""
        fi
        if [[ -z "$SOURCE" ]]; then
          rm -f "$TARBALL.tmp"
          echo "  ERROR: could not download $LIBMPV_URL"
          echo "         (or its gh-proxy mirror). Fetch it by hand into:"
          echo "         $TARBALL"
          exit 1
        fi
        if [[ "$(file_sha "$TARBALL.tmp")" != "$LIBMPV_SHA" ]]; then
          rm -f "$TARBALL.tmp"
          echo "  ERROR: $SOURCE tarball's sha256 does not match the Makefile's"
          echo "         expected $LIBMPV_SHA — refusing to hand it to pod install."
          exit 1
        fi
        mv "$TARBALL.tmp" "$TARBALL"
        echo "  libmpv xcframework [OK, $SOURCE, sha256 ok]"
      fi
    fi
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

# The poster renderer opens Mpv.framework at runtime and has no fallback, so a
# missing embed would only surface as "no posters" on the device. Say it here.
APP="$GUI/build/ios/iphoneos/Runner.app"
if [[ -f "$APP/Frameworks/Mpv.framework/Mpv" ]]; then
  echo "  -> Mpv.framework embedded (poster renderer)"
else
  echo "  WARNING: Mpv.framework is not in Runner.app/Frameworks; posters will be unavailable"
fi

echo "========================================"
echo " BUILD SUCCESSFUL"
echo "========================================"
echo "  App: $APP"
