#!/usr/bin/env bash
# build_clean.sh
# Clean build artifacts using native tool clean commands.
# Usage:
#   ./scripts/build_clean.sh          # clean everything
#   ./scripts/build_clean.sh -n       # dry-run (preview only)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUI="$ROOT/crates/rcrm-gui"
BRIDGE="$ROOT/crates/rcrm-flutter-bridge"

DRY_RUN=false
[[ "${1:-}" == "-n" || "${1:-}" == "--dry-run" ]] && DRY_RUN=true

echo "========================================"
echo " RCrm GUI --- Clean Build Artifacts"
echo "========================================"
echo ""

run_cmd() {
    local label="$1"; shift
    if $DRY_RUN; then
        printf "  [dry]   %s\n" "$label"
        return
    fi
    printf "  [clean] %s\n" "$label"
    "$@"
}

# ── Rust ───────────────────────────────────────────────────────
run_cmd "cargo clean (rcrm-flutter-bridge)" bash -c "cd '$BRIDGE' && cargo clean"
echo ""

# ── Flutter (handles all platforms) ────────────────────────────
run_cmd "flutter clean (rcrm-gui)" bash -c "cd '$GUI' && flutter clean"
echo ""

# ── Android Gradle ─────────────────────────────────────────────
if [[ -f "$GUI/android/gradlew" ]]; then
    run_cmd "gradlew clean (android)" bash -c "cd '$GUI/android' && ./gradlew clean"
    echo ""
fi

# ── Android jniLibs (Rust .so output — not managed by gradlew) ─
JNI="$GUI/android/app/src/main/jniLibs"
if [[ -d "$JNI" ]]; then
    if $DRY_RUN; then
        size=$(du -sb "$JNI" 2>/dev/null | cut -f1)
        size=${size:-0}
        size_mb=$(awk "BEGIN {printf \"%.1f\", $size/1048576}")
        printf "  [dry]   jniLibs/  %s MB\n" "$size_mb"
    else
        rm -rf "$JNI"
        printf "  [del]   jniLibs/\n"
    fi
    echo ""
fi

if $DRY_RUN; then
    echo "Dry run complete — no files changed."
else
    echo "Done."
fi
