// utils/poster_backend.dart
// Which poster backend a build uses, as one pure decision.
//
// The two backends are named for what renders the frame:
//
//   libmpv — libmpv draws it inside our own process, in Rust
//            (`poster_libmpv.dart` / `rcrm_generate_poster_async`). Needs the
//            `libmpv-poster` Cargo feature and a libmpv the process can load.
//   mpv    — media_kit's `Player.screenshot`, encoded by Rust
//            (`poster_mpv.dart`). iOS's only option: its libmpv is linked into
//            the app and the platform refuses an arbitrary `dlopen`.
//
// Nothing here knows about "desktop" or "mobile": the two facts that decide it
// are whether the platform can load libmpv at all, and whether this build has
// the export to call.

import 'dart:io' show Platform;

import '../ffi/rust_bridge.dart' show RustBridge;

enum PosterBackend {
  /// libmpv renders the frame itself, in Rust.
  libmpv,

  /// media_kit takes a screenshot and Rust encodes it.
  mpv,
}

/// The backend for this build, from the two facts that decide it.
///
/// [hasLibMpv] is `RustBridge.libmpvPosterAddr != 0`: an older bridge built
/// without `libmpv-poster` has no direct-render export, and the media_kit
/// backend still works there — which is also what keeps every iOS build correct
/// without a special case elsewhere.
PosterBackend choosePosterBackend({
  required bool isIOS,
  required bool hasLibMpv,
}) {
  if (isIOS) return PosterBackend.mpv;
  return hasLibMpv ? PosterBackend.libmpv : PosterBackend.mpv;
}

/// [choosePosterBackend] for the running platform and the loaded bridge.
///
/// Read per request rather than cached: the bridge is loaded at startup, and a
/// cached answer taken before that would silently pick the wrong backend for
/// the process's lifetime.
PosterBackend posterBackendForThisBuild() => choosePosterBackend(
  isIOS: Platform.isIOS,
  hasLibMpv: RustBridge.libmpvPosterAddr != 0,
);
