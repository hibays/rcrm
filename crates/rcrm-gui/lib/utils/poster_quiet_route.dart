// utils/poster_quiet_route.dart
// The player route, and the poster pool's suspension tied to its lifetime.
//
// Poster players and the playback player share media_kit's STATIC
// `NativePlayer.lock`. On mobile the pool holds exactly one `Player`, and it
// holds that lock across `open` — and again across each `seek` + `screenshot` —
// so a poster job that is mid-flight when the user taps a video makes playback's
// `open`/`play` queue behind it, inside the route transition the user is
// watching. Neither "wait a moment" nor "resume when the first frame is up" can
// bound that: what the pool is doing is only knowable when the route arrives.
//
// So the suspension is tied to the route's own lifetime, which has no delay in
// it:
//
//   * `install()` runs synchronously at push time (`handlePush` →
//     `route.install()`), before this route builds anything at all. The gate is
//     therefore already closed when this route creates the playback player, and
//     before any of the route's widgets exist — the certified order: suspend,
//     create, push.
//   * `dispose()` runs when the route is gone for real, so a pop and a
//     `pushReplacement` both lift the suspension with no ping-pong between the
//     outgoing and incoming screens (`ThumbnailService` counts the depth).
//
// Deliberately not a `Timer`, and deliberately no pool teardown: a live poster
// job holds the pool player across a `screenshot()` whose native side re-checks
// nothing, so disposing the pool for the duration of playback would be a crash
// rather than a saving. The pool is *parked*, not destroyed.

import 'package:flutter/material.dart';
import 'package:media_kit/media_kit.dart';

import '../services/player_factory.dart';
import '../services/thumbnail_service.dart';

/// A `MaterialPageRoute` that keeps the poster pool quiet for as long as it is
/// on the navigator, and that owns the playback `Player` for the screen it
/// builds.
///
/// One class for all four push sites (`video_screen`, `home_screen`,
/// `search_screen`, `video_player_screen._go`), so tap → push → pop → replace is
/// covered in exactly one place.
class PosterQuietRoute<T> extends MaterialPageRoute<T> {
  /// The builder receives the player this route created, or null when creating
  /// it failed, and returns the screen — normally
  /// `VideoPlayerScreen(item: item, warmPlayer: warm)`.
  PosterQuietRoute({required this._build, super.settings})
    : super(builder: _routeBuilder);

  final Widget Function(Player? warmPlayer) _build;

  /// Resolved through the route rather than through a captured closure: the
  /// builder runs while this route is the modal route of its own overlay entry,
  /// and reading `_warm` late is what lets `install()` run first.
  static Widget _routeBuilder(BuildContext context) {
    final route = ModalRoute.of(context);
    if (route is! PosterQuietRoute) {
      throw StateError('PosterQuietRoute built outside itself');
    }
    return route._build(route._warm);
  }

  /// The playback player, created while this route is being built, instead of in
  /// the incoming screen's first `addPostFrameCallback` — where `mpv_create`/
  /// `mpv_initialize` plus ~30 synchronous property writes ran on the UI
  /// isolate, at the tail of the first frame of the 450 ms Android route
  /// transition.
  ///
  /// Owned by this route, handed to the one screen this route builds, and a
  /// route object is used once (`Navigator` asserts as much) — so no player is
  /// ever handed from one screen to another.
  Player? _warm;

  /// True once [_warm] has been decided — including "creation failed", which
  /// must not be retried on every rebuild.
  bool _warmResolved = false;

  @override
  void install() {
    // Before anything of this route builds: the pool must not be in the middle
    // of an `open`/`seek`/`screenshot` when the playback player is created.
    ThumbnailService.suspend();
    super.install();
  }

  @override
  Widget buildPage(
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
  ) {
    if (!_warmResolved) {
      _warmResolved = true;
      _warm = _createWarmPlayer();
    }
    return _build(_warm);
  }

  /// A player that cannot be created must never stop the screen from mounting:
  /// null here means the screen falls back to `PlayerFactory.playback()` in its
  /// own post-frame callback, which is exactly the pre-existing behaviour.
  static Player? _createWarmPlayer() {
    try {
      return PlayerFactory.playback();
    } catch (_) {
      return null;
    }
  }

  @override
  void dispose() {
    // The route is gone: the poster pool may work again. Done here rather than
    // on a timer so a pop returns to a screen whose posters resume immediately,
    // and so two overlapping player routes (a `pushReplacement` under way) only
    // lift the gate when the last of them has gone.
    ThumbnailService.resume();
    super.dispose();
  }
}
