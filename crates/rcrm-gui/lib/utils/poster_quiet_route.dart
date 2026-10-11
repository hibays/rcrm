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
//
// The route also carries the player's DIRECTION. `_go` REPLACES the player route
// on every jump — forward through the history and back through it — so both
// steps are a push, and without a flag the back step played the platform's
// forward transition, i.e. a step back into the history looked exactly like
// opening a video. `backStep` makes that step play what a POP reveals on the
// platform instead, which is a different animation on every platform family —
// Android's slide + fade, the desktop zoom, Cupertino's own slide. The
// `buildTransitions` override below is the only thing it changes.

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
  PosterQuietRoute({
    required this._build,
    this.backStep = false,
    super.settings,
  }) : super(builder: _routeBuilder);

  final Widget Function(Player? warmPlayer) _build;

  /// True when this route is the BACK step of the jump history — the video
  /// `Back` is returning to. It then enters with the mirror of the platform's
  /// forward transition (in from the left) instead of that transition itself.
  ///
  /// A flag here rather than at the call site's widget: the transition belongs
  /// to the ROUTE, so it is decided wherever a route is created — `_go` in
  /// `video_player_screen.dart` is the only such site, and it is the only place
  /// that knows which way the history is being walked.
  final bool backStep;

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
      return warmPlayerFactory();
    } catch (_) {
      return null;
    }
  }

  /// The warm player's factory. Production always uses `PlayerFactory.playback`.
  ///
  /// A seam because this route can be pushed in a widget test (its transition
  /// and its poster-pool gate are drivable there) while a real media_kit
  /// `Player` cannot be created in a test process at all — a test that silently
  /// relied on `PlayerFactory.playback()` throwing would start leaking a native
  /// player the day it does not.
  @visibleForTesting
  static Player? Function() warmPlayerFactory = PlayerFactory.playback;

  // ── Direction ──────────────────────────────────────────────
  // The back step's entrance, as the animation the platform plays for the page a
  // pop REVEALS. A pop drives that page with one specific pair — its own
  // animation already complete, its secondary animation running 1 -> 0 — so
  // `buildTransitions` below either reproduces what that pair produces or hands
  // the pair to the platform's own builder. Neither is a table of per-platform
  // numbers invented here; the difference between them is which one can be
  // reproduced exactly.
  //
  // Android can be, and these two tweens are it verbatim: its reveal is
  // `_secondaryForwardTranslationTween` and `_fadeInTransition` from
  // `FadeForwardsPageTransitionsBuilder` (a `PredictiveBackPageTransitionsBuilder`
  // programmatic push delegates to it) — a slide from -0.25 of the width on
  // `Curves.easeInOutCubicEmphasized`, fading in over `Interval(0, 0.75)`. The
  // route's own `transitionDuration` is not touched, so the length stays the
  // platform's 450ms. Measured against a real pop on the same navigator, the
  // revealed page and this route sample identically: 181.26px / 100.34px /
  // 21.39px from settled at 10% / 25% / 50% of 450ms.
  //
  // Hand-writing it for the other platforms is what was wrong before, and the
  // same measurement says so: Cupertino's reveal (iOS/macOS) travels from -1/3
  // with its own curve — 197.19px / 100.34px / 21.39px, so NOT Android's numbers
  // — and the desktop zoom (Windows/Linux) has no sideways travel at all (it
  // scales and fades, snapshot-painted, leaving the widget tree's geometry
  // identity). A 0.25 slide on Windows was therefore Android's animation painted
  // on a desktop, which is exactly what a "native differences" rule forbids.
  static final Animatable<Offset> _backSlideTween = Tween<Offset>(
    begin: const Offset(-0.25, 0.0),
    end: Offset.zero,
  ).chain(CurveTween(curve: Curves.easeInOutCubicEmphasized));

  static final Animatable<double> _backFadeTween = Tween<double>(
    begin: 0.0,
    end: 1.0,
  ).chain(CurveTween(curve: const Interval(0.0, 0.75)));

  @override
  Widget buildTransitions(
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    // Forward: the platform's transition, untouched — this is the same call the
    // theme would make for a plain `MaterialPageRoute`, so opening a video still
    // feels exactly as it did.
    if (!backStep) {
      return super.buildTransitions(
        context,
        animation,
        secondaryAnimation,
        child,
      );
    }
    // Back. Which animation that is comes from the theme, not from this file:
    // an app that swapped its `PageTransitionsTheme` gets its own answer here.
    final theme = Theme.of(context);
    final builder =
        theme.pageTransitionsTheme.builders[theme.platform] ??
        const ZoomPageTransitionsBuilder();
    if (builder is FadeForwardsPageTransitionsBuilder ||
        builder is PredictiveBackPageTransitionsBuilder) {
      return SlideTransition(
        position: _backSlideTween.animate(animation),
        child: FadeTransition(
          opacity: _backFadeTween.animate(animation),
          child: child,
        ),
      );
    }
    // Everything else asks the platform's own builder to play the revealed page,
    // by making the call the framework makes for it: this route's animation
    // already complete (so the builder does not also play an entrance), and a
    // secondary animation running 1 -> 0 — the page above is going away, which
    // over this route's own duration is `ReverseAnimation(animation)`. Windows
    // and Linux then scale and fade as they do for any revealed page, and
    // iOS/macOS slide in from -1/3 on Cupertino's curve, without this file
    // knowing either animation.
    return builder.buildTransitions<T>(
      this,
      context,
      const AlwaysStoppedAnimation<double>(1.0),
      ReverseAnimation(animation),
      child,
    );
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
