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
//
// A step is TWO pages, though, and `backStep` only ever fixed the one arriving.
// The page being LEFT kept the exit of a push, so on Android the pair travelled
// the same way at the same time — sampled at 0/10/25/50/75% of the 450ms, as
// offsets from rest: the outgoing page at 0 / -18.74 / -154.30 / -190.17 /
// -198.29px (off to the LEFT, i.e. being covered, which is `_secondaryBackward-
// TranslationTween`) while the incoming page came in from the left as well
// (-200 / -181.26 / -45.70 / -9.83 / -1.71px). Two pages sliding one way is what
// a PUSH looks like, with a crossfade on top of it: the step read as another
// forward jump rather than as a return, and the rhythm of the pop it is supposed
// to be — the one an empty history plays, whose two halves are the popped page
// leaving to the RIGHT while the revealed one comes in from the left — was gone.
//
// The page being LEFT is the half that closes it, and it learns so by itself:
// when a `pushReplacement` completes the route it replaces, the framework
// announces the page now below it — `didChangeNext` on the outgoing route, which
// is `_leftAsPop` below — and that is where a page a back step leaves is given
// the pair a POP gives the page it pops, from the platform's own builder. Both
// halves of the step then come out of the back vocabulary and compose into the
// pop an empty history plays. Measured on the same navigator, the outgoing half
// samples at the same numbers a real pop's outgoing page does, and the incoming
// half at the same numbers a real pop's revealed page does.
//
// The step's LENGTH is the platform's, deliberately: no duration is overridden
// here. A 300ms-in / 240ms-out override lived here for one round, on the theory
// that the exit "dragged" — the platform's shape finishes the outgoing page's
// fade at 25% of the duration and the incoming page's only at 75%, so on Android
// the last ~337ms of a step that reveals the library shows the library, all but
// arrived, still fading. That is real, and it was not the bug: the step that felt
// wrong was playing the WRONG animation (a video walking off to the left,
// opaque until the last quarter, because the route had been built as a return
// step — see `buildTransitions`), and shortening every player transition also
// shortened the ones nobody had complained about, the plain "open a video, come
// back". What was wrong was the shape and what each page was DOING.

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

  /// True once the step above this route has announced itself as a BACK step:
  /// this page is the one a return is LEAVING, so it leaves the way a POP leaves
  /// the page it pops instead of the way a push covers it — see
  /// [buildTransitions].
  ///
  /// Learned from the framework rather than handed over by the caller, which is
  /// what makes it impossible to forget. When `pushReplacement` completes the
  /// route it replaces, `NavigatorState._flushRouteAnnouncement` announces the
  /// page now below it — `didChangeNext(newRoute)` on the page being replaced,
  /// i.e. this hook. (It is NOT `didReplace`: `_RouteEntry.handlePush` calls that
  /// only for the `replace` lifecycle, i.e. `pushAndRemoveUntil`.) Both
  /// directions come through here and the guard tells them apart: a forward
  /// jump's replacement has `backStep == false`, and the push exit it plays is
  /// exactly right for that.
  bool _leftAsPop = false;

  @override
  void didChangeNext(Route<dynamic>? nextRoute) {
    if (nextRoute is PosterQuietRoute && nextRoute.backStep) {
      _leftAsPop = true;
    }
    super.didChangeNext(nextRoute);
  }

  /// The route directly below this one, as the framework announces it
  /// (`Route.didChangePrevious`).
  ///
  /// Read by `player_exit.leavePlayerForLibrary`, which has to take the screen a
  /// video was opened from (the search results) out of the chain WITHOUT
  /// animation before the player pops — otherwise Home animates two pages at
  /// once and stops looking like `Back`. A route cannot ask the navigator what is
  /// under it, so the framework's own announcement is kept here.
  Route<dynamic>? get previousRoute => _previousRoute;
  Route<dynamic>? _previousRoute;

  @override
  void didChangePrevious(Route<dynamic>? previousRoute) {
    _previousRoute = previousRoute;
    super.didChangePrevious(previousRoute);
  }

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

  /// The platform's own transition builder for this navigator, resolved through
  /// the THEME rather than named here: an app that swapped its
  /// `PageTransitionsTheme` gets its own answer, on both halves of the step.
  ///
  /// Resolved and called DIRECTLY, never through
  /// `PageTransitionsTheme.buildTransitions`. That entry point is the tidier
  /// call — it is what `MaterialRouteTransitionMixin.buildTransitions` makes,
  /// and it would inherit the framework's own platform fallback — but it does
  /// not survive the substitution this file depends on: routed through it, the
  /// leaving page's animations arrive correct (its `SlideTransition` reports
  /// -0.2 / +0.3 over the step, its `FadeTransition` 1.00 -> 0.60 -> 0.00) while
  /// the page's own on-screen position never moves from 0.00px, so the pop exit
  /// is computed and thrown away — measured, and the reason this looks like the
  /// long way round. `test/poster_quiet_route_test.dart` samples the geometry,
  /// so it fails if this is ever tidied back.
  static PageTransitionsBuilder _builderFor(BuildContext context) {
    final theme = Theme.of(context);
    return theme.pageTransitionsTheme.builders[theme.platform] ??
        const ZoomPageTransitionsBuilder();
  }

  @override
  Widget buildTransitions(
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    // Leaving as a pop. A `pushReplacement` drives this page with the pair for
    // "something is arriving on top of me" — its `secondaryAnimation` forward,
    // its own animation still complete — and that is what a push does to the
    // page it covers. A POP drives the page it pops with the pair below instead,
    // and that pair is available here for free: this page's
    // `secondaryAnimation` IS the replacement's own animation (0 -> 1 over the
    // step), so reversing it is the 1 -> 0 a pop would run this page on, over
    // the same clock, while "nothing above me" is what a pop leaves there.
    //
    // Both are handed to the platform's own builder, so every platform family
    // gets its own pop exit — Android's slide out to the RIGHT + fade over
    // `_backwardTranslationTween`, the desktop zoom's fade + shrink, Cupertino's
    // slide — with no per-platform numbers written down in this file. Measured
    // against a real pop on the same navigator, the samples are identical.
    if (_leftAsPop) {
      return _builderFor(context).buildTransitions<T>(
        this,
        context,
        ReverseAnimation(secondaryAnimation),
        const AlwaysStoppedAnimation<double>(0.0),
        child,
      );
    }
    // Everything that is not "arriving as a return" is the platform's own
    // decision, and `backStep` says nothing about it: for a plain push this is
    // the same call the theme would make for a `MaterialPageRoute`, so opening a
    // video still feels exactly as it did. It is asked one question — is this
    // page still ARRIVING? — and a page that is leaving is leaving whatever it
    // was built as:
    //
    //  * a route created as a back step, POPPED for real when the history runs
    //    out (the last `Back` before the library). It played the reveal
    //    backwards: on Android the video walked off to the LEFT, staying opaque
    //    until the last quarter of the step, where the video opened from the
    //    library walks off to the RIGHT with its fade done at a quarter. On the
    //    desktop zoom it grew from 1.10 and never faded, instead of shrinking to
    //    0.90 behind a fade. One gesture, two animations, decided by how the
    //    route had been built — and neither the gesture nor the user's intent
    //    depends on that;
    //  * and a route created as a back step, COVERED by a forward jump: the
    //    reveal pair evaluated at rest is the identity, so that page did not
    //    move or fade at all under the arriving video, where any other page
    //    drifts and fades the way the platform covers it.
    //
    // "Leaving" is read from the two clocks the framework drives, not from the
    // status of this route's own animation: at a pushed route's FIRST build that
    // animation is still the `ProxyAnimation` default (1.0, completed) — measured
    // — so a status test would call the arriving page "settled" on exactly the
    // frame that has to be the reveal. A page being popped reverses its own
    // animation; a page being covered has the page above it moving.
    if (!backStep) {
      return super.buildTransitions(
        context,
        animation,
        secondaryAnimation,
        child,
      );
    }
    final leaving =
        animation.status == AnimationStatus.reverse ||
        !secondaryAnimation.isDismissed;
    if (leaving) {
      return super.buildTransitions(
        context,
        animation,
        secondaryAnimation,
        child,
      );
    }
    // Arriving as a return: the page a pop reveals. Which animation that is
    // comes from the theme, not from this file — see [_builderFor].
    final builder = _builderFor(context);
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
