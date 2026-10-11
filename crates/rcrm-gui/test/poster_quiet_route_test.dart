// test/poster_quiet_route_test.dart
// The player route's two contracts, driven on a live navigator:
//
//  * the transition DIRECTION — a forward step plays the platform's own
//    transition, a back step (the jump history's `Back`) plays what a POP
//    reveals on that platform — and
//  * the hooks the route carries: the poster pool's suspension in `install()`,
//    its release in `dispose()`, and the one warm player created inside the push
//    and handed to the screen's builder.
//
// The measurement is the page's on-screen position (`tester.getTopLeft`), not a
// transition widget's field: that is what the user actually sees, it needs no
// guess about which of the SDK's own `SlideTransition`s is the entering page's,
// and it is the same number on every platform.
//
// What this file CANNOT drive: the player screen itself (it creates a real
// media_kit `Player` in its first frame) and the felt animation. The clock here
// is fake and the times are exact, so what is asserted is the geometry the
// animation produces — not that it feels right on a device.
//
// `PosterQuietRoute.warmPlayerFactory` is stubbed to null for every test: a real
// `Player` cannot be created in a test process (and one that half-succeeded
// would leak a native handle into the next test), so the warm-player handoff is
// asserted through the factory call and the value the builder received.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:media_kit/media_kit.dart';

import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/utils/poster_quiet_route.dart';

/// The MIT's default 800x600 surface; the sideways travel of a transition is
/// stated as a fraction of it.
const double _pageWidth = 800;

/// A navigator whose theme pins [platform], so "the platform's own transition"
/// is a fixed, documented animation instead of whatever the binding defaults to.
Future<NavigatorState> _host(
  WidgetTester tester,
  TargetPlatform platform,
) async {
  late NavigatorState nav;
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(platform: platform),
      home: Builder(
        builder: (c) {
          nav = Navigator.of(c);
          return const Text('library');
        },
      ),
    ),
  );
  return nav;
}

/// Where the player page is on screen right now, in logical pixels.
double _pageX(WidgetTester tester) => tester.getTopLeft(find.text('player')).dx;

/// The same, for any page's text — the page a native pop reveals is the host's.
double _x(WidgetTester tester, String text) =>
    tester.getTopLeft(find.text(text)).dx;

/// One transition, sampled at the SAME fractions of it every time, expressed as
/// offsets from where the page comes to rest: 0 at the transition's first frame
/// (no time has passed yet — the page is at the transition's start), then 10%,
/// 25% and 50% of the platform's own duration, then settled as 0.
///
/// Fractions of `transitionDuration` rather than fixed milliseconds: Android's
/// transition is 450ms and the desktop zoom's is 300ms, so equal millisecond
/// samples would compare different moments — and a sample at or past the end
/// would measure a settled page rather than a moving one. Negative = the page is
/// left of its resting place (a back step), positive = right of it (the
/// platform's forward entrance).
Future<List<double>> _entranceSamples(
  WidgetTester tester, {
  required bool backStep,
  TargetPlatform platform = TargetPlatform.android,
}) async {
  final nav = await _host(tester, platform);
  final route = PosterQuietRoute<void>(
    backStep: backStep,
    build: (_) => const Text('player'),
  );
  nav.push(route);
  await tester.pump();
  // Installed by the push above, which is what `transitionDuration` reads the
  // theme through (`navigator!.context`).
  final duration = route.transitionDuration;
  final samples = <double>[];
  var elapsed = Duration.zero;
  for (final fraction in [0.0, 0.10, 0.25, 0.50]) {
    final at = duration * fraction;
    await tester.pump(at - elapsed);
    elapsed = at;
    samples.add(_pageX(tester));
  }
  await tester.pumpAndSettle();
  final settled = _pageX(tester);
  // Leave the navigator as it was found: the pop is what releases the poster
  // gate, and the 30s idle timer `resume()` arms has to be drained before the
  // test ends (`_drainPosterIdleTimer`).
  nav.pop();
  await tester.pumpAndSettle();
  await _drainPosterIdleTimer(tester);
  return [for (final x in samples) x - settled];
}

/// The platform's OWN answer to "what does going back look like": an ordinary
/// `MaterialPageRoute` is pushed over the host and then popped, and the page the
/// pop REVEALS is sampled exactly like [_entranceSamples] samples a back step.
///
/// This is the reference the back step is held to. It is measured, not
/// transcribed from the SDK: whatever the platform's builder does for a revealed
/// page — Android's slide and fade, Cupertino's own slide, the desktop zoom —
/// shows up here as the same numbers the back step has to produce.
Future<List<double>> _revealSamples(
  WidgetTester tester,
  TargetPlatform platform,
) async {
  final nav = await _host(tester, platform);
  final route = MaterialPageRoute<void>(builder: (_) => const Text('player'));
  nav.push(route);
  await tester.pumpAndSettle();
  nav.pop();
  await tester.pump();
  final duration = route.transitionDuration;
  final samples = <double>[];
  var elapsed = Duration.zero;
  for (final fraction in [0.0, 0.10, 0.25, 0.50]) {
    final at = duration * fraction;
    await tester.pump(at - elapsed);
    elapsed = at;
    samples.add(_x(tester, 'library'));
  }
  await tester.pumpAndSettle();
  final settled = _x(tester, 'library');
  return [for (final x in samples) x - settled];
}

/// Records every call the theme's own builder receives, and animates nothing:
/// the delegation itself is what its tests are about.
///
/// Keyed by route because every route of the navigator goes through the same
/// theme — the host page included, and again on each of its rebuilds. Reading
/// "the last call" instead would quietly assert things about the host page's
/// already-completed animation (value 1.0, secondary 0.0) rather than about the
/// route under test.
class _SpyTransitionBuilder extends PageTransitionsBuilder {
  final List<
    ({
      PageRoute<dynamic> route,
      Animation<double> animation,
      Animation<double> secondary,
    })
  >
  calls = [];

  @override
  Widget buildTransitions<T>(
    PageRoute<T> route,
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    calls.add((
      route: route,
      animation: animation,
      secondary: secondaryAnimation,
    ));
    return child;
  }
}

/// A navigator whose theme pins [platform] AND uses [builder] for it, so the
/// transition under test is the one this file hands the framework.
Future<NavigatorState> _hostWith(
  WidgetTester tester,
  TargetPlatform platform,
  PageTransitionsBuilder builder,
) async {
  late NavigatorState nav;
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(
        platform: platform,
        pageTransitionsTheme: PageTransitionsTheme(
          builders: {platform: builder},
        ),
      ),
      home: Builder(
        builder: (c) {
          nav = Navigator.of(c);
          return const Text('library');
        },
      ),
    ),
  );
  return nav;
}

/// `ThumbnailService.resume()` re-arms the poster pool's 30s idle timer, and a
/// timer still pending when the widget tree goes away fails the test. Firing it
/// is the whole fix: `_tnDisposePool` disposes an empty pool and arms nothing.
Future<void> _drainPosterIdleTimer(WidgetTester tester) =>
    tester.pump(const Duration(seconds: 31));

void main() {
  late Player? Function() productionFactory;

  setUp(() {
    productionFactory = PosterQuietRoute.warmPlayerFactory;
    PosterQuietRoute.warmPlayerFactory = () => null;
  });
  tearDown(() {
    PosterQuietRoute.warmPlayerFactory = productionFactory;
  });

  group('jump-history direction', () {
    testWidgets('a forward step keeps the platform transition (in from the '
        'right on Android)', (tester) async {
      // The Android default is `PredictiveBackPageTransitionsBuilder`, which for
      // a programmatic push falls back to `FadeForwardsPageTransitionsBuilder`:
      // the page slides in from +0.25 of its width over 450ms. Pinned here so
      // the back step below has a direction to differ FROM.
      final samples = await _entranceSamples(tester, backStep: false);
      // Four moving samples; 0 is where the page settles, by construction.
      expect(samples, hasLength(4));
      expect(
        samples.first,
        closeTo(0.25 * _pageWidth, 0.01),
        reason: 'the platform starts the page a quarter of its width out',
      );
      for (final x in samples) {
        expect(x, greaterThan(0), reason: 'forward enters from the right');
        expect(x, lessThanOrEqualTo(0.25 * _pageWidth));
      }
    });

    testWidgets('a back step plays the page a native pop reveals — Android, '
        'sample for sample', (tester) async {
      final native = await _revealSamples(tester, TargetPlatform.android);
      final back = await _entranceSamples(tester, backStep: true);

      expect(back, hasLength(native.length));
      for (var i = 0; i < native.length; i++) {
        expect(
          back[i],
          closeTo(native[i], 0.01),
          reason:
              'sample $i: the back step has to be the platform\'s own '
              'reveal, not merely something that moves leftwards',
        );
      }
      expect(native.first, closeTo(-0.25 * _pageWidth, 0.01));
    });

    testWidgets('iOS/macOS: the back step is Cupertino\'s reveal, not Android\'s '
        'numbers', (tester) async {
      for (final platform in [TargetPlatform.iOS, TargetPlatform.macOS]) {
        final native = await _revealSamples(tester, platform);
        final back = await _entranceSamples(
          tester,
          backStep: true,
          platform: platform,
        );
        for (var i = 0; i < native.length; i++) {
          expect(
            back[i],
            closeTo(native[i], 0.01),
            reason: '$platform sample $i',
          );
        }
        // A third of the width, not a quarter: hand-writing Android's tween for
        // these platforms is what used to be wrong here.
        expect(
          native.first,
          closeTo(-_pageWidth / 3, 0.01),
          reason: '$platform',
        );
      }
    });

    testWidgets('desktop: the back step does not slide sideways', (
      tester,
    ) async {
      // Windows/Linux use `ZoomPageTransitionsBuilder`, which scales and fades
      // and never travels. A sideways slide there is Android's animation painted
      // on a desktop — which is what the back step used to do.
      for (final platform in [TargetPlatform.windows, TargetPlatform.linux]) {
        expect(
          await _entranceSamples(tester, backStep: true, platform: platform),
          everyElement(closeTo(0, 0.001)),
          reason: '$platform',
        );
      }
    });

    testWidgets('the desktop back step replays the pair the framework hands a '
        'revealed page', (tester) async {
      final spy = _SpyTransitionBuilder();
      final nav = await _hostWith(tester, TargetPlatform.windows, spy);
      final route = PosterQuietRoute<void>(
        backStep: true,
        build: (_) => const Text('player'),
      );
      nav.push(route);
      await tester.pump();

      // The calls made for THIS route; the host page's are on it too.
      List<({Animation<double> animation, Animation<double> secondary})>
      mine() => [
        for (final c in spy.calls)
          if (identical(c.route, route))
            (animation: c.animation, secondary: c.secondary),
      ];
      expect(mine(), isNotEmpty, reason: 'the theme\'s builder must be asked');
      expect(
        mine().last.animation.value,
        1.0,
        reason:
            'the revealed page is not entering, so the builder must not also '
            'play an entrance',
      );
      expect(
        identical(mine().last.animation, route.animation),
        isFalse,
        reason:
            'a pop hands the revealed page a completed animation, not this '
            'route\'s own',
      );
      // The page above is going away: 1 -> 0, across this route's own duration.
      expect(mine().last.secondary.value, closeTo(1.0, 0.02));
      await tester.pump(route.transitionDuration * 0.5);
      expect(mine().last.secondary.value, closeTo(0.5, 0.02));
      await tester.pumpAndSettle();
      expect(mine().last.secondary.value, closeTo(0.0, 0.001));

      nav.pop();
      await tester.pumpAndSettle();
      await _drainPosterIdleTimer(tester);
    });

    testWidgets('the forward step is still the platform\'s own call', (
      tester,
    ) async {
      final spy = _SpyTransitionBuilder();
      final nav = await _hostWith(tester, TargetPlatform.windows, spy);
      final route = PosterQuietRoute<void>(build: (_) => const Text('player'));
      nav.push(route);
      await tester.pump();

      final mine = [
        for (final c in spy.calls)
          if (identical(c.route, route)) c,
      ];
      expect(mine, isNotEmpty);
      expect(
        identical(mine.last.animation, route.animation),
        isTrue,
        reason: 'forward is `super.buildTransitions`, with nothing substituted',
      );
      expect(identical(mine.last.secondary, route.secondaryAnimation), isTrue);

      nav.pop();
      await tester.pumpAndSettle();
      await _drainPosterIdleTimer(tester);
    });
  });

  group('the route still carries its hooks', () {
    testWidgets('install() closes the poster gate before the page builds, '
        'dispose() opens it', (tester) async {
      final suspendedAtBuild = <bool>[];
      late NavigatorState nav;
      final route = PosterQuietRoute<void>(
        build: (_) {
          // The certified order: suspend, create (the warm player above),
          // build. Asserted from inside the build callback, i.e. at the moment
          // the pool must already be quiet.
          suspendedAtBuild.add(ThumbnailService.posterSuspended);
          return const Text('player');
        },
      );
      expect(ThumbnailService.posterSuspended, isFalse);

      nav = await _host(tester, TargetPlatform.android);
      nav.push(route);
      await tester.pumpAndSettle();

      expect(suspendedAtBuild, [true]);
      expect(ThumbnailService.posterSuspended, isTrue);

      nav.pop();
      await tester.pumpAndSettle();
      expect(
        ThumbnailService.posterSuspended,
        isFalse,
        reason: 'the route is gone for real: poster work may start again',
      );
      await _drainPosterIdleTimer(tester);
    });

    testWidgets('one warm player per route, created inside the push and handed '
        'to the builder', (tester) async {
      final events = <String>[];
      final handed = <Player?>[];
      PosterQuietRoute.warmPlayerFactory = () {
        events.add('create');
        return null;
      };
      final nav = await _host(tester, TargetPlatform.android);
      nav.push(
        PosterQuietRoute<void>(
          build: (warm) {
            events.add('build');
            handed.add(warm);
            return const Text('player');
          },
        ),
      );
      await tester.pumpAndSettle();

      expect(events, ['create', 'build']);
      expect(handed, [
        null,
      ], reason: 'the factory\'s answer is what is handed on');
      // `buildPage` itself runs once per route (the SDK caches it:
      // `_ModalScopeState._page ??=`), so what `_warmResolved` protects is the
      // rebuild of the modal scope — the player is never re-created per frame.

      nav.pop();
      await tester.pumpAndSettle();
      await _drainPosterIdleTimer(tester);
    });

    testWidgets(
      'a failing factory leaves the screen to create its own player',
      (tester) async {
        PosterQuietRoute.warmPlayerFactory = () => throw StateError('no mpv');
        Player? warm;
        var built = false;
        final nav = await _host(tester, TargetPlatform.android);
        nav.push(
          PosterQuietRoute<void>(
            build: (p) {
              warm = p;
              built = true;
              return const Text('player');
            },
          ),
        );
        await tester.pumpAndSettle();

        expect(
          built,
          isTrue,
          reason:
              'a player that cannot be created must not '
              'stop the screen from mounting',
        );
        expect(warm, isNull, reason: 'the screen falls back to its own player');
        expect(tester.takeException(), isNull);

        nav.pop();
        await tester.pumpAndSettle();
        await _drainPosterIdleTimer(tester);
      },
    );

    testWidgets('the route is still an ordinary page route with its settings', (
      tester,
    ) async {
      final route = PosterQuietRoute<void>(
        backStep: true,
        settings: const RouteSettings(name: '/player'),
        build: (_) => const Text('player'),
      );
      expect(route.settings.name, '/player');
      expect(route.opaque, isTrue);
      expect(route.maintainState, isTrue);

      final nav = await _host(tester, TargetPlatform.android);
      nav.push(route);
      await tester.pumpAndSettle();
      expect(
        ModalRoute.of(tester.element(find.text('player')))?.settings.name,
        '/player',
      );
      nav.pop();
      await tester.pumpAndSettle();
      await _drainPosterIdleTimer(tester);
    });
  });
}
