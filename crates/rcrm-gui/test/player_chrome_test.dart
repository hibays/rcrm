// test/player_chrome_test.dart
// Widget-level guarantees for the player chrome: it fits at every shipped
// device size, it keeps the controls that have no alternative, the fullscreen
// top bar owns back + settings, and the 2x badge's chevrons really animate.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/widgets/player_controls.dart';

const _position = Duration(minutes: 1, seconds: 23);
const _duration = Duration(minutes: 42, seconds: 5);

Widget _host(Widget child) => MaterialApp(
  home: Scaffold(
    backgroundColor: Colors.black,
    body: Stack(
      children: [Positioned(left: 0, right: 0, bottom: 0, child: child)],
    ),
  ),
);

Future<void> _pumpBar(
  WidgetTester tester, {
  required Size size,
  bool fullscreen = false,
  bool playing = false,
  double volume = 100,
  double speed = 1.0,
  bool hasPrev = false,
  bool hasNext = true,
  bool hasEpisodes = true,
  PlayerTimeMode timeMode = PlayerTimeMode.elapsed,
  VoidCallback? onTimeModeChanged,
  VoidCallback? onPlayPause,
  VoidCallback? onToggleMute,
  VoidCallback? onPrev,
  ValueChanged<double>? onVolumeChanged,
  ValueChanged<Duration>? onSeek,
}) async {
  await tester.binding.setSurfaceSize(size);
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    _host(
      PlayerControlBar(
        playing: playing,
        position: _position,
        duration: _duration,
        buffer: const Duration(minutes: 2),
        volume: volume,
        speed: speed,
        fullscreen: fullscreen,
        hasPrev: hasPrev,
        hasNext: hasNext,
        hasEpisodes: hasEpisodes,
        timeMode: timeMode,
        onTimeModeChanged: onTimeModeChanged,
        onPlayPause: onPlayPause ?? () {},
        onToggleMute: onToggleMute ?? () {},
        onVolumeChanged: onVolumeChanged,
        onSeek: onSeek,
        onFullscreen: () {},
        onNext: () {},
        onPrev: onPrev ?? () {},
        onEpisodes: () {},
        onSpeedChanged: (_) {},
      ),
    ),
  );
}

void main() {
  group('PlayerControlBar layout', () {
    const sizes = <String, Size>{
      'tiny window': Size(250, 500),
      'small laptop window': Size(320, 480),
      'portrait phone': Size(360, 640),
      'large portrait phone': Size(411, 891),
      'landscape phone fullscreen': Size(640, 360),
      'wide phone fullscreen': Size(800, 360),
      'tablet landscape': Size(1024, 768),
      'desktop window': Size(1280, 720),
      'desktop fullscreen': Size(1920, 1080),
    };

    for (final entry in sizes.entries) {
      testWidgets('renders without overflow — ${entry.key}', (tester) async {
        await _pumpBar(
          tester,
          size: entry.value,
          fullscreen: entry.value.width > entry.value.height,
        );
        await tester.pump(const Duration(milliseconds: 250));
        expect(tester.takeException(), isNull);
        expect(find.byType(Slider), findsAtLeast(1));
      });
    }

    testWidgets('tight portrait phone: volume slider yields, nothing else', (
      tester,
    ) async {
      await _pumpBar(
        tester,
        size: const Size(360, 640),
        hasPrev: true,
        volume: 60,
      );
      // Seek slider only — the volume slider gave its space back.
      expect(find.byType(Slider), findsOneWidget);
      // ...but the mute button is still there, and so is skipping.
      // (flutter_test's font is monospace-wide, so this width is the
      // pessimistic case: on a real 360dp phone the speed chip also survives.)
      expect(find.byIcon(Icons.volume_up), findsOneWidget);
      expect(find.byIcon(Icons.skip_next), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.fullscreen), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('the PAINTED bar fits at every width, not just nine sizes', (
      tester,
    ) async {
      // The layout test pins the plan's arithmetic; this pins the pixels. A
      // plan that budgets differently from what it paints (or a tier that runs
      // out of floor) shows up here as a RenderFlex overflow.
      //
      // The sweep starts BELOW the tiny tier's three-button floor (108dp): that
      // is where the plan has to start dropping controls, and starting at 120dp
      // — as this loop used to — skipped the only band that could overflow.
      for (var width = 40.0; width <= 900; width += 10) {
        await _pumpBar(tester, size: Size(width, 500), hasPrev: true);
        await tester.pump(const Duration(milliseconds: 16));
        expect(
          tester.takeException(),
          isNull,
          reason: 'the bar overflowed at ${width}dp',
        );
      }
      // The tier boundaries themselves.
      for (final width in [
        139.0,
        140.0,
        141.0,
        339.0,
        340.0,
        341.0,
        519.0,
        520.0,
      ]) {
        await _pumpBar(tester, size: Size(width, 500), hasPrev: true);
        await tester.pump(const Duration(milliseconds: 16));
        expect(
          tester.takeException(),
          isNull,
          reason: 'the bar overflowed at the ${width}dp tier boundary',
        );
      }
    });

    testWidgets('the narrowest bar still offers play, mute and fullscreen', (
      tester,
    ) async {
      // `volume: 40` is the quiet half of the mute button's range, so the icon
      // is `volume_down` — the control is still the mute toggle either way,
      // which is what this test is about.
      await _pumpBar(tester, size: const Size(120, 500), volume: 40);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.volume_down), findsOneWidget);
      expect(find.byIcon(Icons.fullscreen), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('below the three-button floor it drops the replaceable ones', (
      tester,
    ) async {
      // 3 x 32dp targets + gaps + padding = 108dp. Under that, something has to
      // give: fullscreen first (F11 and the window chrome still do it), then
      // mute (the volume gestures and keys still do). Play/pause stays — it has
      // no alternative — and the row fits instead of painting an overflow.
      await _pumpBar(tester, size: const Size(100, 500));
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.fullscreen), findsNothing);
      expect(tester.takeException(), isNull);

      await _pumpBar(tester, size: const Size(70, 500));
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.volume_up), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets('a tap target paints exactly what the tier budgets', (
      tester,
    ) async {
      // Regression: the default padded tap target plus VisualDensity.compact
      // shrank a 44/48dp tier to 40 while the width budget still spent 44/48.
      const cases = <String, (Size, bool)>{
        'compact': (Size(360, 640), false),
        'regular': (Size(500, 900), false),
        'expanded': (Size(1280, 720), false),
        'expanded fullscreen': (Size(1920, 1080), true),
      };
      for (final entry in cases.entries) {
        final (size, fullscreen) = entry.value;
        await _pumpBar(tester, size: size, fullscreen: fullscreen);
        final m = PlayerChromeMetrics.of(
          size,
          fullscreen: fullscreen,
        ).cappedTo(size.width);
        final painted = tester.getSize(
          find
              .ancestor(
                of: find.byIcon(Icons.play_arrow),
                matching: find.byType(IconButton),
              )
              .first,
        );
        expect(
          painted,
          Size(m.tap, m.tap),
          reason: '${entry.key}: painted $painted, budgeted ${m.tap}',
        );
      }
    });

    testWidgets('no dead skip buttons: one is painted only when it can act', (
      tester,
    ) async {
      // Nothing to go back to → no button at all. A greyed-out slot was tried
      // and rejected: it puts a control in the row that can do nothing for as
      // long as the user has not jumped, and every bar size has to reserve its
      // width for it.
      await _pumpBar(tester, size: const Size(1280, 720), hasPrev: false);
      expect(find.byIcon(Icons.skip_previous), findsNothing);

      var taps = 0;
      await _pumpBar(
        tester,
        size: const Size(1280, 720),
        hasPrev: true,
        onPrev: () => taps++,
      );
      expect(find.byIcon(Icons.skip_previous), findsOneWidget);
      await tester.tap(find.byIcon(Icons.skip_previous));
      expect(taps, 1);

      // The other side of the pair keeps the same rule.
      await _pumpBar(tester, size: const Size(1280, 720), hasNext: false);
      expect(find.byIcon(Icons.skip_next), findsNothing);
      await _pumpBar(tester, size: const Size(1280, 720), hasNext: true);
      expect(find.byIcon(Icons.skip_next), findsOneWidget);
    });

    testWidgets('hasPrev/hasNext are read on every build, never captured once', (
      tester,
    ) async {
      // Two pumps over the same widget type update the element IN PLACE — the
      // assertions on the state object below prove it — so this is the live path
      // the screen drives with `ref.watch(videoJumpStackProvider)`: the bar
      // rebuilds and the plan is recomputed from the fields it was just handed.
      // Caching the plan (or the buttons) would leave the row stale until
      // something else forced a remount.
      await _pumpBar(tester, size: const Size(1280, 720), hasPrev: false);
      final state = tester.state(find.byType(PlayerControlBar));
      expect(find.byIcon(Icons.skip_previous), findsNothing);

      await _pumpBar(tester, size: const Size(1280, 720), hasPrev: true);
      expect(
        identical(tester.state(find.byType(PlayerControlBar)), state),
        isTrue,
        reason: 'same element: an update, not a remount',
      );
      expect(find.byIcon(Icons.skip_previous), findsOneWidget);

      // ...and back to empty, still in place.
      await _pumpBar(tester, size: const Size(1280, 720), hasPrev: false);
      expect(
        identical(tester.state(find.byType(PlayerControlBar)), state),
        isTrue,
      );
      expect(find.byIcon(Icons.skip_previous), findsNothing);
    });

    testWidgets('when there is room, every control is there', (tester) async {
      await _pumpBar(
        tester,
        size: const Size(900, 900),
        hasPrev: true,
        volume: 60,
        speed: 1.25,
      );
      expect(find.byType(Slider), findsNWidgets(2));
      expect(find.byIcon(Icons.skip_previous), findsOneWidget);
      expect(find.byIcon(Icons.skip_next), findsOneWidget);
      expect(find.byIcon(Icons.playlist_play), findsOneWidget);
      expect(find.text('1.25x'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('wide screen: the volume slider is back', (tester) async {
      await _pumpBar(tester, size: const Size(1280, 720), volume: 60);
      expect(find.byType(Slider), findsNWidgets(2));
    });

    testWidgets('muting swaps the icon and keeps the control reachable', (
      tester,
    ) async {
      var muted = 0;
      await _pumpBar(
        tester,
        size: const Size(360, 640),
        volume: 0,
        onToggleMute: () => muted++,
      );
      expect(find.byIcon(Icons.volume_off), findsOneWidget);
      await tester.tap(find.byIcon(Icons.volume_off));
      expect(muted, 1);
    });

    testWidgets('the mute button reports how loud it is, in three states', (
      tester,
    ) async {
      // Regression: `volume > 0` was the whole test, so 5% and 95% both drew a
      // full speaker. Silence is the only state that may read as off.
      await _pumpBar(tester, size: const Size(1280, 720), volume: 100);
      expect(find.byIcon(Icons.volume_up), findsOneWidget);

      await _pumpBar(tester, size: const Size(1280, 720), volume: 49);
      expect(find.byIcon(Icons.volume_down), findsOneWidget);
      expect(find.byIcon(Icons.volume_up), findsNothing);

      await _pumpBar(tester, size: const Size(1280, 720), volume: 50);
      expect(
        find.byIcon(Icons.volume_up),
        findsOneWidget,
        reason: 'the boundary belongs to the loud half',
      );

      await _pumpBar(tester, size: const Size(1280, 720), volume: 0);
      expect(find.byIcon(Icons.volume_off), findsOneWidget);
      expect(find.byIcon(Icons.volume_down), findsNothing);
    });

    testWidgets('fullscreen button reflects state', (tester) async {
      await _pumpBar(tester, size: const Size(1280, 720), fullscreen: false);
      expect(find.byIcon(Icons.fullscreen), findsOneWidget);
      await _pumpBar(tester, size: const Size(1280, 720), fullscreen: true);
      expect(find.byIcon(Icons.fullscreen_exit), findsOneWidget);
    });

    testWidgets('long videos show hours, and the text still fits', (
      tester,
    ) async {
      await tester.binding.setSurfaceSize(const Size(360, 640));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        _host(
          PlayerControlBar(
            playing: true,
            position: const Duration(hours: 1, minutes: 58, seconds: 7),
            duration: const Duration(hours: 2, minutes: 3, seconds: 9),
            buffer: Duration.zero,
            volume: 100,
            speed: 1.0,
            fullscreen: false,
            onSeek: (_) {},
          ),
        ),
      );
      expect(tester.takeException(), isNull);
      expect(find.text('1:58:07'), findsOneWidget);
      expect(find.text(' / 2:03:09'), findsOneWidget);
    });

    testWidgets('speed chip shows the player rate, not a local guess', (
      tester,
    ) async {
      await _pumpBar(tester, size: const Size(1280, 720), speed: 1.5);
      expect(find.text('1.5x'), findsOneWidget);
      await _pumpBar(tester, size: const Size(1280, 720), speed: 1.0);
      expect(find.text('1x'), findsOneWidget);
    });

    testWidgets(
      'the same row reports the accent only while a rate is altered',
      (tester) async {
        // The chip is the one control that reports a STATE rather than offering
        // an action, so it is where the accent earns its place: 1.5x should be
        // answerable from across the room, 1x should not shout.
        Color chipColour(String label) =>
            tester.widget<Text>(find.text(label)).style!.color!;

        await _pumpBar(tester, size: const Size(1280, 720), speed: 1.0);
        expect(chipColour('1x'), isNot(RCrmColors.primary));

        await _pumpBar(tester, size: const Size(1280, 720), speed: 1.25);
        expect(chipColour('1.25x'), RCrmColors.primary);
      },
    );
  });

  group('PlayerControlBar time readout', () {
    testWidgets('reads elapsed over total, and hands the tap back', (
      tester,
    ) async {
      var swaps = 0;
      await _pumpBar(
        tester,
        size: const Size(1280, 720),
        onTimeModeChanged: () => swaps++,
      );
      expect(find.text('01:23'), findsOneWidget);
      expect(find.text(' / 42:05'), findsOneWidget);

      await tester.tap(find.text('01:23'));
      expect(swaps, 1);
      await tester.tap(find.text(' / 42:05'));
      expect(swaps, 2, reason: 'the whole pair is the target, not one number');
    });

    testWidgets('in remaining mode the second number counts down', (
      tester,
    ) async {
      await _pumpBar(
        tester,
        size: const Size(1280, 720),
        timeMode: PlayerTimeMode.remaining,
        onTimeModeChanged: () {},
      );
      expect(find.text('01:23'), findsOneWidget);
      // 42:05 minus 1:23.
      expect(find.text(' / -40:42'), findsOneWidget);
      expect(find.text(' / 42:05'), findsNothing);
    });

    testWidgets('an unknown duration never reads as a countdown', (
      tester,
    ) async {
      // There is no remaining time before there is a total, and "-00:00" would
      // be an invention.
      await tester.binding.setSurfaceSize(const Size(1280, 720));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        _host(
          PlayerControlBar(
            playing: true,
            position: Duration.zero,
            duration: Duration.zero,
            buffer: Duration.zero,
            volume: 100,
            speed: 1.0,
            fullscreen: false,
            timeMode: PlayerTimeMode.remaining,
            onTimeModeChanged: () {},
            onSeek: (_) {},
          ),
        ),
      );
      expect(find.text(' / 00:00'), findsOneWidget);
      expect(find.textContaining('-00:00'), findsNothing);
    });

    testWidgets('swapping the reading never re-plans the row', (tester) async {
      // Both readings are budgeted whether or not one is on screen, so a tap
      // cannot make a control disappear — which at a marginal width is exactly
      // what a re-plan would do to the duration the user just asked for.
      for (final width in [360.0, 400.0, 440.0, 520.0, 900.0]) {
        Future<Set<String>> controlsFor(PlayerTimeMode mode) async {
          await _pumpBar(
            tester,
            size: Size(width, 720),
            timeMode: mode,
            onTimeModeChanged: () {},
          );
          final icons = tester
              .widgetList<Icon>(find.byType(Icon))
              .map((i) => i.icon!.codePoint.toString())
              .toSet();
          // The two readings are different strings by design; what must not
          // change is whether the slot is there at all.
          final texts = tester
              .widgetList<Text>(find.byType(Text))
              .map((t) => t.data ?? '')
              .map((t) => t.startsWith(' / ') ? '<duration>' : t)
              .where((t) => t.trim().isNotEmpty)
              .toSet();
          return {...icons, ...texts};
        }

        final elapsed = await controlsFor(PlayerTimeMode.elapsed);
        final remaining = await controlsFor(PlayerTimeMode.remaining);
        expect(
          remaining,
          elapsed,
          reason: 'the row changed shape at ${width}dp when the reading did',
        );
      }
    });

    testWidgets('with no swap on offer it is plain text', (tester) async {
      // Icon buttons carry tooltips of their own, so the question is not
      // whether a Tooltip exists but whether the TIME has one.
      await _pumpBar(
        tester,
        size: const Size(1280, 720),
        onTimeModeChanged: () {},
      );
      expect(
        find.ancestor(of: find.text('01:23'), matching: find.byType(Tooltip)),
        findsOneWidget,
      );

      await _pumpBar(tester, size: const Size(1280, 720));
      expect(
        find.ancestor(of: find.text('01:23'), matching: find.byType(Tooltip)),
        findsNothing,
      );
      await tester.tap(find.text('01:23'));
      expect(tester.takeException(), isNull);
    });
  });

  group('PlayerControlBar interaction', () {
    testWidgets('play/pause taps reach the caller', (tester) async {
      var taps = 0;
      await _pumpBar(
        tester,
        size: const Size(1280, 720),
        onPlayPause: () => taps++,
      );
      await tester.tap(find.byIcon(Icons.play_arrow));
      expect(taps, 1);
      await _pumpBar(
        tester,
        size: const Size(1280, 720),
        playing: true,
        onPlayPause: () => taps++,
      );
      expect(find.byIcon(Icons.pause), findsOneWidget);
      await tester.tap(find.byIcon(Icons.pause));
      expect(taps, 2);
    });

    testWidgets('dragging the seek bar reports one settled position', (
      tester,
    ) async {
      final seeks = <Duration>[];
      await _pumpBar(tester, size: const Size(1280, 720), onSeek: seeks.add);
      final slider = find.byType(Slider).first;
      final box = tester.getRect(slider);
      await tester.dragFrom(
        Offset(box.left + box.width * 0.1, box.center.dy),
        Offset(box.width * 0.4, 0),
      );
      await tester.pumpAndSettle();
      expect(seeks, hasLength(1));
      expect(seeks.single.inSeconds, greaterThan(60 * 10));
    });

    testWidgets('volume drags stream through onVolumeChanged', (tester) async {
      final values = <double>[];
      await _pumpBar(
        tester,
        size: const Size(1280, 720),
        volume: 50,
        onVolumeChanged: values.add,
      );
      final volumeSlider = find.byType(Slider).last;
      final box = tester.getRect(volumeSlider);
      await tester.dragFrom(box.center, const Offset(-30, 0));
      await tester.pumpAndSettle();
      expect(values, isNotEmpty);
      expect(values.last, lessThan(50));
    });
  });

  group('PlayerTopBar', () {
    testWidgets('carries back, home, title and settings', (tester) async {
      var backs = 0;
      var homes = 0;
      var settings = 0;
      await tester.binding.setSurfaceSize(const Size(640, 360));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            backgroundColor: Colors.black,
            body: Align(
              alignment: Alignment.topCenter,
              child: PlayerTopBar(
                title: 'holiday.mp4',
                onBack: () => backs++,
                onHome: () => homes++,
                onSettings: () => settings++,
              ),
            ),
          ),
        ),
      );
      expect(find.text('holiday.mp4'), findsOneWidget);
      expect(find.byIcon(Icons.arrow_back), findsOneWidget);
      // Home is a way OUT of the player chain, not a jump step: it sits beside
      // back, and the transport bar keeps the history's one-step skip buttons.
      // (It is absent while the history is empty — see the next test.)
      expect(find.byIcon(Icons.home), findsOneWidget);
      expect(find.byIcon(Icons.settings), findsOneWidget);
      await tester.tap(find.byIcon(Icons.arrow_back));
      await tester.tap(find.byIcon(Icons.home));
      await tester.tap(find.byIcon(Icons.settings));
      expect(backs, 1);
      expect(homes, 1);
      expect(settings, 1);
      expect(tester.takeException(), isNull);
    });

    testWidgets('no home button while the jump history is empty', (
      tester,
    ) async {
      // `onHome: null` is that case. Back already leaves the player when there is
      // nothing to retrace, so Home would be the same action twice; it appears
      // once the two really differ (`_go` vs one step back).
      await tester.binding.setSurfaceSize(const Size(640, 360));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            backgroundColor: Colors.black,
            body: Align(
              alignment: Alignment.topCenter,
              child: PlayerTopBar(title: 'holiday.mp4', onBack: () {}),
            ),
          ),
        ),
      );
      expect(find.byIcon(Icons.arrow_back), findsOneWidget);
      expect(find.byIcon(Icons.home), findsNothing);
      expect(find.text('holiday.mp4'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('a long title ellipsises instead of pushing the gear out', (
      tester,
    ) async {
      await tester.binding.setSurfaceSize(const Size(360, 640));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Align(
              alignment: Alignment.topCenter,
              child: PlayerTopBar(
                title: 'a-very-long-episode-name-that-would-never-fit-' * 3,
                onBack: () {},
                onHome: () {},
                onSettings: () {},
              ),
            ),
          ),
        ),
      );
      expect(tester.takeException(), isNull);
      expect(find.byIcon(Icons.settings), findsOneWidget);
      expect(find.byIcon(Icons.arrow_back), findsOneWidget);
      expect(find.byIcon(Icons.home), findsOneWidget);
    });

    testWidgets('no settings button in the windowed player', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Align(
              alignment: Alignment.topCenter,
              child: PlayerTopBar(
                title: 'clip.mp4',
                onBack: () {},
                onHome: () {},
              ),
            ),
          ),
        ),
      );
      expect(find.byIcon(Icons.settings), findsNothing);
    });
  });

  group('PlayerSpeedBadge', () {
    List<double> chevronAlphas(WidgetTester tester) => tester
        .widgetList<Icon>(find.byIcon(Icons.play_arrow))
        .map((i) => i.color!.a)
        .toList();

    testWidgets('chevrons animate while held (not frozen on frame one)', (
      tester,
    ) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: PlayerSpeedBadge(visible: true)),
        ),
      );
      final t0 = chevronAlphas(tester);
      expect(t0, hasLength(3));
      await tester.pump(const Duration(milliseconds: 150));
      final t1 = chevronAlphas(tester);
      await tester.pump(const Duration(milliseconds: 150));
      final t2 = chevronAlphas(tester);
      expect(t1, isNot(equals(t0)));
      expect(t2, isNot(equals(t1)));
    });

    testWidgets('stays mounted while hidden so the exit can fade', (
      tester,
    ) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: PlayerSpeedBadge(visible: true)),
        ),
      );
      await tester.pump(const Duration(milliseconds: 200));
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: PlayerSpeedBadge(visible: false)),
        ),
      );
      // Mid-fade the badge is still painted...
      await tester.pump(const Duration(milliseconds: 80));
      final opacity = tester
          .widgetList<FadeTransition>(find.byType(FadeTransition))
          .map((f) => f.opacity.value)
          .toList();
      final faded = tester
          .widgetList<AnimatedOpacity>(find.byType(AnimatedOpacity))
          .map((a) => a.opacity)
          .toList();
      expect(find.byType(PlayerSpeedBadge), findsOneWidget);
      // ...driven by the animation, not snapped.
      expect([...opacity, ...faded].any((v) => v > 0 && v < 1), isTrue);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    });
  });

  group('PlayerGestureChip', () {
    testWidgets('keeps its last value while fading out', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: PlayerGestureChip(brightness: false, value: 42)),
        ),
      );
      expect(find.text('42%'), findsOneWidget);
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlayerGestureChip(brightness: false, value: null),
          ),
        ),
      );
      await tester.pump(const Duration(milliseconds: 60));
      // Still showing the value it faded out with — never a flash of "0%".
      expect(find.text('42%'), findsOneWidget);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    });
  });
}
