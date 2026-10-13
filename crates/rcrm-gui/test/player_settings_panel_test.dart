// test/player_settings_panel_test.dart
// The player's settings panel: what it offers, and — just as important — what
// it refuses to offer where the platform cannot act on it.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/player_orientation.dart';
import 'package:rcrm_gui/widgets/player_settings_panel.dart';

Widget _host(Widget child) => MaterialApp(
  home: Scaffold(backgroundColor: Colors.black, body: child),
);

Widget _panel({
  PlaybackMode mode = PlaybackMode.pauseAfter,
  ValueChanged<PlaybackMode>? onModeChanged,
  PlayerOrientation orientation = defaultOrientation,
  ValueChanged<PlayerOrientation>? onOrientationChanged,
  bool showOrientation = false,
  List<PlayerMediaFact> facts = const [],
  bool showShortcuts = false,
  VoidCallback? onDismiss,
}) => _host(
  PlayerSettingsPanel(
    mode: mode,
    onModeChanged: onModeChanged ?? (_) {},
    orientation: orientation,
    onOrientationChanged: onOrientationChanged ?? (_) {},
    onDismiss: onDismiss ?? () {},
    showOrientation: showOrientation,
    facts: facts,
    showShortcuts: showShortcuts,
  ),
);

void main() {
  testWidgets('each mode says what it will really do', (tester) async {
    // "Loop All" and "Loop One" are one letter apart and mean opposite things,
    // and Loop All now arrives through a countdown the viewer can refuse — none
    // of which a two-word segment can carry.
    for (final mode in PlaybackMode.values) {
      await tester.pumpWidget(_panel(mode: mode));
      await tester.pumpAndSettle();
      expect(find.text(mode.label), findsOneWidget);
      expect(
        find.text(mode.note),
        findsOneWidget,
        reason: '${mode.label} explains itself',
      );
    }
    expect(PlaybackMode.loopAll.note, contains('next video'));
    expect(PlaybackMode.loopOne.note, contains('again'));
    expect(PlaybackMode.pauseAfter.note, contains('wait'));
  });

  testWidgets('picking a mode hands it back, selected', (tester) async {
    final picked = <PlaybackMode>[];
    await tester.pumpWidget(
      _panel(mode: PlaybackMode.pauseAfter, onModeChanged: picked.add),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Loop One'));
    expect(picked, [PlaybackMode.loopOne]);
  });

  testWidgets('the orientation row is only there where it can act', (
    tester,
  ) async {
    // Orientation is mobile-only and only mobile code acts on it: on desktop this
    // row would be a live control that did nothing, which is the one kind of
    // control this app does not ship.
    await tester.pumpWidget(_panel(showOrientation: false));
    await tester.pumpAndSettle();
    expect(find.text('Fullscreen Orientation'), findsNothing);
    expect(find.byType(SegmentedButton<OrientationPolicy>), findsNothing);

    await tester.pumpWidget(_panel(showOrientation: true));
    await tester.pumpAndSettle();
    expect(find.text('Fullscreen Orientation'), findsOneWidget);
    expect(find.byType(SegmentedButton<OrientationPolicy>), findsOneWidget);
  });

  testWidgets('the orientation row offers the four strategies, notes included', (
    tester,
  ) async {
    await tester.pumpWidget(_panel(showOrientation: true));
    await tester.pumpAndSettle();
    for (final p in OrientationPolicy.values) {
      expect(find.text(p.label), findsOneWidget, reason: p.label);
    }
    expect(
      find.text(orientationNote(OrientationPolicy.fill)),
      findsOneWidget,
      reason: 'the note follows the choice that is in force',
    );

    // "Follow the phone" is offered on BOTH mobile platforms — Android reaches
    // it with `FULL_SENSOR`, iOS with the hardware posture plus a geometry
    // request — so nothing here drops it. The row as a whole is what desktop
    // does not get (see the test above).
    expect(find.text(OrientationPolicy.device.label), findsOneWidget);

    // Picking another strategy moves the note with it.
    await tester.pumpWidget(
      _panel(
        showOrientation: true,
        orientation: PlayerOrientation.device,
      ),
    );
    await tester.pumpAndSettle();
    expect(
      find.text(orientationNote(OrientationPolicy.device)),
      findsOneWidget,
    );
    expect(find.text(orientationNote(OrientationPolicy.fill)), findsNothing);
  });

  testWidgets('the lock reveals its direction, and neither is a no-op', (
    tester,
  ) async {
    final picked = <PlayerOrientation>[];
    await tester.pumpWidget(
      _panel(
        showOrientation: true,
        orientation: PlayerOrientation.fill,
        onOrientationChanged: picked.add,
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Portrait'), findsNothing);
    expect(find.text('Landscape'), findsNothing);

    // Picking the lock enters it at landscape — this is a video player — and
    // that is what puts the direction row on screen.
    await tester.tap(find.text(OrientationPolicy.lock.label));
    expect(picked, [PlayerOrientation.landscape]);

    await tester.pumpWidget(
      _panel(
        showOrientation: true,
        orientation: PlayerOrientation.portrait,
        onOrientationChanged: picked.add,
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Portrait'), findsOneWidget);
    expect(find.text('Landscape'), findsOneWidget);

    // The policy segment is already chosen, so the framework does not call back
    // for it at all: re-tapping the lock cannot reset the direction the viewer
    // picked, and the direction segment is the way to change it.
    picked.clear();
    await tester.tap(find.text(OrientationPolicy.lock.label));
    expect(picked, isEmpty, reason: 'the lock is already the policy');

    await tester.tap(find.text('Landscape'));
    expect(picked, [PlayerOrientation.landscape]);
  });

  testWidgets('the key map is desktop-only, and lists what is really wired', (
    tester,
  ) async {
    await tester.pumpWidget(_panel(showShortcuts: false));
    await tester.pumpAndSettle();
    expect(find.text('Keyboard'), findsNothing);

    await tester.pumpWidget(_panel(showShortcuts: true));
    await tester.pumpAndSettle();
    expect(find.text('Keyboard'), findsOneWidget);
    // The panel is a reminder of a map that exists in
    // `widgets/media_player_keys.dart`; a key named here that is not wired
    // there would be a promise, not documentation.
    final line = tester.widget<Text>(find.textContaining('Space or K')).data!;
    for (final key in ['Space', 'K', 'J', 'L', 'M', 'F', 'Esc']) {
      expect(line, contains(key), reason: '$key is wired, so $key is named');
    }
    // Directions are words, not glyphs: Roboto (the engine's own font set, and
    // Android's UI font) has no U+2190-2193, so arrows would render as boxes.
    for (final glyph in ['←', '→', '↑', '↓']) {
      expect(line, isNot(contains(glyph)));
    }
    expect(line, contains('Left or Right'));
    expect(line, contains('Up or Down'));
  });

  testWidgets('facts are printed as given, and absent when there are none', (
    tester,
  ) async {
    await tester.pumpWidget(_panel());
    await tester.pumpAndSettle();
    expect(find.text('This Video'), findsNothing);

    await tester.pumpWidget(
      _panel(
        facts: const [
          PlayerMediaFact('Resolution', '1920 × 1080 (1080p)'),
          PlayerMediaFact('Audio', '48.0 kHz · stereo'),
        ],
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('This Video'), findsOneWidget);
    expect(find.text('Resolution'), findsOneWidget);
    expect(find.text('1920 × 1080 (1080p)'), findsOneWidget);
    expect(find.text('Audio'), findsOneWidget);
    expect(find.text('48.0 kHz · stereo'), findsOneWidget);
  });

  testWidgets('a long fact list scrolls instead of overflowing', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(640, 420));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      _panel(
        // The tallest the panel ever gets: both mobile rows, the lock's
        // direction row, and a long fact list.
        showOrientation: true,
        orientation: PlayerOrientation.landscape,
        showShortcuts: true,
        facts: [
          for (var i = 0; i < 14; i++)
            PlayerMediaFact('Fact $i', 'value $i that is fairly long'),
        ],
      ),
    );
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });

  testWidgets('tapping the scrim dismisses, tapping the panel does not', (
    tester,
  ) async {
    var dismissed = 0;
    await tester.binding.setSurfaceSize(const Size(900, 900));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(_panel(onDismiss: () => dismissed++));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Playback Settings'));
    expect(dismissed, 0, reason: 'a tap inside is not a dismissal');

    await tester.tapAt(const Offset(8, 8));
    expect(dismissed, 1);
  });
}
