// test/player_settings_panel_test.dart
// The player's settings panel: what it offers, and — just as important — what
// it refuses to offer where the platform cannot act on it.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/player_settings_panel.dart';

Widget _host(Widget child) => MaterialApp(
  home: Scaffold(backgroundColor: Colors.black, body: child),
);

Widget _panel({
  PlaybackMode mode = PlaybackMode.pauseAfter,
  ValueChanged<PlaybackMode>? onModeChanged,
  bool autoRotate = false,
  bool showAutoRotate = false,
  List<PlayerMediaFact> facts = const [],
  bool showShortcuts = false,
  VoidCallback? onDismiss,
}) => _host(
  PlayerSettingsPanel(
    mode: mode,
    onModeChanged: onModeChanged ?? (_) {},
    autoRotate: autoRotate,
    onAutoRotateChanged: (_) {},
    onDismiss: onDismiss ?? () {},
    showAutoRotate: showAutoRotate,
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

  testWidgets('the rotation switch is only there where it can act', (
    tester,
  ) async {
    // Rotation is mobile-only and only mobile code acts on it: on desktop this
    // row was a live control that did nothing, which is the one kind of control
    // this app does not ship.
    await tester.pumpWidget(_panel(showAutoRotate: false));
    await tester.pumpAndSettle();
    expect(find.text('Auto-Rotate'), findsNothing);
    expect(find.byType(Switch), findsNothing);

    await tester.pumpWidget(_panel(showAutoRotate: true));
    await tester.pumpAndSettle();
    expect(find.text('Auto-Rotate'), findsOneWidget);
    expect(find.byType(Switch), findsOneWidget);
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
        showAutoRotate: true,
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
