// test/media_player_keys_test.dart
// The desktop key map for a media surface: which key does what, and — the half
// that is easy to get wrong — which key does NOTHING.
//
// The handler is global (`HardwareKeyboard`), so "does nothing" has to mean
// "returns false and lets the event through", or a player screen becomes a
// keyboard trap for the rest of the app.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/media_player_keys.dart';

/// Every callback wired, each recording into [log].
Widget _host(List<String> log, {Widget? body}) => MaterialApp(
  home: MediaPlayerKeys(
    actions: MediaPlayerKeyActions(
      onTogglePlay: () => log.add('play'),
      onSeek: (d) => log.add('seek${d.inSeconds}'),
      onVolume: (d) => log.add('vol${d > 0 ? '+' : '-'}'),
      onEscape: () => log.add('esc'),
      onToggleFullscreen: () => log.add('fs'),
      onToggleMute: () => log.add('mute'),
      onSpeed: (d) => log.add('rate${d > 0 ? '+' : '-'}'),
    ),
    child: Scaffold(body: body ?? const SizedBox.expand()),
  ),
);

Future<void> _press(WidgetTester tester, LogicalKeyboardKey key) async {
  await tester.sendKeyEvent(key);
  await tester.pump();
}

void main() {
  testWidgets('the player keys are the ones players have taught everyone', (
    tester,
  ) async {
    final log = <String>[];
    await tester.pumpWidget(_host(log));

    await _press(tester, LogicalKeyboardKey.space);
    await _press(tester, LogicalKeyboardKey.keyK);
    await _press(tester, LogicalKeyboardKey.keyM);
    await _press(tester, LogicalKeyboardKey.keyJ);
    await _press(tester, LogicalKeyboardKey.keyL);
    await _press(tester, LogicalKeyboardKey.arrowLeft);
    await _press(tester, LogicalKeyboardKey.arrowRight);
    await _press(tester, LogicalKeyboardKey.arrowUp);
    await _press(tester, LogicalKeyboardKey.arrowDown);
    await _press(tester, LogicalKeyboardKey.comma);
    await _press(tester, LogicalKeyboardKey.period);
    await _press(tester, LogicalKeyboardKey.keyF);
    await _press(tester, LogicalKeyboardKey.escape);

    expect(log, [
      // Space and K are the same action, as they are in video.js (`playPauseKey`
      // is `k` or space) and everywhere else.
      'play',
      'play',
      'mute',
      'seek-10',
      'seek10',
      'seek-10',
      'seek10',
      'vol+',
      'vol-',
      'rate-',
      'rate+',
      'fs',
      'esc',
    ]);
  });

  testWidgets('a key with no callback is left for whoever else wants it', (
    tester,
  ) async {
    // Half a key map: the rest must fall through rather than be swallowed.
    var plays = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: MediaPlayerKeys(
          actions: MediaPlayerKeyActions(onTogglePlay: () => plays++),
          child: const Scaffold(body: SizedBox.expand()),
        ),
      ),
    );
    await _press(tester, LogicalKeyboardKey.keyM);
    await _press(tester, LogicalKeyboardKey.keyJ);
    await _press(tester, LogicalKeyboardKey.period);
    expect(plays, 0);
  });

  testWidgets('arrows stay with a focused slider, other keys do not', (
    tester,
  ) async {
    // A Slider is the one control that needs left/right for its own value; the
    // letters are still the player's.
    final log = <String>[];
    final node = FocusNode();
    addTearDown(node.dispose);
    await tester.pumpWidget(
      _host(
        log,
        body: Slider(value: 0.5, focusNode: node, onChanged: (_) {}),
      ),
    );
    node.requestFocus();
    await tester.pumpAndSettle();

    await _press(tester, LogicalKeyboardKey.arrowLeft);
    await _press(tester, LogicalKeyboardKey.arrowRight);
    await _press(tester, LogicalKeyboardKey.keyM);
    expect(log, ['mute']);
  });

  testWidgets('nothing is stolen while a text field is typing', (tester) async {
    // Regression: the gate tested the focus node's OWN widget, but a focused
    // text field's node belongs to the `EditableText` inside it — so every
    // letter key stayed armed and `m` muted the video instead of typing.
    final log = <String>[];
    final controller = TextEditingController();
    addTearDown(controller.dispose);
    await tester.pumpWidget(
      _host(
        log,
        body: Center(child: TextField(controller: controller, autofocus: true)),
      ),
    );
    await tester.pumpAndSettle();
    expect(FocusManager.instance.primaryFocus, isNotNull);

    await _press(tester, LogicalKeyboardKey.keyM);
    await _press(tester, LogicalKeyboardKey.keyK);
    await _press(tester, LogicalKeyboardKey.space);
    await _press(tester, LogicalKeyboardKey.keyJ);
    await _press(tester, LogicalKeyboardKey.comma);
    await _press(tester, LogicalKeyboardKey.arrowLeft);

    expect(log, isEmpty, reason: 'the keyboard belongs to the field');
  });

  testWidgets('a key-up is not a key-press', (tester) async {
    final log = <String>[];
    await tester.pumpWidget(_host(log));
    await tester.sendKeyDownEvent(LogicalKeyboardKey.keyM);
    await tester.pump();
    expect(log, ['mute']);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.keyM);
    await tester.pump();
    expect(log, ['mute'], reason: 'letting go of M does not mute again');
  });

  testWidgets('the handler is gone once the surface is', (tester) async {
    final log = <String>[];
    await tester.pumpWidget(_host(log));
    await _press(tester, LogicalKeyboardKey.keyM);
    expect(log, ['mute']);

    await tester.pumpWidget(const MaterialApp(home: SizedBox.shrink()));
    await _press(tester, LogicalKeyboardKey.keyM);
    expect(log, [
      'mute',
    ], reason: 'a disposed surface must not keep answering the keyboard');
  });
}
