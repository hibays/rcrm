// test/player_pip_gesture_test.dart
// The floating player's hold-to-2x, and the one framework guarantee it rests on.
//
// The floating window drags (a pan moves it) and holds at 2x (a long press speeds
// the file up) — two recognisers in one arena. That wiring is only safe because
// of something Flutter does rather than something this app decides: once
// `onLongPressStart` has fired, lifting the finger always fires
// `onLongPressEnd`, and moving in between does NOT cancel the hold
// (`LongPressGestureRecognizer.handlePrimaryPointer` — a move while accepted
// reports only `onLongPressMoveUpdate`). Without that pairing, a hold that
// drifted into a drag would leave the file running at 2x with nothing to undo it.
//
// It is an SDK internal, so an engine upgrade is exactly what would break it —
// hence a test rather than a comment that says it is fine.

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  /// The PiP's recogniser set, with the rate writes the screen performs standing
  /// in for as event names: what is under test is which of them fire, and when.
  Widget host(List<String> log) => MaterialApp(
    home: GestureDetector(
      onPanUpdate: (_) => log.add('move'),
      onLongPressStart: (_) => log.add('2x on'),
      onLongPressEnd: (_) => log.add('2x off'),
      child: const ColoredBox(key: ValueKey('surface'), color: Colors.black),
    ),
  );

  testWidgets('a hold that drifts into a drag still gives the end back', (
    tester,
  ) async {
    final log = <String>[];
    await tester.pumpWidget(host(log));

    final g = await tester.startGesture(tester.getCenter(find.byKey(const ValueKey('surface'))));
    await tester.pump(kLongPressTimeout + const Duration(milliseconds: 100));
    expect(log, ['2x on'], reason: 'the file is running at 2x');

    // The finger drifts, which is what a drag looks like. The hold must survive
    // it — and it must not become a drag either, because the arena is spent:
    // a viewer who holds to skim does not also drag the window across the page.
    await g.moveBy(const Offset(40, 0));
    await tester.pump();
    expect(log, ['2x on'], reason: 'the hold is not lost, and not a pan');

    await g.up();
    await tester.pump();
    expect(log, ['2x on', '2x off'], reason: 'and the rate is put back');
  });

  testWidgets('a drag that starts before the hold is a drag, never a 2x', (
    tester,
  ) async {
    final log = <String>[];
    await tester.pumpWidget(host(log));

    final g = await tester.startGesture(tester.getCenter(find.byKey(const ValueKey('surface'))));
    // Past the pan's slop (which is where it takes the arena), then a second
    // move — a pan reports `onPanStart` on the move that crosses slop and only
    // starts reporting updates on the ones after it, which is exactly why a
    // single 40px nudge looks like nothing happened.
    await g.moveBy(const Offset(40, 0));
    await tester.pump();
    await g.moveBy(const Offset(10, 0));
    await tester.pump();
    await tester.pump(kLongPressTimeout + const Duration(milliseconds: 100));
    await g.up();
    await tester.pump();

    expect(log, contains('move'), reason: 'it moved the window');
    // Nothing 2x happened, so there is no rate to restore: the other direction
    // of the same guarantee, and the reason a cancel callback is not needed.
    expect(log.where((e) => e != 'move'), isEmpty);
  });
}