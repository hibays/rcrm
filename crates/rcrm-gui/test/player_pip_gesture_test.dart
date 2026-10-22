// test/player_pip_gesture_test.dart
// The floating player's hold-to-2x, and the two framework guarantees it rests on.
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
// The other guarantee is the one the app has to act on: the pair is only ever
// delivered BY the surface that took the hold, so unmounting that surface
// mid-hold invokes nothing at all — no end ever arrives. Both are SDK internals,
// so an engine upgrade is exactly what would break them; hence tests rather than
// comments that say it is fine.

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

  /// The second guarantee, and the one every teardown path in the screen exists
  /// for: swap the surface that took the hold out of the tree mid-hold, and the
  /// recogniser is disposed without invoking anything — so no `onLongPressEnd`
  /// ever arrives and the rate would stay at 2x with the chip still lit.
  ///
  /// This is not hypothetical. The page's slot is `_pip ? SizedBox(...) : video`,
  /// so the picture leaves the tree the moment the floating window appears under
  /// it (scrolling past the video: the wheel on desktop, a second finger on
  /// touch) and the window leaves when it is scrolled back — which is why
  /// `_onScroll` ends the hold itself on either flip, rather than trusting an end
  /// that cannot come.
  testWidgets('a surface swapped out mid-hold never reports its end', (
    tester,
  ) async {
    final log = <String>[];
    final ctrl = ScrollController();
    addTearDown(ctrl.dispose);
    var swapped = false;

    late StateSetter flip;
    await tester.pumpWidget(
      MaterialApp(
        home: StatefulBuilder(
          builder: (_, setState) {
            flip = setState;
            return Scaffold(
              body: CustomScrollView(
                controller: ctrl,
                slivers: [
                  SliverToBoxAdapter(
                    child: swapped
                        // What the slot becomes while the window is up.
                        ? const SizedBox(width: 200, height: 113)
                        : GestureDetector(
                            onLongPressStart: (_) => log.add('2x on'),
                            onLongPressEnd: (_) => log.add('2x off'),
                            child: const ColoredBox(
                              key: ValueKey('surface'),
                              color: Colors.black,
                              child: SizedBox(height: 300, width: 300),
                            ),
                          ),
                  ),
                  const SliverToBoxAdapter(child: SizedBox(height: 2000)),
                ],
              ),
            );
          },
        ),
      ),
    );

    final g = await tester.startGesture(
      tester.getCenter(find.byKey(const ValueKey('surface'))),
    );
    await tester.pump(kLongPressTimeout + const Duration(milliseconds: 100));
    expect(log, ['2x on'], reason: 'the file is running at 2x');

    // The page scrolls past the picture, and the slot swaps on that frame — the
    // picture out, the window in — with the finger still down.
    ctrl.jumpTo(600);
    flip(() => swapped = true);
    await tester.pump();
    expect(
      find.byKey(const ValueKey('surface')),
      findsNothing,
      reason: 'the surface that took the hold is gone',
    );

    await g.up();
    await tester.pump();
    expect(
      log,
      ['2x on'],
      reason:
          'no end arrives — the surface that would have sent it is gone, which '
          'is exactly why the teardown has to end the hold itself',
    );
  });
}