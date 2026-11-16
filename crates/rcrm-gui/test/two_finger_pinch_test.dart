// test/two_finger_pinch_test.dart
// The RAW pointer plumbing of the library's pinch. It deliberately does not use
// Flutter's scale recognizer (which loses the arena to the grid's own drag), so
// these tests drive pointers directly and pin the three things that make the
// gesture trustworthy:
//
//  * one finger is a scroll, never a scale;
//  * two fingers report a scale relative to the span they STARTED on;
//  * letting EITHER finger go ends the gesture — the survivor must not carry on
//    resizing the grid as the finger drags.

import 'package:flutter/gestures.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:rcrm_gui/widgets/two_finger_pinch.dart';

void main() {
  late int starts;
  late int ends;
  late List<double> scales;
  late bool pinching;

  Future<void> pump(WidgetTester tester) async {
    starts = 0;
    ends = 0;
    scales = <double>[];
    pinching = false;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: TwoFingerPinch(
            onStart: () => starts++,
            onEnd: () => ends++,
            onScale: scales.add,
            builder: (_, p) {
              pinching = p;
              return const SizedBox.expand();
            },
          ),
        ),
      ),
    );
  }

  testWidgets('one finger is a scroll, not a pinch', (tester) async {
    await pump(tester);
    final finger = await tester.createGesture(pointer: 1);
    await finger.down(const Offset(200, 300));
    await finger.moveTo(const Offset(200, 500));
    await tester.pump();

    expect(pinching, isFalse);
    expect(starts, 0);
    expect(scales, isEmpty);
    await finger.up();
  });

  testWidgets('two fingers report a scale from the span they started on', (
    tester,
  ) async {
    await pump(tester);
    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);

    await a.down(const Offset(200, 300));
    await b.down(const Offset(300, 300)); // span 100
    await tester.pump();
    expect(pinching, isTrue);
    expect(starts, 1);

    await a.moveTo(const Offset(150, 300));
    await b.moveTo(const Offset(350, 300)); // span 200 -> scale 2
    await tester.pump();
    expect(scales.last, closeTo(2, 0.001));

    // Coming back toward the start reports the smaller cumulative scale, not a
    // second doubling: the reference is the gesture's own first span.
    await a.moveTo(const Offset(240, 300));
    await b.moveTo(const Offset(260, 300)); // span 20 -> scale 0.2
    await tester.pump();
    expect(scales.last, closeTo(0.2, 0.001));

    await a.up();
    await tester.pump();
    expect(pinching, isFalse);
    expect(ends, 1);
    await b.up();
  });

  testWidgets('lifting one finger ends it; the survivor cannot resize', (
    tester,
  ) async {
    await pump(tester);
    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);
    await a.down(const Offset(100, 100));
    await b.down(const Offset(200, 100));
    await tester.pump();
    expect(pinching, isTrue);
    final before = scales.length;

    await b.up();
    await tester.pump();
    expect(pinching, isFalse);
    expect(ends, 1);

    // A finger still down, dragged a long way: no new scale.
    await a.moveTo(const Offset(100, 600));
    await tester.pump();
    expect(scales.length, before, reason: 'a release ends the pinch');
    await a.up();
  });

  testWidgets('a third finger does not rescale the first two', (tester) async {
    await pump(tester);
    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);
    final c = await tester.createGesture(pointer: 3);
    await a.down(const Offset(100, 100));
    await b.down(const Offset(200, 100));
    await c.down(const Offset(300, 100));
    await tester.pump();
    expect(starts, 1);

    await a.moveTo(const Offset(50, 100));
    await b.moveTo(const Offset(250, 100));
    await tester.pump();
    final scale = scales.last;
    await c.moveTo(const Offset(600, 500));
    await tester.pump();
    expect(scales.last, scale, reason: 'a resting third finger is not news');
    await a.up();
    await tester.pump();
    await b.up();
    await c.up();
  });

  testWidgets('lifting a third finger leaves the pair running', (tester) async {
    await pump(tester);
    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);
    final c = await tester.createGesture(pointer: 3);
    await a.down(const Offset(100, 100));
    await b.down(const Offset(200, 100));
    await c.down(const Offset(300, 100));
    await tester.pump();
    expect(pinching, isTrue);

    await c.up();
    await tester.pump();
    expect(pinching, isTrue, reason: 'the pair is still down');
    expect(ends, 0);

    await a.moveTo(const Offset(50, 100));
    await b.moveTo(const Offset(250, 100));
    await tester.pump();
    expect(scales.last, closeTo(2, 0.001));

    await a.up();
    await tester.pump();
    expect(pinching, isFalse);
    expect(ends, 1);
    await b.up();
  });

  testWidgets('a trackpad pan/zoom is only a pinch once its scale moves', (
    tester,
  ) async {
    await pump(tester);
    final pointer = TestPointer(1, PointerDeviceKind.trackpad);

    await tester.sendEventToBinding(
      pointer.panZoomStart(const Offset(300, 300)),
    );
    await tester.sendEventToBinding(
      pointer.panZoomUpdate(const Offset(300, 300), pan: const Offset(0, 40)),
    );
    await tester.pump();
    expect(
      pinching,
      isFalse,
      reason: 'a two-finger trackpad SCROLL shares this event and belongs to '
          'the grid, not to the column count',
    );
    expect(starts, 0);

    await tester.sendEventToBinding(
      pointer.panZoomUpdate(const Offset(300, 300), scale: 1.5),
    );
    await tester.pump();
    expect(pinching, isTrue);
    expect(starts, 1);
    expect(scales.last, closeTo(1.5, 0.001));

    await tester.sendEventToBinding(pointer.panZoomEnd());
    await tester.pump();
    expect(pinching, isFalse);
    expect(ends, 1);
  });
}