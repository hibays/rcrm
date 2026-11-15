// test/viewer_gesture_model_test.dart
// The viewer's gesture state tree in isolation.
//
// The bug these pin is the one no single handler could see: the raw pointer
// Listener (pull-to-dismiss) and the ScaleGestureRecognizer (pager + pinch)
// each thought they owned a two-finger gesture, so a pinch with a downward
// drift pulled — and sometimes dismissed — the photo it was zooming. The
// state tree makes ownership one fact, decided once, with zoom first.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/viewer_gesture.dart';

void main() {
  group('axis lock (the old behaviour, unchanged)', () {
    test('a sideways lead commits to the pager', () {
      expect(
        decideViewerGestureOwner(const Offset(-40, 5), pullAllowed: true),
        ViewerGestureOwner.page,
      );
    });

    test('a downward lead commits to the pull', () {
      expect(
        decideViewerGestureOwner(const Offset(5, 20), pullAllowed: true),
        ViewerGestureOwner.pull,
      );
    });

    test('tremor under the slop decides nothing', () {
      expect(
        decideViewerGestureOwner(const Offset(3, 4), pullAllowed: true),
        isNull,
      );
    });

    test('a blocked pull never takes the pager with it', () {
      // A zoomed picture or a playing live photo: the downward lane is shut,
      // but a sideways drag still turns the page.
      expect(
        decideViewerGestureOwner(const Offset(0, 40), pullAllowed: false),
        isNull,
      );
      expect(
        decideViewerGestureOwner(const Offset(-40, 5), pullAllowed: false),
        ViewerGestureOwner.page,
      );
    });
  });

  group('one owner per sequence', () {
    test('the first finger starts undecided; a second makes it a pinch', () {
      var g = ViewerGesture.idle.pointerDown(1);
      expect(g.owner, ViewerGestureOwner.undecided);
      expect(g.isActive, isTrue);

      g = g.pointerDown(2);
      expect(g.owner, ViewerGestureOwner.zoom);
      expect(g.pointers, {1, 2});
    });

    test('two fingers can never commit to the pull, however they travel', () {
      var g = ViewerGesture.idle.pointerDown(1).pointerDown(2);
      // Either finger's own downward travel used to be enough to engage the
      // pull, because the origin was reset on the second down.
      for (var i = 0; i < 20; i++) {
        g = g.pointerMove(const Offset(0, 100), pullAllowed: true);
        expect(g.owner, ViewerGestureOwner.zoom);
      }
    });

    test('a decided sequence keeps its owner when the finger curves', () {
      var g = ViewerGesture.idle.pointerDown(1);
      g = g.pointerMove(const Offset(40, 0), pullAllowed: true);
      expect(g.owner, ViewerGestureOwner.page);
      // It dives down afterwards: the pager still owns it.
      g = g.pointerMove(const Offset(40, 400), pullAllowed: true);
      expect(g.owner, ViewerGestureOwner.page);
    });

    test('lifting one finger of a pinch leaves it zoomed', () {
      var g = ViewerGesture.idle.pointerDown(1).pointerDown(2);
      g = g.pointerUp(1);
      expect(g.owner, ViewerGestureOwner.zoom);
      expect(g.isActive, isTrue);
      // The remaining finger's downward travel must not become a pull.
      g = g.pointerMove(const Offset(0, 500), pullAllowed: true);
      expect(g.owner, ViewerGestureOwner.zoom);
    });

    test('the last lift keeps the owner readable, finish clears it', () {
      var g = ViewerGesture.idle
          .pointerDown(1)
          .pointerMove(const Offset(0, 40), pullAllowed: true);
      expect(g.owner, ViewerGestureOwner.pull);
      g = g.pointerUp(1);
      expect(g.isActive, isFalse);
      // The scale recognizer's end arrives after the pointer Listener's up and
      // still has to know the sequence was a pull.
      expect(g.owner, ViewerGestureOwner.pull);
      expect(g.finish(), ViewerGesture.idle);
    });

    test('starting on a zoomed picture is a pan, not a pull', () {
      final g = ViewerGesture.idle.pointerDown(1, zoomed: true);
      expect(g.owner, ViewerGestureOwner.zoom);
    });

    test('a fresh sequence after the last lift starts clean', () {
      var g = ViewerGesture.idle
          .pointerDown(1)
          .pointerMove(const Offset(0, 40), pullAllowed: true)
          .pointerUp(1)
          .finish();
      g = g.pointerDown(7);
      expect(g.owner, ViewerGestureOwner.undecided);
      expect(g.pointers, {7});
    });
  });
}
