// test/library_columns_test.dart
// The library's column arithmetic, pinned where it runs: a pinch is an analogue
// gesture aiming at a discrete number, and the rules that turn one into the
// other are easy to get subtly wrong (the wrong reference point, the wrong
// direction, a threshold that flickers).
//
// Nothing here mounts a widget: the tests in `two_finger_pinch_test.dart` own
// the pointer plumbing, and `image_ungrouped_test.dart` / `video_folders_test`
// own what the screens render.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/library_columns.dart';

void main() {
  group('pinchColumnCount', () {
    test('scale 1 leaves the count alone', () {
      expect(pinchColumnCount(startColumns: 4, scale: 1, min: 1, max: 8), 4);
    });

    test('spreading the fingers asks for FEWER, bigger cells', () {
      expect(pinchColumnCount(startColumns: 4, scale: 2, min: 1, max: 8), 2);
      expect(pinchColumnCount(startColumns: 6, scale: 3, min: 1, max: 8), 2);
    });

    test('pinching in asks for more cells per line', () {
      expect(pinchColumnCount(startColumns: 3, scale: 0.5, min: 1, max: 8), 6);
    });

    test('the answer is clamped to the range the build would show', () {
      expect(pinchColumnCount(startColumns: 4, scale: 4, min: 2, max: 8), 2);
      expect(pinchColumnCount(startColumns: 4, scale: 0.1, min: 2, max: 8), 8);
      // A start outside the range is itself brought inside it.
      expect(pinchColumnCount(startColumns: 12, scale: 1, min: 2, max: 8), 8);
    });

    test('the mapping is from the START count, not the live one', () {
      // What the caller must keep: two calls at the same scale answer the same
      // number even after the grid has already resized between them.
      final first = pinchColumnCount(startColumns: 4, scale: 2, min: 1, max: 8);
      final second = pinchColumnCount(
        startColumns: 4,
        scale: 2,
        min: 1,
        max: 8,
      );
      expect(first, second);
      expect(first, 2);
      // The compounded version (feeding 2 back in) is the bug: it would say 1.
      expect(pinchColumnCount(startColumns: 2, scale: 2, min: 1, max: 8), 1);
    });

    test('a broken scale is not a column count', () {
      for (final bad in [0.0, -1.0, double.nan, double.infinity]) {
        expect(
          pinchColumnCount(startColumns: 3, scale: bad, min: 2, max: 8),
          3,
          reason: '$bad must leave the grid where it was',
        );
      }
    });
  });

  group('pinchListColumns', () {
    test('a pinch must travel before the list changes its answer', () {
      expect(pinchListColumns(scale: 1), isNull);
      expect(pinchListColumns(scale: 1.19), isNull);
      expect(pinchListColumns(scale: 0.84), isNull);
    });

    test('spreading = one row per line; pinching in = two', () {
      expect(pinchListColumns(scale: kPinchListStep), 1);
      expect(pinchListColumns(scale: 2), 1);
      expect(pinchListColumns(scale: 1 / kPinchListStep), 2);
      expect(pinchListColumns(scale: 0.5), 2);
    });

    test('a broken scale never flips the layout', () {
      for (final bad in [0.0, -1.0, double.nan, double.infinity]) {
        expect(pinchListColumns(scale: bad), isNull);
      }
    });
  });

  group('videoListColumnCount', () {
    test('auto is one column until the 840dp expanded breakpoint', () {
      expect(videoListColumnCount(mode: 'auto', width: 839), 1);
      expect(videoListColumnCount(mode: 'auto', width: 840), 2);
      expect(videoListColumnCount(mode: 'auto', width: 1920), 2);
    });

    test('an explicit One wins at every width', () {
      expect(videoListColumnCount(mode: 'one', width: 375), 1);
      expect(videoListColumnCount(mode: 'one', width: 1920), 1);
    });

    test('an explicit Two needs a window wide enough for two rows', () {
      // 600dp is the floor: below it half a phone cannot host a 100dp list row
      // with a poster and a readable text column.
      expect(videoListColumnCount(mode: 'two', width: 599), 1);
      expect(videoListColumnCount(mode: 'two', width: 600), 2);
      expect(videoListColumnCount(mode: 'two', width: 1920), 2);
    });

    test('an unknown stored value reads as auto', () {
      expect(videoListColumnCount(mode: 'three', width: 500), 1);
      expect(videoListColumnCount(mode: 'three', width: 1000), 2);
    });
  });

  group('videoGridBounds', () {
    test('a phone may go to one column and fits two at 375dp', () {
      final b = videoGridBounds(width: 375, mobile: true);
      expect(b.min, 1);
      expect(b.max, 2);
      expect(b.resolve(4), 2);
      expect(b.resolve(0), 1);
    });

    test('a desktop window keeps at least two when it can fit them', () {
      final b = videoGridBounds(width: 1920, mobile: false);
      expect(b.min, 2);
      expect(b.max, 6);
      expect(b.resolve(99), 6);
    });

    test('a window too narrow for two cards still goes to one', () {
      final b = videoGridBounds(width: 300, mobile: false);
      expect(b.min, 1);
      expect(b.max, 1);
      expect(b.resolve(4), 1);
    });

    test('bounds compare by value', () {
      expect(
        videoGridBounds(width: 375, mobile: true),
        videoGridBounds(width: 375, mobile: true),
      );
    });
  });

  group('videoGridChoiceBounds', () {
    test('is the range a wide window shows — that is what the preference means', () {
      // The settings row that SETS the count offers this range; a window clamps
      // what it SHOWS. Pinning the two together stops them drifting: a number
      // picked on a wide screen must be a number the grid can actually render.
      for (final mobile in [true, false]) {
        expect(
          videoGridChoiceBounds(mobile: mobile),
          videoGridBounds(width: 4000, mobile: mobile),
          reason: 'mobile=$mobile',
        );
      }
    });

    test('a phone may choose one column; a desktop window may not', () {
      // One column is what a phone's pinch can already commit, so the row has
      // to be able to select it back. A desktop window keeps two as its floor
      // (one column of 160dp cards is a list pretending to be a grid), so
      // offering 1 there would advertise a count it never shows.
      expect(videoGridChoiceBounds(mobile: true).min, 1);
      expect(videoGridChoiceBounds(mobile: false).min, 2);
      expect(videoGridChoiceBounds(mobile: true).max, 6);
      expect(videoGridChoiceBounds(mobile: false).max, 6);
    });
  });

  group('imageGridMaxColumns', () {
    test('at least two, at most eight, never under 100dp a cell', () {
      expect(imageGridMaxColumns(375), 3);
      expect(imageGridMaxColumns(100), 2);
      expect(imageGridMaxColumns(2000), 8);
    });
  });
}
