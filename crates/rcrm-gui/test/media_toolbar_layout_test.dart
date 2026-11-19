// test/media_toolbar_layout_test.dart
// The width → controls ladder is a pure rule: pin the numbers here instead of
// only observing whichever chip happened to disappear in a widget test.

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/utils/media_toolbar_layout.dart';

void main() {
  group('mediaToolbarLayout', () {
    test('the tag label fits at 600dp and loses its padding below it', () {
      final below = mediaToolbarLayout(599);
      expect(below.compactTagLabel, isTrue);
      expect(below.horizontalPadding, 8);

      final at = mediaToolbarLayout(600);
      expect(at.compactTagLabel, isFalse);
      expect(at.horizontalPadding, 12);
      expect(mediaToolbarLayout(1000).horizontalPadding, 12);
    });

    test('below 520dp every right control folds into one overflow button', () {
      // The narrowest width that still holds the full row, even with the long
      // "Duration ↑" sort label (~508dp), keeps the controls inline.
      expect(mediaToolbarLayout(520).showOverflow, isFalse);
      expect(mediaToolbarLayout(600).showOverflow, isFalse);
      expect(mediaToolbarLayout(1000).showOverflow, isFalse);

      // The instant the row cannot hold them, the overflow appears — and stays
      // at every narrower width, replacing the bare `#` rather than leaving a
      // gap on the right.
      for (final width in const [519.0, 460.0, 414.0, 400.0, 375.0, 320.0]) {
        expect(
          mediaToolbarLayout(width).showOverflow,
          isTrue,
          reason: '$width cannot hold every control; they must stay reachable',
        );
      }
    });

    test('the filter chip folds in only where the row cannot hold it', () {
      expect(mediaToolbarLayout(414).showFormatChipInline, isTrue);
      expect(mediaToolbarLayout(380).showFormatChipInline, isTrue);
      expect(mediaToolbarLayout(379).showFormatChipInline, isFalse);
      expect(mediaToolbarLayout(320).showFormatChipInline, isFalse);
      // Wide layouts always keep it inline.
      expect(mediaToolbarLayout(600).showFormatChipInline, isTrue);
    });

    test('the measured phone widths get the controls that fit', () {
      final phone = mediaToolbarLayout(414);
      expect(phone.compactTagLabel, isTrue);
      expect(phone.showOverflow, isTrue);
      expect(phone.showFormatChipInline, isTrue);

      final narrow = mediaToolbarLayout(375);
      expect(narrow.compactTagLabel, isTrue);
      expect(narrow.showOverflow, isTrue);
      expect(narrow.showFormatChipInline, isFalse);

      final tiny = mediaToolbarLayout(320);
      expect(tiny.compactTagLabel, isTrue);
      expect(tiny.showOverflow, isTrue);
      expect(tiny.showFormatChipInline, isFalse);
    });

    test('an unconstrained run is full; a bad width never guesses wide', () {
      expect(mediaToolbarLayout(double.infinity), mediaToolbarLayout(1000));
      for (final bad in [double.nan, -1.0, double.negativeInfinity]) {
        final layout = mediaToolbarLayout(bad);
        expect(layout.compactTagLabel, isTrue);
        expect(layout.showOverflow, isFalse);
        expect(layout.showFormatChipInline, isFalse);
        expect(layout.horizontalPadding, 8);
      }
    });

    test('layouts compare by value', () {
      expect(mediaToolbarLayout(800), mediaToolbarLayout(900));
      expect(
        mediaToolbarLayout(800).hashCode,
        mediaToolbarLayout(900).hashCode,
      );
    });
  });
}
