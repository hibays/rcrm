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

    test('the sort arrow leaves first — re-picking the sort chip reverses', () {
      expect(mediaToolbarLayout(460).showSortArrow, isTrue);
      expect(mediaToolbarLayout(459).showSortArrow, isFalse);
    });

    test('Organize and the layout switch leave next — Settings has both', () {
      expect(mediaToolbarLayout(400).showRightIcons, isTrue);
      expect(mediaToolbarLayout(399).showRightIcons, isFalse);
    });

    test('the column button leaves last — a narrow desktop has no pinch', () {
      expect(mediaToolbarLayout(350).showColumnButton, isTrue);
      expect(mediaToolbarLayout(349).showColumnButton, isFalse);
    });

    test('the measured phone widths admit exactly the controls that fit', () {
      final phone = mediaToolbarLayout(414);
      expect(phone.compactTagLabel, isTrue);
      expect(phone.showSortArrow, isFalse);
      expect(phone.showColumnButton, isTrue);
      expect(phone.showRightIcons, isTrue);

      final narrow = mediaToolbarLayout(375);
      expect(narrow.compactTagLabel, isTrue);
      expect(narrow.showSortArrow, isFalse);
      expect(narrow.showColumnButton, isTrue);
      expect(narrow.showRightIcons, isFalse);

      final tiny = mediaToolbarLayout(320);
      expect(tiny.compactTagLabel, isTrue);
      expect(tiny.showSortArrow, isFalse);
      expect(tiny.showColumnButton, isFalse);
      expect(tiny.showRightIcons, isFalse);
    });

    test('an unconstrained run is full; a bad width never guesses wide', () {
      expect(mediaToolbarLayout(double.infinity), mediaToolbarLayout(1000));
      for (final bad in [double.nan, -1.0, double.negativeInfinity]) {
        final layout = mediaToolbarLayout(bad);
        expect(layout.compactTagLabel, isTrue);
        expect(layout.showSortArrow, isFalse);
        expect(layout.showColumnButton, isFalse);
        expect(layout.showRightIcons, isFalse);
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
