// test/menu_placement_test.dart
// A menu is given an alignment before it is measured, so the opening direction
// is a decision made from an estimate. These are the two numbers that decision
// rests on: how tall a menu will be, and which side of the anchor has room.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/menu_placement.dart';

void main() {
  group('estimatedMenuHeight', () {
    test('rows are the native 48dp plus the menu\'s 8dp of padding', () {
      expect(estimatedMenuHeight(5), 5 * 48 + 16);
      expect(estimatedMenuHeight(1), 64);
    });

    test('a large text scale grows the estimate with it', () {
      expect(estimatedMenuHeight(4, textScale: 1.5), 4 * 48 * 1.5 + 16);
      // Capped where the row's own air takes over from the text.
      expect(estimatedMenuHeight(4, textScale: 3), 4 * 48 * 1.6 + 16);
      // A broken scale is not a size.
      expect(estimatedMenuHeight(4, textScale: double.nan), 4 * 48 + 16);
    });
  });

  group('menuOpensUpward', () {
    test('opens downward when it fits below', () {
      expect(
        menuOpensUpward(anchorY: 100, screenHeight: 800, rows: 5),
        isFalse,
      );
    });

    test('flips up when the space below cannot hold it', () {
      expect(
        menuOpensUpward(anchorY: 700, screenHeight: 800, rows: 5),
        isTrue,
        reason: '92dp below a 256dp menu is not a place to put a menu',
      );
    });

    test('with neither side fitting, the roomier side wins', () {
      // 10 rows = 496dp; a 400dp-tall window has 92 below and 292 above.
      expect(
        menuOpensUpward(anchorY: 300, screenHeight: 400, rows: 10),
        isTrue,
      );
      expect(
        menuOpensUpward(anchorY: 80, screenHeight: 400, rows: 10),
        isFalse,
      );
    });

    test('the margin is the touch/pointer gap, not part of the menu', () {
      // Exactly enough room below at margin 8, not at margin 40.
      expect(
        menuOpensUpward(anchorY: 800 - 256 - 8, screenHeight: 800, rows: 5),
        isFalse,
      );
      expect(
        menuOpensUpward(
          anchorY: 800 - 256 - 8,
          screenHeight: 800,
          rows: 5,
          margin: 40,
        ),
        isTrue,
      );
    });
  });
}
