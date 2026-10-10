// test/format_test.dart
// `formatMs` feeds every time label in the player (elapsed, duration, and the
// scrub preview). It must never print a value that did not come from a real
// millisecond count — the regression below is the "random memory number" users
// saw on the progress bar after the controls rewrite.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/format.dart';

void main() {
  group('formatMs', () {
    test('under an hour it is mm:ss, rounded to the nearest second', () {
      expect(formatMs(0), '00:00');
      expect(formatMs(999), '00:01');
      expect(formatMs(59_499), '00:59');
      expect(formatMs(59_500), '01:00');
      expect(formatMs(3_599_000), '59:59');
    });

    test('past an hour it is h:mm:ss', () {
      expect(formatMs(3_600_000), '1:00:00');
      expect(formatMs(3_661_000), '1:01:01');
      expect(formatMs(36_000_000), '10:00:00');
    });

    test('negative input is clamped, never wrapped', () {
      // Dart's `%` is non-negative, so a negative millisecond count used to come
      // out as a negative hour count with ordinary-looking minutes (`-1` printed
      // as `-1:59:59`), and a large negative — what an unclamped scrub fraction
      // multiplied by the duration produced — printed as a huge hour count: the
      // "random memory number". Every negative must read as the start of the
      // media instead.
      expect(formatMs(-1), '00:00');
      expect(formatMs(-59_500), '00:00');
      expect(formatMs(-3_600_000), '00:00');
      expect(formatMs(-(1 << 62)), '00:00');
    });

    test('a very large value stays a plausible time, not an overflow', () {
      // 2^62 ms is absurd but must still format as hours (1.28e12 of them) and
      // nothing may throw or wrap. Pinned to the exact string so a future change
      // to the rounding cannot quietly alter what the bar prints.
      expect(formatMs(1 << 62), '1281023894007:36:28');
    });
  });
}
