// test/seek_preview_test.dart
// The scrub arithmetic that the gesture handlers delegate to. Both functions
// exist because of real failures: a zero-width gesture area produced a NaN that
// threw in `Duration.round()` when the finger lifted, and a duration that shrank
// mid-drag produced a seek past the end.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/seek_preview.dart';

const _dur = Duration(minutes: 10); // 600_000 ms

void main() {
  group('advanceScrubPreview', () {
    test('a full-width drag moves by the whole duration', () {
      expect(
        advanceScrubPreview(current: 0, delta: 400, width: 400, duration: _dur),
        600_000,
      );
    });

    test('it scales with the width and the duration', () {
      // A quarter of the width is a quarter of the media.
      expect(
        advanceScrubPreview(current: 0, delta: 100, width: 400, duration: _dur),
        150_000,
      );
      // Moving left subtracts, and stops at the start rather than going negative.
      expect(
        advanceScrubPreview(
          current: 1_000,
          delta: -100,
          width: 400,
          duration: _dur,
        ),
        0,
      );
      // Moving right stops at the end.
      expect(
        advanceScrubPreview(
          current: 590_000,
          delta: 100,
          width: 400,
          duration: _dur,
        ),
        600_000,
      );
    });

    test('an unknown duration leaves the preview alone', () {
      expect(
        advanceScrubPreview(
          current: 0,
          delta: 50,
          width: 400,
          duration: Duration.zero,
        ),
        0,
      );
    });

    test('a gesture area with no width cannot invent a value', () {
      // Before the first layout `width` is 0: the factor would be ±Infinity, and
      // NaN when the delta is zero as well. Neither may reach the preview.
      for (final delta in <double>[0, 37, -37, double.infinity, double.nan]) {
        expect(
          advanceScrubPreview(
            current: 123,
            delta: delta,
            width: 0,
            duration: _dur,
          ),
          123,
          reason: 'delta $delta with a zero width',
        );
      }
    });

    test('a non-finite delta is ignored', () {
      expect(
        advanceScrubPreview(
          current: 500,
          delta: double.nan,
          width: 400,
          duration: _dur,
        ),
        500,
      );
    });

    test('a preview that is already NaN is not propagated further', () {
      expect(
        advanceScrubPreview(
          current: double.nan,
          delta: 10,
          width: 400,
          duration: _dur,
        ),
        isNaN,
      );
    });
  });

  group('scrubSeekTarget', () {
    test('rounds the preview to milliseconds', () {
      expect(
        scrubSeekTarget(previewMs: 150_000.4, duration: _dur),
        const Duration(milliseconds: 150_000),
      );
    });

    test('clamps against the duration as it is now', () {
      // The finger is still down when the stream re-reports a shorter duration.
      expect(
        scrubSeekTarget(
          previewMs: 590_000,
          duration: const Duration(minutes: 2),
        ),
        const Duration(minutes: 2),
      );
      expect(scrubSeekTarget(previewMs: -5_000, duration: _dur), Duration.zero);
    });

    test(
      'nothing is sought without a duration or with a non-finite preview',
      () {
        expect(
          scrubSeekTarget(previewMs: 1_000, duration: Duration.zero),
          isNull,
        );
        expect(scrubSeekTarget(previewMs: double.nan, duration: _dur), isNull);
        expect(
          scrubSeekTarget(previewMs: double.infinity, duration: _dur),
          isNull,
        );
      },
    );
  });
}
