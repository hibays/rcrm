// test/poster_frame_test.dart
// The one pure decision in video-poster generation: where to look.
//
// The pixel work (blank test, WebP encode) lives in Rust and is tested there
// (src/poster.rs); this file deliberately has no pixel loops to pin.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/poster_frame.dart';

void main() {
  group('posterSeekPlan', () {
    test('an unknown duration falls back to absolute seconds, content first '
        'and the first frame last', () {
      expect(posterSeekPlan(Duration.zero), [
        30.0,
        15.0,
        3.0,
        0.5,
        60.0,
        120.0,
        240.0,
        0.0,
      ]);
      // The first candidate is what a film is represented by. A feature's
      // title card often lives at 3s, so 3.0 must not lead the ladder (the
      // review that moved it there made every title-card film cache its logo).
      expect(posterSeekPlan(Duration.zero).first, 30.0);
      expect(posterSeekPlan(const Duration(seconds: -1)).last, 0.0);
    });

    test('a 90s clip is sampled by fraction, and the very first frame is only '
        'ever the last resort', () {
      final plan = posterSeekPlan(const Duration(seconds: 90));
      expect(plan.first, 9.0, reason: '10% in, not the black leader');
      expect(plan.last, 0.0);
      expect(plan, contains(22.5));
      expect(plan, contains(45.0));
      // 0.0 appears exactly once, at the end.
      expect(plan.where((p) => p == 0.0).length, 1);
    });

    test('no candidate reaches or passes the end of the file', () {
      for (final seconds in [1, 2, 5, 8, 20, 90, 600, 7200]) {
        final plan = posterSeekPlan(Duration(seconds: seconds));
        for (final p in plan) {
          expect(
            p,
            lessThan(seconds.toDouble()),
            reason:
                'a seek to the duration itself returns the last frame or '
                'nothing (${seconds}s -> $plan)',
          );
          expect(p, greaterThanOrEqualTo(0));
        }
      }
    });

    test('a three-hour film is not sampled at minute 18', () {
      final plan = posterSeekPlan(const Duration(hours: 3));
      expect(plan.first, 300.0, reason: 'the fraction is clamped to 5 minutes');
    });

    test('a short clip still gets distinct, useful candidates', () {
      final plan = posterSeekPlan(const Duration(seconds: 8));
      expect(plan.first, 1.0);
      expect(plan.toSet().length, plan.length, reason: 'unique: $plan');
      expect(plan.last, 0.0);
    });

    test('no candidates are duplicates after rounding', () {
      for (final seconds in [1, 3, 4, 10, 40, 200, 1000]) {
        final plan = posterSeekPlan(Duration(seconds: seconds));
        expect(
          plan.toSet().length,
          plan.length,
          reason: '${seconds}s -> $plan',
        );
      }
    });
  });
}
