// test/poster_frame_test.dart
// The two pure decisions in video-poster generation: where to look, and whether
// a capture is the same frame the pipeline already looked at.
//
// The pixel work (blank test, downscale, WebP encode) now lives in Rust and is
// tested there (src/poster.rs, src/decode.rs); this file deliberately has no
// pixel loops left to pin.

import 'dart:typed_data';

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

  group('isStalePosterFrame', () {
    final frame = Uint8List.fromList([1, 2, 3, 4]);
    final same = Uint8List.fromList([1, 2, 3, 4]);
    final other = Uint8List.fromList([1, 2, 3, 5]);

    test('a repeat of the previous frame at a content position is stale', () {
      expect(
        isStalePosterFrame(position: 30, previous: frame, current: same),
        isTrue,
      );
    });

    test('a different frame is new', () {
      expect(
        isStalePosterFrame(position: 30, previous: frame, current: other),
        isFalse,
      );
    });

    test('the first capture has no baseline', () {
      expect(
        isStalePosterFrame(position: 30, previous: null, current: frame),
        isFalse,
      );
    });

    test('the 0.0 fallback accepts the pre-seek frame', () {
      // A static video/slideshow returns the same frame at every position.
      // Every content candidate exhausts its retries; if 0.0 also rejected it,
      // the video would get no poster at all.
      expect(
        isStalePosterFrame(position: 0, previous: frame, current: same),
        isFalse,
      );
    });
  });

  group('sameEncodedFrame', () {
    Uint8List bytes(int seed, {int length = 4000}) =>
        Uint8List.fromList(List<int>.generate(length, (i) => (i * seed) % 251));

    test('the same encode is the same frame', () {
      final a = bytes(7);
      final b = Uint8List.fromList(a);
      expect(sameEncodedFrame(a, b), isTrue);
      expect(sameEncodedFrame(a, a), isTrue, reason: 'identical buffer');
    });

    test('a different length can never be the same frame', () {
      expect(sameEncodedFrame(bytes(7), bytes(7, length: 4001)), isFalse);
    });

    test('a frame whose pixels changed is not the same frame', () {
      final a = bytes(7);
      final b = Uint8List.fromList(a);
      b[2000] = (b[2000] + 1) % 256;
      expect(sameEncodedFrame(a, b), isFalse);
    });

    test('a single changed byte at the very end is caught', () {
      final a = bytes(11);
      final b = Uint8List.fromList(a);
      b[b.length - 1] = (b[b.length - 1] + 3) % 256;
      expect(sameEncodedFrame(a, b), isFalse);
    });

    test('a changed byte in the non-4-aligned tail is still caught', () {
      // 4003 = 1000 whole words + 3 tail bytes.
      final a = bytes(7, length: 4003);
      final b = Uint8List.fromList(a);
      b[4002] = (b[4002] + 1) % 256;
      expect(sameEncodedFrame(a, b), isFalse);
    });

    test('unaligned views fall back to byte-by-byte and stay correct', () {
      // Each view needs its OWN backing buffer: three views over one buffer
      // would all change together when one of them is edited.
      Uint8List unaligned(Uint8List src) {
        final padded = Uint8List(src.length + 1);
        padded.setRange(1, padded.length, src);
        return Uint8List.view(padded.buffer, 1, src.length);
      }

      final base = Uint8List.fromList(
        List<int>.generate(4000, (i) => (i * 7) % 251),
      );
      final a = unaligned(base);
      final b = unaligned(base);
      expect(a.offsetInBytes % 4, isNot(0));
      expect(sameEncodedFrame(a, b), isTrue);

      final changed = Uint8List.fromList(base);
      changed[3999] = (changed[3999] + 1) % 256;
      expect(sameEncodedFrame(a, unaligned(changed)), isFalse);
    });

    test('raw BGRA captures are compared in the representation they arrive in', () {
      // media_kit returns a fresh sublist(0) copy for every raw screenshot; the
      // service compares those raw buffers directly, before Rust swaps channels.
      // Two captures of the same frame are equal byte for byte.
      Uint8List capture() {
        final out = Uint8List(4 * 4 * 4);
        for (var i = 0; i < 16; i++) {
          out[i * 4] = 40; // B
          out[i * 4 + 1] = 90; // G
          out[i * 4 + 2] = 180; // R
          out[i * 4 + 3] = 0; // mpv leaves alpha at zero
        }
        return out;
      }

      final first = capture();
      final second = capture();
      expect(sameEncodedFrame(first, second), isTrue);
      second[0] = 41;
      expect(sameEncodedFrame(first, second), isFalse);
    });

    test('empty input is trivially the same', () {
      expect(sameEncodedFrame(Uint8List(0), Uint8List(0)), isTrue);
    });
  });
}
