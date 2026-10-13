// test/swipe_value_test.dart
// The vertical swipe's arithmetic, shared by the brightness and volume halves of
// the mobile player.
//
// Regression these pin: the volume half used to feed itself from `_volume.value`,
// which while bound is the STEP the device landed on. A 15-step phone answers in
// 6.7% jumps, so re-reading it every frame threw the finger's travel away — a
// slow swipe moved nothing at all, and a wobble across a step boundary walked the
// volume backwards. The brightness half never had the bug because nothing
// quantises a screen's brightness, which is exactly why the two now share this.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/swipe_value.dart';

void main() {
  // A phone in portrait, fullscreen: the gesture area the player lays out.
  const height = 600.0;

  test('up is more, on both scales the player uses', () {
    // A finger moving up reports a NEGATIVE delta.
    final louder = advanceVerticalValue(
      current: 50,
      deltaDy: -60,
      height: height,
    );
    expect(louder, greaterThan(50));

    final brighter = advanceVerticalValue(
      current: 0.5,
      deltaDy: -60,
      height: height,
      max: 1,
    );
    expect(brighter, greaterThan(0.5));
  });

  test('one swipe-span of travel is one full range', () {
    // Which is the whole point of the accumulator: how far the finger goes is
    // what the value does, whatever the device does with the number. The span is
    // kVerticalSwipeSpanRatio of the area's height -- see the ratio's own test.
    const span = height * kVerticalSwipeSpanRatio;
    expect(advanceVerticalValue(current: 0, deltaDy: -span, height: height), 100);
    expect(advanceVerticalValue(current: 100, deltaDy: span, height: height), 0);
    expect(
      advanceVerticalValue(current: 0, deltaDy: -span, height: height, max: 1),
      1,
    );
  });

  test('and the span is shorter than the screen on purpose', () {
    // The stride the viewer asked for. A full height of travel was too slow once
    // the swipe started tracking the finger honestly (on a portrait fullscreen
    // that is ~890px for 0..100, about nine pixels per percent), so the full range
    // now takes a fraction of the height. This pins BOTH ends of that decision:
    // it is faster than the whole height, and it is not so fast that a percent
    // costs less than a pixel of travel.
    expect(kVerticalSwipeSpanRatio, lessThan(1.0));
    expect(
      kVerticalSwipeSpanRatio,
      greaterThanOrEqualTo(0.4),
      reason: 'a shorter span than this aims in sub-pixel steps',
    );
    // In the numbers, on a portrait phone in fullscreen.
    const portrait = 890.0;
    final perPercent = portrait * kVerticalSwipeSpanRatio / 100;
    expect(perPercent, greaterThan(4));
    expect(perPercent, lessThan(9));
  });

  test('a slow swipe still moves, in proportion', () {
    // Four pixels on a 600px area is 1.1% -- a fifth of the step a 15-step phone
    // can even reach -- and the accumulator is what keeps that travel instead of
    // losing it to the device's quantisation.
    final v = advanceVerticalValue(
      current: 50,
      deltaDy: -4,
      height: height,
    );
    expect(v, closeTo(50 + 4 / (height * kVerticalSwipeSpanRatio) * 100, 0.01));
  });

  test('the finger\'s NET travel is what the value does', () {
    // Five frames up, one pixel of wobble down, five more up: the deltas sum to
    // -31px, and the value must end exactly 31px worth of the range above where it
    // started -- nothing lost, nothing rounded. Reading the bar back instead (what
    // the volume half used to do) threw away whatever did not add up to a step the
    // device has, so a swipe of this size used to change nothing at all.
    double v = 40;
    for (final dy in <double>[-8, -8, 1, -8, -8]) {
      v = advanceVerticalValue(current: v, deltaDy: dy, height: height);
    }
    expect(v, closeTo(40 + 31 / (height * kVerticalSwipeSpanRatio) * 100, 0.0001));
  });

  test('a one-pixel wobble moves it one pixel, not one step', () {
    // The direction fight the volume half had: with a quantised value read back,
    // a wobble across a step boundary walked the volume by 6.7% (a 15-step
    // phone) or did nothing -- never by the 1px the finger actually moved.
    final wobbled = advanceVerticalValue(
      current: 40,
      deltaDy: 1,
      height: height,
    );
    expect(
      40 - wobbled,
      closeTo(1 / (height * kVerticalSwipeSpanRatio) * 100, 0.0001),
    );
    expect(40 - wobbled, lessThan(1));
  });

  test('the ends clamp instead of wrapping', () {
    expect(
      advanceVerticalValue(current: 99, deltaDy: -height, height: height),
      100,
    );
    expect(
      advanceVerticalValue(current: 1, deltaDy: height, height: height),
      0,
    );
    // A scale that does not start at zero (the brightness half's 0..1 does, but
    // nothing here assumes it).
    expect(
      advanceVerticalValue(
        current: 5,
        deltaDy: height,
        height: height,
        min: 5,
        max: 15,
      ),
      5,
    );
  });

  test('an area with no height yet leaves the value where it was', () {
    // Before the first layout the divisor is zero, and NaN cannot be clamped:
    // it would reach the player and the platform.
    for (final h in <double>[0, -1, double.nan, double.infinity]) {
      expect(
        advanceVerticalValue(current: 42, deltaDy: 20, height: h),
        42,
        reason: 'height $h',
      );
    }
    expect(
      advanceVerticalValue(current: 42, deltaDy: double.nan, height: height),
      42,
    );
  });
}
