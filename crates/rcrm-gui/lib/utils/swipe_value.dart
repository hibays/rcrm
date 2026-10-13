// utils/swipe_value.dart
// Where a vertical swipe leaves the value it drives -- the arithmetic the
// player's brightness and volume gestures share, in one place so the two halves
// of the screen cannot drift apart.
//
// They are deliberately the SAME shape: one private number per gesture, owned by
// the finger, pushed OUT to whoever applies it (the system brightness, the
// player's volume) and never read back from there. That is what makes a swipe
// feel like a swipe -- the finger's travel is what the value does, whatever the
// device does with the number in the meantime, and the direction of the finger is
// the direction of the value.
//
// Reading the value back is the failure this exists to prevent, and the volume
// half shipped with it: while the volume is bound to the device, what comes back
// is the STEP the phone landed on, so a slow swipe asks for the same step again
// and again -- the volume does not move at all, however far the finger goes --
// and a one-pixel wobble across a step boundary walks it backwards, which is the
// direction fight the gesture used to have. Brightness never had it because
// nothing quantises a screen's brightness.

/// How much of the gesture area's height one full range of travel takes.
///
/// The original rule was the whole height (1.0), and it is too slow to live with
/// once the accumulator above makes the swipe track the finger honestly: on a
/// portrait phone in fullscreen that is ~890px of finger travel to move the
/// volume from 0 to 100 — roughly nine pixels per percent — so adjusting by a
/// noticeable amount meant walking the finger most of the way up the screen.
///
/// 0.6 is "a bit faster" rather than "twitchy": the full range now takes ~60% of
/// the height (about 1.7x the old rate, ~5px per percent on that same phone), the
/// ends still clamp, and a single pixel still moves the value by a single pixel's
/// worth. Landscape fullscreen has a much shorter area to begin with (~360px), so
/// the same factor keeps it fast without becoming hard to aim.
///
/// It lives here rather than at the call sites because BOTH halves of the screen
/// must move at the same rate: the brightness swipe and the volume swipe are one
/// gesture at two scales, and a viewer who learns one has learned the other.
const double kVerticalSwipeSpanRatio = 0.6;

/// The value [current] becomes after a vertical drag of [deltaDy] over a gesture
/// area [height] px tall, on a scale running [min]..[max].
///
/// Up is more: a finger moving up reports a negative `deltaDy`, which raises the
/// value. [kVerticalSwipeSpanRatio] of the height is one full range on either
/// scale the player uses (brightness `0..1`, volume `0..100`), and the ends CLAMP
/// rather than wrap -- a swipe past the end must not jump to the other one.
///
/// A gesture area with no height yet (before the first layout) would divide by
/// zero: NaN cannot be clamped and reaches both the player and the platform, so
/// such a frame leaves the value exactly where it was.
double advanceVerticalValue({
  required double current,
  required double deltaDy,
  required double height,
  double min = 0,
  double max = 100,
}) {
  if (!(height > 0) || !deltaDy.isFinite) return current.clamp(min, max);
  final span = max - min;
  return (current - deltaDy / (height * kVerticalSwipeSpanRatio) * span).clamp(
    min,
    max,
  );
}
