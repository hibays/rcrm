// utils/swipe_value.dart
// Where a vertical swipe leaves the value it drives -- the arithmetic the
// player's brightness and volume gestures share, in one place so the two halves
// of the screen cannot drift apart.
//
// They are deliberately the SAME shape: one private number per gesture, owned by
// the finger, pushed OUT to whoever applies it (the system brightness, the
// player's volume) and never read back from there. That is what makes a swipe
// feel like a swipe -- one screen height of travel is one full range, whatever
// the device does with the number in the meantime, and the direction of the
// finger is the direction of the value.
//
// Reading the value back is the failure this exists to prevent, and the volume
// half shipped with it: while the volume is bound to the device, what comes back
// is the STEP the phone landed on, so a slow swipe asks for the same step again
// and again -- the volume does not move at all, however far the finger goes --
// and a one-pixel wobble across a step boundary walks it backwards, which is the
// direction fight the gesture used to have. Brightness never had it because
// nothing quantises a screen's brightness.

/// The value [current] becomes after a vertical drag of [deltaDy] over a gesture
/// area [height] px tall, on a scale running [min]..[max].
///
/// Up is more: a finger moving up reports a negative `deltaDy`, which raises the
/// value. One full height is one full range on either scale the player uses
/// (brightness `0..1`, volume `0..100`), and the ends CLAMP rather than wrap --
/// a swipe past the end must not jump to the other one.
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
  return (current - deltaDy / height * span).clamp(min, max);
}
