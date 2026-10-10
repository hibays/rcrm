// utils/seek_preview.dart
// The arithmetic behind the player's scrub gestures, as pure functions.
//
// These are the parts that can go wrong numerically — a gesture area with no
// width yet (the drag factor becomes ±Infinity, or NaN when the delta is zero
// too), a duration that is not known yet, a duration that shrinks while the
// finger is still down — and pulling them out of the gesture handlers is what
// makes them testable, because the handlers themselves need a media_kit Player
// to drive.

/// Advances a scrub preview by a horizontal drag, returning the new preview in
/// milliseconds.
///
/// [current] is the preview so far, [delta] the horizontal movement in pixels,
/// [width] the gesture area's width and [duration] the media's length. When the
/// inputs cannot describe a real position — no duration yet, no width yet, a
/// non-finite delta — [current] is returned unchanged, so a preview never becomes
/// a number that `Duration` will refuse later. Otherwise the result is clamped to
/// `[0, duration]`: a drag past either end is simply that end.
double advanceScrubPreview({
  required double current,
  required double delta,
  required double width,
  required Duration duration,
}) {
  final total = duration.inMilliseconds.toDouble();
  if (total <= 0 || width <= 0 || !delta.isFinite || !current.isFinite) {
    return current;
  }
  return (current + (delta / width) * total).clamp(0, total);
}

/// The position a lifted finger should seek to, or `null` when there is nothing
/// sensible to seek to.
///
/// The preview is clamped again, against the duration as it is **now**: a duration
/// that shrank while the finger was down would otherwise ask for a position past
/// the end. A non-finite preview returns `null` instead of reaching `Duration`,
/// whose `round()` throws on NaN.
Duration? scrubSeekTarget({
  required double previewMs,
  required Duration duration,
}) {
  final total = duration.inMilliseconds;
  if (total <= 0 || !previewMs.isFinite) return null;
  return Duration(milliseconds: previewMs.clamp(0, total.toDouble()).round());
}
