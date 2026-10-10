// utils/pan_lock.dart
// Which gesture a player drag means, as a pure function.
//
// The mobile player locks a drag to one of its three gestures the first time the
// movement is big enough to tell them apart, and the lock is not cosmetic: a
// committed seek hides the entire control bar (only the minimal seek bar stays)
// for as long as the finger is down, and a committed vertical swipe moves the
// brightness or the volume. The rule used to live in the gesture handler and
// asked only whether `max(|dx|, |dy|)` had passed a 12px slop — and a drag 30px
// across and 29px down passes that test, so a diagonal the user never aimed at
// as a scrub threw the controls away. A dominance ratio is what makes the
// direction unambiguous; between the two axes the answer is "not yet", which
// keeps the handler asking until the drag really does go one way.

import 'dart:ui' show Offset;

/// Which gesture a drag of [travel] commits to, or 0 while that is not yet
/// decidable.
///
/// [travel] is the whole movement since the drag was anchored, not the last
/// frame's delta: the question is where the finger went, and a per-frame delta
/// would re-ask it on every wobble.
///
///  * `1` — seek. Only when the horizontal travel passed [slop] **and** dominates
///    the vertical one by [dominance].
///  * `2` — the vertical gesture (brightness/volume). The same test the other way
///    round. Which of the two it is depends on where the drag started, which this
///    function cannot know — it has no notion of the screen's width — so the
///    screen turns `2` into its own `3` for the right half. `3` is therefore never
///    returned here.
///  * `0` — undecided: the drag is still too short, or too diagonal for either
///    axis to own it. The caller keeps asking while its mode is 0, so a drag that
///    starts ambiguous can still commit once it genuinely goes one way.
///
/// Once committed the lock holds for the rest of the drag (the caller stops
/// asking), so a bar cannot vanish mid-swipe.
///
/// Travel that is not a number stays undecided: every comparison below is false
/// for NaN, and "not yet" is the safe answer.
int decidePanMode(Offset travel, {double slop = 12, double dominance = 1.5}) {
  final dx = travel.dx.abs();
  final dy = travel.dy.abs();
  if (dx > slop && dx > dominance * dy) return 1;
  if (dy > slop && dy > dominance * dx) return 2;
  return 0;
}
