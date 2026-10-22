// utils/shuffle_next.dart
// What `Shuffle` draws when a file ends, as a pure function: a uniform pick from
// the RELATED list — the viewer's own list, the one on the page.
//
// This is deliberately the SAME list Loop All reads, and deliberately not the
// whole library. The Related list is what the viewer was looking at when the
// video ended (same directory first, the jump history already excluded), so a
// draw from it is an offer the viewer can account for — the card names the
// video either way, but Related keeps the surprise inside a set the viewer has
// seen. Shuffle and Loop All therefore differ in exactly one thing: Loop All
// takes the TOP of the list (the row Next would play), Shuffle takes any row of
// it, uniformly.
//
// No memory of its own: a shuffle that remembered where it had been would be a
// queue, and the eight-second card that asks before playing is what keeps the
// surprise answerable.

import 'dart:math';

import '../models/media_item.dart';

/// A uniformly random row of [related], or null when the list is empty.
///
/// [related] is the caller's Related list — same exclusions, same cap — so this
/// function owns none of the set's rules, only the draw.
///
/// [rng] is injected so the draw is testable; production passes nothing and
/// takes the process's own source of randomness.
MediaItem? shuffledPick(List<MediaItem> related, {Random? rng}) {
  if (related.isEmpty) return null;
  return related[(rng ?? Random()).nextInt(related.length)];
}
