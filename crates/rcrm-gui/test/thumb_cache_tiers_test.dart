// test/thumb_cache_tiers_test.dart
// WHERE the tier boundaries fall — the part of the grading that decides which
// entries a ticked tier actually takes with it.
//
// The rule: the boundaries are the two largest GAPS in the score order, and only
// when those gaps are significant relative to the cache's own typical gap. So a
// cache whose entries fall into three clear generations is cut BETWEEN them, not
// through the middle of one; a cache with no shape at all is cut into equal
// thirds, which is what it did before and the honest answer when there is nothing
// to read.
//
// Every fixture here has 9 entries on purpose: the fallback for small caches
// (< 6) means the older tests cannot move, so this file is where the new rule is
// pinned on shape alone.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/thumb_cache_policy.dart';

final _now = DateTime(2026, 3, 1, 12);

ThumbCacheEntry _entry(String name, {required int hoursAgo, int bytes = 100}) =>
    ThumbCacheEntry(
      name: name,
      generatedAt: _now.subtract(Duration(hours: hoursAgo)),
      bytes: bytes,
    );

ThumbCachePlan _plan(List<ThumbCacheEntry> entries) =>
    planThumbCache(entries, maxBytes: 1, now: _now);

void main() {
  test('three clear generations are cut between them, not through one', () {
    // Three clusters an hour apart within each, months apart between: age alone
    // separates them, and that is what the score order shows as two big steps.
    final plan = _plan([
      _entry('c1', hoursAgo: 24 * 300),
      _entry('c2', hoursAgo: 24 * 299),
      _entry('c3', hoursAgo: 24 * 298),
      _entry('w1', hoursAgo: 24 * 60),
      _entry('w2', hoursAgo: 24 * 59),
      _entry('w3', hoursAgo: 24 * 58),
      _entry('f1', hoursAgo: 3),
      _entry('f2', hoursAgo: 2),
      _entry('f3', hoursAgo: 1),
    ]);

    expect(plan.cold, ['c1', 'c2', 'c3']);
    expect(plan.warm, ['w1', 'w2', 'w3']);
    expect(plan.fresh, ['f1', 'f2', 'f3']);
  });

  test('a shapeless cache falls back to equal thirds', () {
    // Nine entries a minute apart: every gap is the same, so no gap is evidence of
    // a boundary, and the tiers stay thirds — the previous behaviour, kept as the
    // answer for "nothing to read here".
    final plan = _plan([
      for (var i = 9; i >= 1; i--) _entry('e$i', hoursAgo: i),
    ]);

    expect(plan.cold, hasLength(3));
    expect(plan.warm, hasLength(3));
    expect(plan.fresh, hasLength(3));
    expect(plan.cold, ['e9', 'e8', 'e7'], reason: 'oldest first, equal thirds');
  });

  test('identical scores are not a shape either', () {
    // All written in the same instant, same size: every gap is zero, so there is
    // nothing to read and thirds is the answer rather than an arbitrary cut.
    final plan = _plan([
      for (var i = 0; i < 9; i++) _entry('same$i', hoursAgo: 1),
    ]);

    expect(plan.cold, hasLength(3));
    expect(plan.fresh, hasLength(3));
  });

  test('the tiers still sum to the cache, whatever the cut', () {
    final plan = _plan([
      _entry('a', hoursAgo: 24 * 400, bytes: 300),
      _entry('b', hoursAgo: 24 * 399, bytes: 300),
      _entry('c', hoursAgo: 24 * 398, bytes: 300),
      _entry('d', hoursAgo: 5, bytes: 300),
      _entry('e', hoursAgo: 4, bytes: 300),
      _entry('f', hoursAgo: 3, bytes: 300),
      _entry('g', hoursAgo: 2, bytes: 300),
      _entry('h', hoursAgo: 1, bytes: 300),
      _entry('i', hoursAgo: 0, bytes: 300),
    ]);

    expect(plan.graded, 9);
    expect(plan.keptBytes + plan.droppedBytes, 9 * 300);
    expect(plan.coldBytes + plan.warmBytes + plan.freshBytes, 9 * 300);
  });
}
