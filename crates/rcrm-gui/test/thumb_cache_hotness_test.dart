// test/thumb_cache_hotness_test.dart
// The cache's grading is a SCORE, and the point of a score is that two entries
// with the SAME age can be worth different things.
//
// This is the case the old "thirds by generation time" rule could not express at
// all: a thumbnail generated years ago that somebody opened yesterday, next to
// one generated last week that nobody has ever opened. Age alone ranks the second
// one as the keeper; the cache's own access record says the opposite, and the
// access record is the only evidence about what will be wanted again.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/thumb_cache_policy.dart';

final _now = DateTime(2026, 3, 1, 12);

ThumbCacheEntry _entry(
  String name, {
  required Duration generatedAgo,
  Duration? usedAgo,
  int bytes = 1000,
}) => ThumbCacheEntry(
  name: name,
  generatedAt: _now.subtract(generatedAgo),
  lastUsedAt: usedAgo == null ? null : _now.subtract(usedAgo),
  bytes: bytes,
);

ThumbCachePlan _plan(List<ThumbCacheEntry> entries) =>
    planThumbCache(entries, maxBytes: 1, now: _now);

void main() {
  test('a recently opened old entry outlives a newer one nobody opened', () {
    // Both are cold by age; only the access record separates them. The budget is
    // one byte, so this is purely about which one the grading protects longest.
    final plan = _plan([
      _entry(
        'oldButHot',
        generatedAgo: const Duration(days: 900),
        usedAgo: const Duration(hours: 2),
      ),
      _entry('newButNeverOpened', generatedAgo: const Duration(days: 7)),
      _entry('filler', generatedAgo: const Duration(days: 400)),
    ]);

    expect(
      plan.drop.first,
      isNot('oldButHot'),
      reason: 'used two hours ago: the hottest thing in this cache',
    );
    expect(
      plan.drop,
      contains('newButNeverOpened'),
      reason: 'never opened and older than nothing: the coldest thing here',
    );
  });

  test('last use outweighs size when both are extreme', () {
    // A single huge cold entry is usually worth reclaiming — that is the -2 size
    // weight — but it must not outvote a recent read (weight 3). If it did, the
    // cache would evict exactly the pictures a session is showing.
    final plan = _plan([
      _entry(
        'hugeAndHot',
        generatedAgo: const Duration(days: 500),
        usedAgo: const Duration(minutes: 5),
        bytes: 200000,
      ),
      _entry('smallAndDead', generatedAgo: const Duration(days: 500)),
      _entry('middle', generatedAgo: const Duration(days: 30)),
    ]);

    expect(plan.drop.first, 'smallAndDead');
  });

  test('an entry with no access record falls back to its generation time', () {
    // Nothing was ever recorded for either of these, so the only honest signal is
    // when they were made. Both orderings below follow that: the newer keeper.
    final plan = _plan([
      _entry('never1', generatedAgo: const Duration(days: 40)),
      _entry('never2', generatedAgo: const Duration(days: 1)),
      _entry('never3', generatedAgo: const Duration(days: 400)),
    ]);

    expect(plan.drop.first, 'never3');
  });

  test('the tier boundary follows the score, not the calendar', () {
    // Same generations, opposite access: the tier a given entry lands in has to
    // move with the reads.
    List<ThumbCacheEntry> cache({required bool oldIsHot}) => [
      _entry(
        'old',
        generatedAgo: const Duration(days: 400),
        usedAgo: oldIsHot ? const Duration(minutes: 1) : null,
      ),
      _entry(
        'new',
        generatedAgo: const Duration(days: 2),
        usedAgo: oldIsHot ? null : const Duration(minutes: 1),
      ),
      _entry('mid', generatedAgo: const Duration(days: 60)),
    ];

    final oldHot = planThumbCache(
      cache(oldIsHot: true),
      maxBytes: 1,
      now: _now,
    );
    final newHot = planThumbCache(
      cache(oldIsHot: false),
      maxBytes: 1,
      now: _now,
    );

    // Read a minute ago, the entry generated 400 DAYS ago is the hottest thing
    // in this cache — it lands in the newest tier, above one generated two days
    // ago that nobody has opened. Swap the reads and it drops to the coldest
    // tier, which is the whole claim: the boundary follows the score.
    expect(oldHot.fresh, contains('old'));
    expect(oldHot.cold, isNot(contains('old')));
    expect(newHot.cold, contains('old'));
  });

  test('the same cache grades the same way whatever the clock says', () {
    // The grading normalises by the cache's OWN medians, so shifting every
    // timestamp (a different machine's clock, a cache inspected a year later)
    // cannot change which tier an entry belongs to. That is what "no asserted
    // age" has to mean in practice.
    final entries = [
      _entry(
        'a',
        generatedAgo: const Duration(days: 400),
        usedAgo: const Duration(days: 300),
      ),
      _entry(
        'b',
        generatedAgo: const Duration(days: 200),
        usedAgo: const Duration(days: 1),
      ),
      _entry(
        'c',
        generatedAgo: const Duration(days: 3),
        usedAgo: const Duration(hours: 1),
      ),
    ];
    final shifted = [
      for (final e in entries)
        ThumbCacheEntry(
          name: e.name,
          generatedAt: e.generatedAt.subtract(const Duration(days: 365)),
          lastUsedAt: e.lastUsedAt?.subtract(const Duration(days: 365)),
          bytes: e.bytes,
        ),
    ];

    final here = planThumbCache(entries, maxBytes: 1, now: _now);
    final there = planThumbCache(shifted, maxBytes: 1, now: _now);
    expect(there.drop, here.drop);
    expect(there.cold, here.cold);
    expect(there.fresh, here.fresh);
  });
}
