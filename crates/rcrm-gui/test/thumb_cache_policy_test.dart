// test/thumb_cache_policy_test.dart
// The thumbnail cache's management rule, as a pure decision.
//
// What these pin, and why each one is load-bearing:
//
//  * GRADED BY GENERATION TIME, BOUNDED BY THE CACHE ITSELF — the tiers are
//    thirds of the entries in age order, so the boundary sits wherever this
//    cache's own ages put it. The same rule is therefore right for a library
//    scanned weekly and one opened twice a year (see the scale test below),
//    which no asserted age can be.
//  * COLDEST FIRST, NEWEST LAST — the newest tier is what a session is most
//    likely showing, and is spent only when everything colder cannot cover the
//    overshoot.
//  * ONLY AS MUCH AS THE BUDGET NEEDS — the budget is in bytes, so an overshoot
//    costs a few entries, not the cache. That is the whole difference from the
//    `clear()` this replaces.
//
// Every tier list is in GENERATION ORDER (oldest first), the same order the
// shedding walks.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/thumb_cache_policy.dart';

/// A fixed `now`, so a test can say "this was generated an hour ago" directly
/// and the assertions stay about the rule rather than about the clock.
final _now = DateTime(2026, 3, 1, 12);

ThumbCacheEntry _entry(
  String name, {
  required int minutesAgo,
  int bytes = 100,
}) => ThumbCacheEntry(
  name: name,
  generatedAt: _now.subtract(Duration(minutes: minutesAgo)),
  bytes: bytes,
);

void main() {
  test('an under-budget cache is left completely alone', () {
    final plan = planThumbCache([
      _entry('a', minutesAgo: 10),
      _entry('b', minutesAgo: 20),
    ], maxBytes: 10000);

    expect(plan.drop, isEmpty);
    expect(plan.keptBytes, 200);
    expect(plan.droppedBytes, 0);
    expect(plan.graded, 2);
    // Generation order, oldest first — and with fewer than three entries there
    // is no older tier to make, so both are "fresh".
    expect(plan.fresh, ['b', 'a']);
    expect(plan.cold, isEmpty);
  });

  test('the coldest go first, and only as many as the budget needs', () {
    // Three entries, 100 bytes each, 250 allowed: one entry covers the overshoot
    // and the other two are untouched.
    final plan = planThumbCache([
      _entry('old1', minutesAgo: 3000),
      _entry('new1', minutesAgo: 10),
      _entry('mid1', minutesAgo: 1000),
    ], maxBytes: 250);

    expect(plan.cold, ['old1']);
    expect(plan.warm, ['mid1']);
    expect(plan.fresh, ['new1']);
    expect(plan.drop, ['old1']);
    expect(plan.keptBytes, 200);
    expect(plan.droppedBytes, 100);
  });

  test(
    'a burst generated together is graded as a block, not per timestamp',
    () {
      // Five entries: three written an hour ago in the same minute, two written
      // just now. Tiers are thirds by count, so the third boundary falls inside
      // the first burst and the current session is not touched at all.
      final plan = planThumbCache([
        _entry('burst1a', minutesAgo: 62),
        _entry('burst1b', minutesAgo: 61),
        _entry('burst1c', minutesAgo: 61),
        _entry('burst2a', minutesAgo: 1),
        _entry('burst2b', minutesAgo: 0),
      ], maxBytes: 350);

      expect(plan.cold, ['burst1a']);
      expect(plan.warm, ['burst1b']);
      expect(plan.fresh, ['burst1c', 'burst2a', 'burst2b']);
      expect(plan.drop, ['burst1a', 'burst1b']);
      expect(plan.keptBytes, 300);
    },
  );

  test('the newest tier is spent when the colder ones cannot pay', () {
    // Nothing but the current session in the cache, and a budget below it: the
    // oldest of that session goes, and the shed stops as soon as it is under.
    final plan = planThumbCache([
      _entry('a', minutesAgo: 3),
      _entry('b', minutesAgo: 2),
      _entry('c', minutesAgo: 1),
    ], maxBytes: 50);

    expect(plan.cold, ['a']);
    expect(plan.warm, ['b']);
    expect(plan.fresh, ['c']);
    expect(plan.drop, ['a', 'b', 'c']);
    expect(
      plan.keptBytes,
      0,
      reason:
          'every drop is a whole 100-byte entry and the budget is 50, so the '
          'shed can only land on zero — it never overshoots upwards',
    );
  });

  test('the same rule holds at any age scale — no age is asserted', () {
    // Identical sizes and budget, one cache spanning a year and one spanning a
    // minute: the SHAPE of the answer is the same, because the boundary comes
    // from the entries rather than from a calendar. This is what makes an
    // absolute "older than N days" rule unnecessary — and wrong.
    List<ThumbCacheEntry> spanning(Duration step) => [
      _entry('old', minutesAgo: step.inMinutes * 2),
      _entry('mid', minutesAgo: step.inMinutes),
      _entry('new', minutesAgo: 0),
    ];

    final year = planThumbCache(
      spanning(const Duration(days: 182)),
      maxBytes: 250,
    );
    final minute = planThumbCache(
      spanning(const Duration(minutes: 1)),
      maxBytes: 250,
    );

    for (final plan in [year, minute]) {
      expect(plan.cold, ['old']);
      expect(plan.warm, ['mid']);
      expect(plan.fresh, ['new']);
      expect(plan.drop, ['old']);
      expect(plan.keptBytes, 200);
    }
  });

  test(
    'bytes decide the shed, so one big cold entry can cover the overshoot',
    () {
      // 1100 bytes over a 1000-byte budget: the single old entry pays for the
      // whole overshoot, where a count of files would have taken two entries.
      final plan = planThumbCache([
        _entry('bigOld', minutesAgo: 3000, bytes: 900),
        _entry('small1', minutesAgo: 1000),
        _entry('small2', minutesAgo: 10),
      ], maxBytes: 1000);

      expect(plan.drop, ['bigOld']);
      expect(plan.keptBytes, 200);
    },
  );

  test('an empty cache produces an empty plan, not a crash', () {
    final plan = planThumbCache([], maxBytes: 100);
    expect(plan.graded, 0);
    expect(plan.drop, isEmpty);
    expect(describeThumbCachePlan(plan), 'cache is empty');
  });

  test('the budget is the platform default unless the user picked one', () {
    // The hysteresis helper is gone with the automatic management it served:
    // nothing prunes on its own, so the arithmetic left to pin is what the MANUAL
    // clean-up aims at, and that the user's own target wins over the default.
    expect(thumbCacheBudgetBytes(isMobile: true), 96 * 1024 * 1024);
    expect(thumbCacheBudgetBytes(isMobile: false), 512 * 1024 * 1024);
    expect(
      thumbCacheBudgetBytes(isMobile: true, limitMb: 256),
      256 * 1024 * 1024,
    );
    expect(
      thumbCacheBudgetBytes(isMobile: false, limitMb: 64),
      64 * 1024 * 1024,
    );
  });
}
