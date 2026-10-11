// test/thumb_cache_age_test.dart
// The ages in the cache dialog: minutes, hours, days, months, years.
//
// A tier boundary answers "how old is this?", so that is what the dialog says.
// A date would make the reader subtract two dates to get there — and the reader
// is being asked to decide, at that moment, whether a tier is worth keeping.
//
// The units are pinned at their edges, because that is where a formatter of this
// kind goes wrong: 59 minutes must not read as an hour, and one of each unit must
// read in the singular.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/thumb_cache_policy.dart';

final _now = DateTime(2026, 3, 1, 12);

String _age(Duration elapsed) => describeAge(_now.subtract(elapsed), now: _now);

void main() {
  test('minutes, up to the hour', () {
    expect(_age(Duration.zero), 'just now');
    expect(_age(const Duration(seconds: 30)), 'just now');
    expect(_age(const Duration(minutes: 1)), '1 min ago');
    expect(_age(const Duration(minutes: 59)), '59 mins ago');
  });

  test('hours, up to the day', () {
    expect(_age(const Duration(minutes: 60)), '1 hour ago');
    expect(_age(const Duration(hours: 23)), '23 hours ago');
  });

  test('days, up to the month', () {
    expect(_age(const Duration(hours: 24)), '1 day ago');
    expect(_age(const Duration(days: 29)), '29 days ago');
  });

  test('months, up to the year', () {
    expect(_age(const Duration(days: 30)), '1 month ago');
    expect(_age(const Duration(days: 364)), '12 months ago');
  });

  test('years beyond that', () {
    expect(_age(const Duration(days: 365)), '1 year ago');
    expect(_age(const Duration(days: 365 * 3)), '3 years ago');
  });

  test('never a calendar date', () {
    for (final elapsed in [
      const Duration(minutes: 5),
      const Duration(days: 3),
      const Duration(days: 400),
    ]) {
      final text = _age(elapsed);
      expect(text, isNot(contains('2026')));
      expect(text, isNot(contains('2025')));
      expect(text, endsWith('ago'));
    }
  });
}
