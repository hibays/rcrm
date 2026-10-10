// test/pan_lock_test.dart
// The rule the mobile player uses to decide what a drag means.
//
// The function exists because of a real failure: the old inline rule committed
// the drag as soon as `max(|dx|, |dy|)` cleared a 12px slop, so a 30px/29px
// diagonal — a drag the user never aimed at as a scrub — hid the whole control
// bar for the rest of the gesture. The cases below pin the decision the old rule
// got wrong, and the boundaries that decision now sits on.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/pan_lock.dart';

void main() {
  group('decidePanMode', () {
    test('a near-diagonal drag is not a decision yet', () {
      // The certified failure: 30 > 12 passed the old slop test, and 30 > 29
      // made it a seek — controls gone for a diagonal. Neither axis dominates
      // the other by 1.5x, so the honest answer is 0 and the caller keeps
      // asking; the drag may still commit later.
      expect(decidePanMode(const Offset(30, 29)), 0);
      expect(decidePanMode(const Offset(29, 30)), 0);
      expect(decidePanMode(const Offset(-30, 29)), 0);
    });

    test('a big diagonal is still not a decision', () {
      // Slop is not the whole rule: scaling the same ambiguous drag up does not
      // make it less ambiguous. The old rule returned 1 for both of these.
      expect(decidePanMode(const Offset(300, 290)), 0);
      expect(decidePanMode(const Offset(290, -300)), 0);
    });

    test('horizontal travel that dominates is a seek', () {
      expect(decidePanMode(const Offset(30, 5)), 1);
      // Direction does not matter, only which axis owns the drag.
      expect(decidePanMode(const Offset(-30, 5)), 1);
      expect(decidePanMode(const Offset(-400, 10)), 1);
    });

    test('vertical travel that dominates is the vertical gesture', () {
      // 2 = brightness/volume: which side of the screen the drag started on is
      // the caller's rule, and that is why 3 is never returned here.
      expect(decidePanMode(const Offset(5, 30)), 2);
      expect(decidePanMode(const Offset(-5, -30)), 2);
      expect(decidePanMode(const Offset(10, 400)), 2);
    });

    test('anything below the slop is undecided', () {
      expect(decidePanMode(Offset.zero), 0);
      expect(decidePanMode(const Offset(11, 3)), 0);
      expect(decidePanMode(const Offset(3, -11)), 0);
      expect(decidePanMode(const Offset(-11, -11)), 0);
    });

    test('the slop boundary is exclusive on both axes', () {
      // Exactly at the slop is still below it (`>` not `>=`), which costs one
      // frame: the caller asks again on the next update.
      expect(decidePanMode(const Offset(12, 0)), 0);
      expect(decidePanMode(const Offset(0, 12)), 0);
      expect(decidePanMode(const Offset(13, 0)), 1);
      expect(decidePanMode(const Offset(0, 13)), 2);
    });

    test('dominance is strict, not a tie-break', () {
      // 18 is exactly 1.5 x 12, so neither axis dominates.
      expect(decidePanMode(const Offset(18, 12)), 0);
      expect(decidePanMode(const Offset(19, 12)), 1);
      expect(decidePanMode(const Offset(12, 18)), 0);
      expect(decidePanMode(const Offset(12, 19)), 2);
    });

    test('the slop and the ratio are parameters, not constants', () {
      // The defaults are what the screen uses; the parameters exist so the rule
      // can be stated once and read without arithmetic.
      expect(decidePanMode(const Offset(30, 29), dominance: 1.0), 1);
      expect(decidePanMode(const Offset(30, 29), slop: 40), 0);
      expect(decidePanMode(const Offset(30, 5), slop: 40), 0);
    });

    test('travel that is NaN stays undecided', () {
      // Every comparison is false for NaN, and "not yet" is the safe answer —
      // never a commit that would hide the bar on a nonsense value.
      expect(decidePanMode(const Offset(double.nan, 30)), 0);
      expect(decidePanMode(const Offset(30, double.nan)), 0);
      expect(decidePanMode(const Offset(double.nan, double.nan)), 0);
    });
  });
}
