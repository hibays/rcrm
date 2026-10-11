// test/thumb_cache_dialog_test.dart
// The cache dialog: the grading is legible, every tier can be deleted on its own,
// and the default strategy says out loud what it does.
//
// Three things are pinned here, all of them the point of the design:
//
//  * the rows show an AGE, not a date ("generated 2 months ago") — a boundary
//    answers "how old is this?", and a calendar date makes the reader subtract;
//  * each row deletes ITSELF, whole, and nothing else — the manual per-tier
//    removal, with no selection model in between;
//  * the default clean-up is a STATED strategy ("coldest entries until the cache
//    is under X"), switchable at the point of use, and it is not a selection.
//
// The plan is built here rather than read off a filesystem, so the rows describe a
// known grading; `describeAge` itself is covered in the age test file.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/thumb_cache_policy.dart';
import 'package:rcrm_gui/widgets/thumb_cache_dialog.dart';

final _now = DateTime(2026, 3, 1, 12);

ThumbCacheEntry _entry(String name, {required int daysAgo, int bytes = 100}) =>
    ThumbCacheEntry(
      name: name,
      generatedAt: _now.subtract(Duration(days: daysAgo)),
      bytes: bytes,
    );

/// Three entries in three widely separated generations, and a budget that only
/// needs the oldest: cold holds one, warm one, fresh one.
ThumbCachePlan _plan() => planThumbCache([
  _entry('cold', daysAgo: 400, bytes: 3000),
  _entry('warm', daysAgo: 40, bytes: 2000),
  _entry('fresh', daysAgo: 1, bytes: 1000),
], maxBytes: 4000);

/// Opens the dialog and returns a READER for the choice.
///
/// A reader, not the value: the choice is assigned inside the button's async
/// closure long after this returns, so returning the value would hand back the null
/// it held at that moment.
///
/// ONE harness for every case, on a phone-sized surface: the rows are not `dense`,
/// so on the 800x600 test default the last action sits off-screen inside the
/// dialog's scroll view, and a tap there fails the hit test — which says nothing
/// about the dialog and everything about the window.
Future<ThumbCacheChoice? Function()> _open(
  WidgetTester tester, {
  ThumbCachePlan? plan,
  int initialLimitMb = 0,
}) async {
  await tester.binding.setSurfaceSize(const Size(500, 900));
  addTearDown(() => tester.binding.setSurfaceSize(null));

  ThumbCacheChoice? result;
  await tester.pumpWidget(
    MaterialApp(
      home: Builder(
        builder: (context) => Scaffold(
          body: Center(
            child: ElevatedButton(
              onPressed: () async {
                result = await showDialog<ThumbCacheChoice>(
                  context: context,
                  builder: (_) => ThumbCacheDialog(
                    plan: plan ?? _plan(),
                    initialLimitMb: initialLimitMb,
                    clock: () => _now,
                  ),
                );
              },
              child: const Text('open'),
            ),
          ),
        ),
      ),
    ),
  );
  await tester.tap(find.text('open'));
  await tester.pumpAndSettle();
  return () => result;
}

/// Taps a labelled control as the WIDGET: a label is one child of a row whose
/// target is the control itself, so tapping the text lands beside the handler.
Future<void> _tap(WidgetTester tester, Type type, String label) async {
  await tester.tap(find.widgetWithText(type, label));
  await tester.pumpAndSettle();
  // One more pump: the harness captures the choice from inside the `onPressed`
  // async closure, and this flushes the microtask that assigns it.
  await tester.pump();
}

void main() {
  testWidgets('every tier is an entry, and the age is an age', (tester) async {
    await _open(tester);

    for (final label in ['Cold', 'Warm', 'Fresh']) {
      expect(find.text(label), findsOneWidget, reason: label);
    }
    expect(find.textContaining('1 year ago'), findsOneWidget);
    expect(find.textContaining('1 month ago'), findsOneWidget);
    expect(
      find.textContaining('what you are looking at'),
      findsOneWidget,
      reason: 'the newest tier names itself rather than dating itself',
    );
    // Ages, in words — never a calendar date.
    expect(find.textContaining('2026-'), findsNothing);
    expect(find.textContaining('2025-'), findsNothing);
    // Sizes are there too: the other half of the grading. Both spellings because
    // `ThumbCache.human` switches unit at 1024 bytes: 3000 is "2.9 KB" (not 3.0)
    // and 1000 is "1000 B".
    expect(find.textContaining('2.9 KB'), findsOneWidget);
    expect(find.textContaining('1000 B'), findsOneWidget);
    // No selection model: the rows act, they do not accumulate ticks.
    expect(find.byType(CheckboxListTile), findsNothing);
  });

  testWidgets('each row deletes its own tier, whole, and nothing else', (
    tester,
  ) async {
    final readChoice = await _open(tester);

    // Three rows, three delete buttons — and the tooltip names the tier, so the
    // control does not have to be guessed at.
    expect(find.byIcon(Icons.delete_outline), findsNWidgets(3));
    expect(find.byTooltip('Delete the Cold tier'), findsOneWidget);

    await tester.tap(find.byTooltip('Delete the Cold tier'));
    await tester.pumpAndSettle();
    await tester.pump();

    expect(readChoice()?.wholeTier, isTrue, reason: 'the whole tier goes');
    expect(readChoice()?.spend, {ThumbCacheTier.cold}, reason: 'and only that');
    expect(readChoice()?.clearAll, isFalse);
  });

  testWidgets('the default strategy is stated, and switchable here', (
    tester,
  ) async {
    final readChoice = await _open(tester, initialLimitMb: 256);

    expect(
      find.textContaining('coldest entries'),
      findsOneWidget,
      reason: 'the button says what it will do',
    );
    expect(find.text('Trim to'), findsOneWidget);
    expect(
      find.text('256 MB'),
      findsOneWidget,
      reason: 'the remembered target',
    );

    await _tap(tester, SimpleDialogOption, 'Auto trim');

    expect(readChoice()?.wholeTier, isFalse, reason: 'a strategy, not a tier');
    expect(readChoice()?.clearAll, isFalse);
    expect(readChoice()?.limitMb, 256, reason: 'carried out with the target');
  });

  testWidgets('"Delete all" asks for the clear path, no tiers', (tester) async {
    final readChoice = await _open(tester);
    await _tap(tester, SimpleDialogOption, 'Delete all');

    expect(readChoice()?.clearAll, isTrue);
    expect(readChoice()?.spend, isEmpty);
  });

  testWidgets('an empty cache offers no clean-up to run', (tester) async {
    // A control that can only do nothing is the dead-control defect: with nothing
    // cached there are no rows, and Auto trim is disabled rather than decorative.
    await _open(tester, plan: planThumbCache(const [], maxBytes: 1000));

    expect(find.text('Nothing cached yet.'), findsOneWidget);
    expect(find.byIcon(Icons.delete_outline), findsNothing);
    // BOTH actions are disabled: with the cache empty there is nothing for either
    // of them to do, and a live button that cannot act is the dead-control defect.
    for (final label in ['Auto trim', 'Delete all']) {
      final action = tester.widget<SimpleDialogOption>(
        find.widgetWithText(SimpleDialogOption, label),
      );
      expect(action.onPressed, isNull, reason: label);
    }
  });

  test('deleting one tier whole ignores the budget entirely', () {
    // The per-row delete's guarantee, asserted on the POLICY, where it lives: a
    // budget that could stop it halfway would make the button a suggestion.
    final entries = [
      _entry('cold', daysAgo: 400, bytes: 10),
      _entry('warm', daysAgo: 40, bytes: 10),
      _entry('fresh', daysAgo: 1, bytes: 10),
    ];

    final whole = planThumbCache(
      entries,
      maxBytes: 1000, // ten times the whole cache: the budget is not the point
      spend: {ThumbCacheTier.cold},
      dropWholeTiers: true,
      now: _now,
    );
    expect(whole.drop, ['cold'], reason: 'all of the tier, nothing else');
    expect(whole.keptBytes, 20);

    // The default strategy stops at the budget — both remain available.
    final budgeted = planThumbCache(entries, maxBytes: 25, now: _now);
    expect(budgeted.drop, ['cold']);
    expect(budgeted.keptBytes, 20);
  });
}
