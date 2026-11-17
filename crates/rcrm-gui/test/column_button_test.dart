// test/column_button_test.dart
// The column control's RANGE is what the current width can display, not a
// constant 2..6 — so it can collapse to a single value on a narrow window.
// Two rules have to hold together then: the control is not shown, and it never
// writes. Writing is the dangerous half: the caller's range is what the window
// allows, so a tap would replace a stored 6 with the 2 the window happened to
// show, without changing a single pixel on screen.

import 'package:flutter/gestures.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/widgets/column_button.dart';
import 'package:rcrm_gui/widgets/media_toolbar.dart';

Future<void> _pump(WidgetTester tester, Widget child) async {
  await tester.binding.setSurfaceSize(const Size(700, 300));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      theme: RCrmTheme.dark,
      home: Scaffold(body: Center(child: child)),
    ),
  );
  await tester.pump();
}

MediaToolbar _bar({
  required int min,
  required int max,
  required int current,
  ValueChanged<int>? onChanged,
}) => MediaToolbar(
  sortOptions: const ['name'],
  currentSort: 'name',
  isAscending: true,
  onSortChanged: (_) {},
  onSortDirectionChanged: () {},
  onColumnsChanged: onChanged ?? (_) {},
  currentColumns: current,
  minColumns: min,
  maxColumns: max,
);

void main() {
  testWidgets('a range holding one value neither cycles nor steps', (
    tester,
  ) async {
    final calls = <int>[];
    await _pump(
      tester,
      ColumnButton(current: 2, min: 2, max: 2, onChanged: calls.add),
    );

    await tester.tap(find.byType(TextButton));
    await tester.pump();
    expect(
      calls,
      isEmpty,
      reason: 'writing 2 over a stored 6 is data loss, not a no-op',
    );

    // The wheel is the other door into the same write.
    final pointer = TestPointer(1, PointerDeviceKind.mouse);
    final centre = tester.getCenter(find.byType(TextButton));
    await tester.sendEventToBinding(pointer.hover(centre));
    await tester.sendEventToBinding(pointer.scroll(const Offset(0, -120)));
    await tester.pump();
    expect(calls, isEmpty);
  });

  testWidgets('a real range still cycles and wraps', (tester) async {
    final calls = <int>[];
    await _pump(
      tester,
      ColumnButton(current: 2, min: 2, max: 3, onChanged: calls.add),
    );

    await tester.tap(find.byType(TextButton));
    await tester.pump();
    expect(calls, [3]);

    await _pump(
      tester,
      ColumnButton(current: 3, min: 2, max: 3, onChanged: calls.add),
    );
    await tester.tap(find.byType(TextButton));
    await tester.pump();
    expect(calls, [3, 2], reason: 'the top of the range wraps to the floor');
  });

  testWidgets('the toolbar does not show a control that cannot act', (
    tester,
  ) async {
    // A narrow desktop window displays two columns whatever is stored, so the
    // range the caller passes is 2..2.
    await _pump(tester, _bar(min: 2, max: 2, current: 2));
    expect(find.byType(ColumnButton), findsNothing);

    // One column of range is enough for it to come back.
    await _pump(tester, _bar(min: 2, max: 3, current: 2));
    expect(find.byType(ColumnButton), findsOneWidget);
  });
}
