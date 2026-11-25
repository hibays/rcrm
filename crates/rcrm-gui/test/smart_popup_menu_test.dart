// test/smart_popup_menu_test.dart
// The popup menu is a MENU, and the two things that make it one are pinned
// here: it is sized by its content (not by the surface it is anchored into) and
// its rows are the native menu's 48dp, so it looks like the control it
// replaces. Regression: the anchored surface hands its child the whole window,
// and a `stretch` column fills it — measured on Windows, the player's speed menu
// opened as a full-window slab.
//
// A selection comes back through `onSelected` only for a real choice; closing
// without one is `onClosed` (covered where the caller uses it).

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/smart_popup_menu.dart';

Future<void> _pump(
  WidgetTester tester, {
  ValueChanged<String>? onSelected,
  List<String> values = const ['0.5x', '0.75x', '1x'],
}) async {
  await tester.binding.setSurfaceSize(const Size(1280, 720));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      navigatorObservers: [FlutterSmartDialog.observer],
      builder: FlutterSmartDialog.init(),
      home: Scaffold(
        body: Center(
          child: SmartPopupMenu<String>(
            tooltip: 'Open',
            onSelected: onSelected,
            items: [
              for (final v in values)
                SmartPopupMenuItem<String>(value: v, child: Text(v)),
            ],
            child: const SizedBox(
              width: 40,
              height: 40,
              child: Center(child: Text('open')),
            ),
          ),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _open(WidgetTester tester) async {
  await tester.tap(find.text('open'));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('the menu is as wide as its content, not the window', (
    tester,
  ) async {
    await _pump(tester);
    await _open(tester);

    final rows = find.byType(SmartPopupMenuItem<String>);
    expect(rows, findsNWidgets(3));
    final width = tester.getRect(rows.first).width;
    expect(
      width,
      lessThanOrEqualTo(280),
      reason:
          'a menu is not a full-window slab (the anchored surface would '
          'hand it 1280 if the body did not ask for its own width)',
    );
    expect(
      width,
      greaterThanOrEqualTo(112),
      reason:
          "PopupMenuButton's own floor, so a short choice is still a target",
    );
    // The rows fill the panel (stretch is what gives every row one width).
    for (final row in rows.evaluate()) {
      final rect = tester.getRect(find.byWidget(row.widget));
      expect(rect.width, width, reason: 'rows are one column');
    }
  });

  testWidgets('a row is the native menu\'s 48dp floor', (tester) async {
    await _pump(tester);
    await _open(tester);
    for (final row in find.byType(SmartPopupMenuItem<String>).evaluate()) {
      expect(
        tester.getRect(find.byWidget(row.widget)).height,
        greaterThanOrEqualTo(48),
        reason: 'one menu row, not a dense list row',
      );
    }
  });

  testWidgets('a long choice is capped, not allowed to run off the screen', (
    tester,
  ) async {
    await _pump(
      tester,
      values: ['a label that is long enough to want the whole window width'],
    );
    await _open(tester);
    final row = find.byType(SmartPopupMenuItem<String>);
    expect(
      tester.getRect(row).width,
      lessThanOrEqualTo(280),
      reason: "the panel caps at PopupMenuButton's 280 and the label wraps",
    );
  });

  testWidgets('a choice is handed back through onSelected', (tester) async {
    String? selected;
    await _pump(tester, onSelected: (v) => selected = v);
    await _open(tester);
    await tester.tap(find.text('0.75x'));
    await tester.pumpAndSettle();
    expect(selected, '0.75x');
    expect(find.byType(SmartPopupMenuItem<String>), findsNothing);
  });

  testWidgets('a choice reaches its owner on the click, not after the panel '
      'has animated away', (tester) async {
    var calls = 0;
    String? selected;
    await _pump(
      tester,
      onSelected: (v) {
        calls++;
        selected = v;
      },
    );
    await _open(tester);

    await tester.tap(find.text('0.75x'));
    // ONE frame, no settle: the panel is still on screen (its exit animation
    // has not finished), and the page must already know what was chosen —
    // routing the value through `showAttach`'s future made every filter land
    // after the menu collapsed, which reads as a third of a second of nothing.
    await tester.pump();
    expect(
      find.byType(SmartPopupMenuItem<String>),
      findsNWidgets(3),
      reason: 'the panel is still animating out on this frame',
    );
    expect(selected, '0.75x');
    expect(calls, 1, reason: 'the awaited result must not deliver it again');

    await tester.pumpAndSettle();
    expect(calls, 1);
    expect(find.byType(SmartPopupMenuItem<String>), findsNothing);
  });

  testWidgets('a second tap on the same row, before the panel is gone, does '
      'not deliver the choice twice', (tester) async {
    var calls = 0;
    await _pump(tester, onSelected: (_) => calls++);
    await _open(tester);

    await tester.tap(find.text('0.75x'));
    await tester.pump();
    // The row is still tappable on this frame (see the test above), so an
    // impatient second tap lands on it. One choice, one delivery: the owner
    // may not be idempotent — the sort menu's re-pick FLIPS the direction, so
    // a double delivery would flip and flip back.
    await tester.tap(find.text('0.75x'), warnIfMissed: false);
    await tester.pump();
    await tester.pumpAndSettle();
    expect(calls, 1);
  });

  testWidgets('closing without a choice selects nothing', (tester) async {
    var calls = 0;
    await _pump(tester, onSelected: (_) => calls++);
    await _open(tester);
    // A tap on the mask dismisses without a value.
    await tester.tapAt(const Offset(20, 20));
    await tester.pumpAndSettle();
    expect(calls, 0);
    expect(find.byType(SmartPopupMenuItem<String>), findsNothing);
  });

  // A visible "copied" toast must not eat the first tap on a menu row:
  // smart_dialog checks its notify queue BEFORE its dialog queue, so an
  // untagged `dismiss` used to close the toast instead of the menu and the
  // row's action never ran (desktop: Copy path, then Details within 2.5s).
  testWidgets('a visible notify does not swallow the first menu tap', (
    tester,
  ) async {
    String? selected;
    await tester.binding.setSurfaceSize(const Size(800, 600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      MaterialApp(
        navigatorObservers: [FlutterSmartDialog.observer],
        builder: FlutterSmartDialog.init(),
        home: Scaffold(
          body: Center(
            child: SmartPopupMenu<String>(
              onSelected: (v) => selected = v,
              items: [
                SmartPopupMenuItem<String>(
                  value: 'details',
                  child: const Text('Details'),
                ),
              ],
              child: const SizedBox(
                width: 40,
                height: 40,
                child: Center(child: Text('open')),
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();

    SmartDialog.showNotify(msg: 'Path copied', notifyType: NotifyType.success);
    await tester.pumpAndSettle();

    await tester.tap(find.text('Details'));
    await tester.pumpAndSettle();
    expect(
      selected,
      'details',
      reason: 'first tap selects, not dismiss the notify',
    );

    // Drain the notify's own auto-dismiss timer before the tree is torn down.
    await tester.pump(const Duration(seconds: 3));
    await tester.pumpAndSettle();
  });
}
