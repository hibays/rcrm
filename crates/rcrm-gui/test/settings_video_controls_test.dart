// The two toolbar controls that disappear on a very narrow window must have
// a real second door. A mouse user cannot pinch a grid, and a 320dp window
// cannot show the Organize menu, so Settings owns both settings at every size.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';

void main() {
  testWidgets('narrow Settings keeps grouping and grid columns reachable', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final c = ProviderContainer();
    addTearDown(c.dispose);
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: c,
        child: const MaterialApp(home: SettingsScreen()),
      ),
    );
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));

    final scrollable = find.byType(Scrollable).first;
    final grouping = find.byKey(const Key('video-grouping-seg'));
    await tester.scrollUntilVisible(grouping, 300, scrollable: scrollable);
    await tester.pump();
    expect(grouping, findsOneWidget);
    expect(
      find.descendant(of: grouping, matching: find.text('Format')),
      findsOneWidget,
    );
    await tester.tap(
      find.descendant(of: grouping, matching: find.text('Format')),
    );
    await tester.pump();
    expect(c.read(uiSettingsProvider).videoClassification, 'format');

    final columns = find.byKey(const Key('video-grid-columns-seg'));
    await tester.scrollUntilVisible(columns, 300, scrollable: scrollable);
    await tester.pump();
    expect(columns, findsOneWidget);
    // The segments are built from `videoGridChoiceBounds`, not from five
    // literals: this is a desktop window, whose floor is two columns, and the
    // range ends at six. A count outside that range either cannot be stored
    // (1) or cannot be shown (7+).
    final seg = tester.widget<SegmentedButton<int>>(
      find.descendant(of: columns, matching: find.byType(SegmentedButton<int>)),
    );
    expect(seg.segments.map((s) => s.value).toList(), <int>[2, 3, 4, 5, 6]);
    expect(seg.selected, <int>{4}, reason: 'the stored default is four');
    await tester.tap(find.descendant(of: columns, matching: find.text('6')));
    await tester.pump();
    expect(c.read(videoGridColumnsProvider), 6);
    expect(
      tester
          .widget<SegmentedButton<int>>(
            find.descendant(
              of: columns,
              matching: find.byType(SegmentedButton<int>),
            ),
          )
          .selected,
      <int>{6},
    );

    expect(tester.takeException(), isNull);
  });
}
