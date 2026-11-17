// test/keyword_chip_test.dart
// The two tag-chip roles in search: the neutral suggestion ADDS a tag, the
// filled/checked selected chip REMOVES one. Tags are multi-select, so both
// states have to be unmistakable.

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/utils/keywords.dart';
import 'package:rcrm_gui/widgets/keyword_chip.dart';

void main() {
  testWidgets('a suggestion adds and a selected chip removes', (tester) async {
    await tester.binding.setSurfaceSize(const Size(320, 220));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    var added = false;
    var removed = false;
    await tester.pumpWidget(
      MaterialApp(
        theme: RCrmTheme.dark,
        home: Scaffold(
          body: Wrap(
            spacing: 6,
            runSpacing: 2,
            children: [
              KeywordChip(
                tag: const KeywordTag('amateur', 'Amateur'),
                onTap: () => added = true,
              ),
              SelectedKeywordChip(
                tag: const KeywordTag('cooking', 'Cooking'),
                onRemove: () => removed = true,
              ),
            ],
          ),
        ),
      ),
    );

    expect(find.text('#Amateur'), findsOneWidget);
    expect(find.text('#Cooking'), findsOneWidget);
    expect(tester.takeException(), isNull);

    await tester.tap(find.text('#Amateur'));
    await tester.pump();
    expect(added, isTrue);

    await tester.tap(find.text('#Cooking'));
    await tester.pump();
    expect(removed, isTrue);
  });
}
