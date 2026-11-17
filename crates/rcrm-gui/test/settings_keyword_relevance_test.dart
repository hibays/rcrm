// test/settings_keyword_relevance_test.dart
// The settings screen's Keyword Relevance slider.
//
// The control is the one place the automatic-keyword weight is adjusted; these
// tests mount the screen and check the travel, the value beside it and the
// write-through to the persisted setting, the same way the jump-history test
// does.

import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/settings_service.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  Future<ProviderContainer> pumpSettings(
    WidgetTester tester, {
    Size size = const Size(1000, 1600),
    ProviderContainer? container,
  }) async {
    await tester.binding.setSurfaceSize(size);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final c = container ?? ProviderContainer();
    addTearDown(c.dispose);
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: c,
        child: MaterialApp(theme: RCrmTheme.dark, home: const SettingsScreen()),
      ),
    );
    await tester.pump();
    return c;
  }

  const finder = ValueKey('keyword-relevance-slider');

  testWidgets(
    'the slider shows the current weight and writes a change through',
    (tester) async {
      final c = await pumpSettings(tester);

      expect(find.text('Keyword Relevance'), findsOneWidget);
      final slider = tester.widget<Slider>(find.byKey(finder));
      expect(slider.min, kKeywordRelevanceMin.toDouble());
      expect(slider.max, kKeywordRelevanceMax.toDouble());
      expect(slider.value, kKeywordRelevanceDefault.toDouble());
      expect(
        c.read(uiSettingsProvider).keywordRelevance,
        kKeywordRelevanceDefault,
      );
      expect(find.text('$kKeywordRelevanceDefault'), findsOneWidget);

      slider.onChanged!(82);
      await tester.pump();

      expect(c.read(uiSettingsProvider).keywordRelevance, 82);
      expect(await SettingsService().getKeywordRelevance(), 82);
      expect(find.text('82'), findsOneWidget);
    },
  );

  testWidgets('a stored weight is restored into the slider at launch', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({'keyword_relevance': 25});
    final c = ProviderContainer();
    await c.read(uiSettingsProvider.notifier).load();

    await pumpSettings(tester, container: c);

    expect(c.read(uiSettingsProvider).keywordRelevance, 25);
    expect(tester.widget<Slider>(find.byKey(finder)).value, 25);
  });

  testWidgets(
    'the narrow row stacks the subtitle and slider without overflow',
    (tester) async {
      await pumpSettings(tester, size: const Size(360, 3000));

      expect(find.text('Keyword Relevance'), findsOneWidget);
      expect(find.byKey(finder), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );
}
