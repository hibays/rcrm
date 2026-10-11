// test/settings_cache_entry_test.dart
// The settings page's cache row: ONE way in.
//
// Managing the cache and deleting all of it are two answers to the same question,
// so they are offered when that one row is opened — not as two rows, which made
// the careful option look like the exception beside the drastic one. These tests
// pin the shape: a single tile, both choices inside it, and each choice saying
// what it does.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/thumb_cache.dart';

Future<void> _pump(WidgetTester tester) async {
  await tester.binding.setSurfaceSize(const Size(900, 1400));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    const ProviderScope(child: MaterialApp(home: SettingsScreen())),
  );
  await tester.pump();
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ThumbCache.resetForTest();
  });
  tearDown(ThumbCache.resetForTest);

  testWidgets('one row, and the drastic action is not beside it', (
    tester,
  ) async {
    await _pump(tester);

    expect(find.text('Thumbnail cache'), findsOneWidget);
    expect(
      find.text('Delete all'),
      findsNothing,
      reason: 'the choices appear when the row is opened, not before',
    );
    expect(
      find.byIcon(Icons.delete_sweep),
      findsNothing,
      reason: 'no second row offering deletion as a peer of management',
    );
    expect(
      find.text('Auto trim'),
      findsNothing,
      reason: 'nor as a button of its own',
    );
  });

  testWidgets('opening the row offers both, each saying what it does', (
    tester,
  ) async {
    await _pump(tester);
    await tester.tap(find.text('Thumbnail cache'));
    await tester.pumpAndSettle();

    expect(find.text('Auto trim'), findsOneWidget);
    expect(find.text('Delete all'), findsOneWidget);
    // Each action says what it will do — the strategy is stated, not implied.
    expect(find.textContaining('coldest entries'), findsOneWidget);
    expect(find.textContaining('regenerated'), findsOneWidget);
    expect(find.textContaining('regenerated'), findsOneWidget);
  });

  testWidgets('both choices are real targets, not decoration', (tester) async {
    await _pump(tester);
    await tester.tap(find.text('Thumbnail cache'));
    await tester.pumpAndSettle();

    // What is asserted here is that each choice RUNS something. Following the
    // tap through to the snackbar is not decidable in a widget test: both paths
    // go through `path_provider`, which has no plugin here, so the async tail of
    // the flow never settles (it is caught and turns into "no cache directory",
    // not into a message). The service side is covered by the cache tests.
    for (final label in ['Auto trim', 'Delete all']) {
      final option = find.widgetWithText(SimpleDialogOption, label);
      expect(option, findsOneWidget, reason: label);
      expect(
        tester.widget<SimpleDialogOption>(option).onPressed,
        isNotNull,
        reason: '$label must actually run something',
      );
    }
  });
}
