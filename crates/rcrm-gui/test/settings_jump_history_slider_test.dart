// test/settings_jump_history_slider_test.dart
// The settings screen's jump-history slider, at the seam it lives on.
//
// The control is a real `Slider` in `screens/settings_screen.dart` (the
// provider contract it writes to is pinned in `video_jump_stack_test.dart`),
// so these tests mount the screen the way `settings_layout_test.dart` does and
// check what the user actually sees and touches: the value beside the label,
// the travel of the slider, and the write-through to the persisted setting.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/settings_service.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  /// Pumps the settings screen at a width that selects the wide (ListTile)
  /// layout, tall enough that the Display section's groups are built — the
  /// ListView builds lazily, and the jump-history group sits below the fold of
  /// a default-sized test surface.
  Future<ProviderContainer> pumpSettings(
    WidgetTester tester, {
    Size size = const Size(1000, 1200),
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

  testWidgets('the slider shows the current limit and writes a change through',
      (tester) async {
    final c = await pumpSettings(tester);

    expect(find.text('Jump History'), findsOneWidget);
    final slider = tester.widget<Slider>(find.byType(Slider));
    expect(slider.min, kVideoJumpHistoryMin.toDouble());
    expect(slider.max, kVideoJumpHistoryMax.toDouble());
    expect(slider.value, kVideoJumpHistoryDefault.toDouble());
    expect(
      c.read(uiSettingsProvider).videoJumpHistoryLimit,
      kVideoJumpHistoryDefault,
    );
    // The value is shown next to the label.
    expect(find.text('$kVideoJumpHistoryDefault'), findsOneWidget);

    // Drive the control's own callback: a drag would land on an arbitrary step
    // of the 49 the track resolves, and the point here is the wiring, not the
    // gesture arithmetic (the drag itself is covered below).
    slider.onChanged!(30);
    await tester.pump();

    expect(c.read(uiSettingsProvider).videoJumpHistoryLimit, 30);
    expect(await SettingsService().getVideoJumpHistoryLimit(), 30);
    expect(find.text('30'), findsOneWidget);
    expect(find.text('$kVideoJumpHistoryDefault'), findsNothing);
  });

  testWidgets('dragging the slider moves the limit and persists it',
      (tester) async {
    final c = await pumpSettings(tester);

    await tester.drag(find.byType(Slider), const Offset(60, 0));
    await tester.pump();

    final limit = c.read(uiSettingsProvider).videoJumpHistoryLimit;
    expect(
      limit,
      greaterThan(kVideoJumpHistoryDefault),
      reason: 'a rightward drag must raise the limit',
    );
    expect(limit, lessThanOrEqualTo(kVideoJumpHistoryMax));
    expect(await SettingsService().getVideoJumpHistoryLimit(), limit);
    // The number on screen is the value now in effect.
    expect(find.text('$limit'), findsOneWidget);
  });

  testWidgets('a stored limit is restored into the slider at launch',
      (tester) async {
    SharedPreferences.setMockInitialValues({'video_jump_history_limit': 42});
    final c = ProviderContainer();
    // What `app.dart` does at startup.
    await c.read(uiSettingsProvider.notifier).load();

    await pumpSettings(tester, container: c);

    expect(c.read(uiSettingsProvider).videoJumpHistoryLimit, 42);
    expect(tester.widget<Slider>(find.byType(Slider)).value, 42);
    expect(find.text('42'), findsOneWidget);
  });

  testWidgets('narrow cards stack the label over the slider without overflow',
      (tester) async {
    await pumpSettings(tester, size: const Size(360, 1500));

    expect(find.text('Jump History'), findsOneWidget);
    expect(find.byType(Slider), findsOneWidget);
    expect(find.text('$kVideoJumpHistoryDefault'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
