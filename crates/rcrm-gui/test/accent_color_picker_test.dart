// test/accent_color_picker_test.dart
// The Custom accent's one door: the picker opens from its swatch, cancelling
// changes nothing, and confirming commits the colour AND selects the accent.

// ignore: deprecated_member_use — the picker's own TextField is flutter's
import 'package:flutter/material.dart' as fm;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/settings_service.dart';

Future<void> _pumpSettings(
  WidgetTester tester,
  ProviderContainer c, {
  Size size = const Size(500, 900),
}) async {
  await tester.binding.setSurfaceSize(size);
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: MaterialApp(
        theme: RCrmTheme.dark,
        navigatorObservers: [FlutterSmartDialog.observer],
        builder: FlutterSmartDialog.init(),
        home: const SettingsScreen(),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('confirming a pick commits the colour and selects Custom', (
    tester,
  ) async {
    final c = ProviderContainer();
    addTearDown(c.dispose);
    await _pumpSettings(tester, c);

    await tester.tap(find.text('Custom'));
    await tester.pumpAndSettle();
    expect(find.text('Custom accent'), findsOneWidget);
    expect(find.text('Use this colour'), findsOneWidget);

    // The picker is built against flutter/material, not the app's material_ui
    // fork, so its TextField is flutter's. The hex field is the one whose
    // controller holds a '#RRGGBB' value.
    final fields = tester
        .widgetList<fm.TextField>(find.byType(fm.TextField))
        .toList();
    final hexIndex = fields.indexWhere(
      (f) => f.controller?.text.startsWith('#') ?? false,
    );
    expect(hexIndex, greaterThanOrEqualTo(0));
    await tester.enterText(find.byType(fm.TextField).at(hexIndex), '#3366FF');
    await tester.pump();

    await tester.tap(find.text('Use this colour'));
    await tester.pumpAndSettle();
    await tester.pump();

    final ui = c.read(uiSettingsProvider);
    expect(ui.appearanceAccent, 'custom');
    expect(ui.appearanceCustomColor, 0xFF3366FF);
    expect(await SettingsService().getAppearanceAccent(), 'custom');
    expect(await SettingsService().getAppearanceCustomColor(), 0xFF3366FF);
    expect(tester.takeException(), isNull);
  });

  testWidgets('cancelling the picker leaves the accent untouched', (
    tester,
  ) async {
    final c = ProviderContainer();
    addTearDown(c.dispose);
    await _pumpSettings(tester, c);
    expect(c.read(uiSettingsProvider).appearanceAccent, 'marquee');

    await tester.tap(find.text('Custom'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    await tester.pump();

    expect(c.read(uiSettingsProvider).appearanceAccent, 'marquee');
    expect(c.read(uiSettingsProvider).appearanceCustomColor, isNull);
    expect(await SettingsService().getAppearanceAccent(), 'marquee');
  });

  testWidgets('a double tap cannot stack two pickers', (tester) async {
    final c = ProviderContainer();
    addTearDown(c.dispose);
    await _pumpSettings(tester, c);

    // No pump between the taps: both land on the chip before the dialog exists.
    await tester.tap(find.text('Custom'));
    await tester.tap(find.text('Custom'));
    await tester.pumpAndSettle();
    expect(find.text('Custom accent'), findsOneWidget);
  });

  testWidgets('the picker fits a 320dp screen without clipping', (
    tester,
  ) async {
    final c = ProviderContainer();
    addTearDown(c.dispose);
    await _pumpSettings(tester, c, size: const Size(320, 640));

    // At 320dp the accent row sits below the fold of the settings scroll view.
    await tester.ensureVisible(find.text('Custom'));
    await tester.pump();
    await tester.tap(find.text('Custom'));
    await tester.pumpAndSettle();
    expect(find.text('Custom accent'), findsOneWidget);

    // The fixed 280dp picker is scaled to the dialog's ~192dp content width;
    // no RenderFlex overflow and no half-visible saturation square.
    final pickerBox = find.ancestor(
      of: find.byType(fm.TextField),
      matching: find.byType(FittedBox),
    );
    expect(pickerBox, findsOneWidget);
    final scale = tester.widget<FittedBox>(pickerBox).fit;
    expect(scale, BoxFit.scaleDown);
    expect(tester.takeException(), isNull);
  });

  testWidgets('the scaled picker still commits a pick at 320dp', (
    tester,
  ) async {
    final c = ProviderContainer();
    addTearDown(c.dispose);
    await _pumpSettings(tester, c, size: const Size(320, 640));
    await tester.ensureVisible(find.text('Custom'));
    await tester.pump();

    await tester.tap(find.text('Custom'));
    await tester.pumpAndSettle();
    final fields = tester
        .widgetList<fm.TextField>(find.byType(fm.TextField))
        .toList();
    final hexIndex = fields.indexWhere(
      (f) => f.controller?.text.startsWith('#') ?? false,
    );
    await tester.enterText(find.byType(fm.TextField).at(hexIndex), '#00AA88');
    await tester.pump();
    await tester.tap(find.text('Use this colour'));
    await tester.pumpAndSettle();
    await tester.pump();

    expect(c.read(uiSettingsProvider).appearanceCustomColor, 0xFF00AA88);
    expect(tester.takeException(), isNull);
  });

  testWidgets('reopening restores the pick after switching to a preset', (
    tester,
  ) async {
    final c = ProviderContainer();
    addTearDown(c.dispose);
    await _pumpSettings(tester, c);

    await tester.tap(find.text('Custom'));
    await tester.pumpAndSettle();
    var fields = tester
        .widgetList<fm.TextField>(find.byType(fm.TextField))
        .toList();
    var hexIndex = fields.indexWhere(
      (f) => f.controller?.text.startsWith('#') ?? false,
    );
    await tester.enterText(find.byType(fm.TextField).at(hexIndex), '#AA33CC');
    await tester.pump();
    await tester.tap(find.text('Use this colour'));
    await tester.pumpAndSettle();
    await tester.pump();

    // Switching to a preset must not erase the remembered colour.
    await tester.tap(find.text('Neon'));
    await tester.pumpAndSettle();
    expect(c.read(uiSettingsProvider).appearanceAccent, 'neon');

    await tester.tap(find.text('Custom'));
    await tester.pumpAndSettle();
    fields = tester
        .widgetList<fm.TextField>(find.byType(fm.TextField))
        .toList();
    hexIndex = fields.indexWhere(
      (f) => f.controller?.text.startsWith('#') ?? false,
    );
    expect(fields[hexIndex].controller?.text, '#AA33CC');
    expect(tester.takeException(), isNull);
  });
}
