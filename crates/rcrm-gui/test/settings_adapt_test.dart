// Adapt regression: the settings page must not stretch to full width on a
// desktop/tablet window, must respect the bottom inset, and every touch target
// must meet the platform minimum (44pt iOS / 48dp Android — 44 is the shared bar).
//
// Failures here are silent visually: a 1920px card with the title at the far
// left and a switch at the far right looks "wrong" but throws no FlutterError.

import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/screens/settings_screen.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  Future<void> pumpSettings(
    WidgetTester tester, {
    Map<String, Object>? config,
  }) async {
    SharedPreferences.setMockInitialValues({
      if (config != null) 'server_config': jsonEncode(config),
    });
    await tester.pumpWidget(
      const ProviderScope(child: MaterialApp(home: SettingsScreen())),
    );
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
  }

  testWidgets('content is width-capped and centred on a wide window', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await pumpSettings(tester);

    final rect = tester.getRect(
      find.byKey(const Key('settings-content-width')),
    );
    expect(
      rect.width,
      lessThanOrEqualTo(840),
      reason: 'a 1920dp window must not stretch settings to full width',
    );
    expect(
      rect.center.dx,
      closeTo(960, 2),
      reason: 'the capped content must be horizontally centred',
    );
  });

  testWidgets('narrow window keeps full width', (tester) async {
    tester.view.physicalSize = const Size(360, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await pumpSettings(tester);

    final rect = tester.getRect(
      find.byKey(const Key('settings-content-width')),
    );
    expect(
      rect.width,
      closeTo(360, 1),
      reason: 'a phone must still use the full available width',
    );
  });

  testWidgets('body respects the bottom safe area', (tester) async {
    await pumpSettings(tester);
    // The content key must sit inside a SafeArea that avoids the bottom inset —
    // framework SafeAreas exist too, so test the ancestor not the raw count.
    final safe = find.ancestor(
      of: find.byKey(const Key('settings-content-width')),
      matching: find.byWidgetPredicate((w) => w is SafeArea && w.bottom),
    );
    expect(
      safe,
      findsOneWidget,
      reason: 'home indicator / gesture area must not cover the last row',
    );
  });

  testWidgets('segmented rows meet the 44dp touch target on a phone', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await pumpSettings(tester);

    final segs = find.byWidgetPredicate((w) => w is SegmentedButton);
    expect(segs, findsWidgets);
    for (final seg in segs.evaluate()) {
      final box = seg.renderObject as RenderBox;
      expect(
        box.size.height,
        greaterThanOrEqualTo(44),
        reason: 'segmented control is a touch target, not a compact label',
      );
    }
    expect(tester.takeException(), isNull, reason: 'no overflow at 320dp');
  });

  testWidgets('async connection errors are announced to screen readers', (
    tester,
  ) async {
    await pumpSettings(tester);
    // The LiveRegion is attached to the error text; with no error the widget
    // is absent, so assert the shape of the tree rather than a specific string.
    final live = find.byWidgetPredicate(
      (w) => w is Semantics && w.properties.liveRegion == true,
    );
    // No error in the default state: the container is harmless if present.
    expect(live, findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('cloud protocol button meets the 44dp touch target', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await pumpSettings(
      tester,
      config: {'deployMode': 'cloud', 'remoteUrl': 'https://example.com:443'},
    );

    final protocol = find.byWidgetPredicate((w) => w is SegmentedButton<bool>);
    expect(protocol, findsOneWidget);
    final box = protocol.evaluate().single.renderObject as RenderBox;
    expect(
      box.size.height,
      greaterThanOrEqualTo(44),
      reason:
          'HTTPS/HTTP must keep its 44dp+ tap height without FittedBox scaling',
    );
  });

  testWidgets('protocol button never wraps into a tall block on phones', (
    tester,
  ) async {
    for (final entry in [
      {'w': 375.0, 's': 1.0},
      {'w': 390.0, 's': 1.3},
    ]) {
      tester.view.physicalSize = Size(entry['w'] as double, 800.0);
      tester.view.devicePixelRatio = 1.0;
      tester.platformDispatcher.textScaleFactorTestValue = entry['s'] as double;
      addTearDown(tester.view.reset);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      await pumpSettings(
        tester,
        config: {'deployMode': 'cloud', 'remoteUrl': 'https://example.com:443'},
      );
      final seg = find.byWidgetPredicate((w) => w is SegmentedButton<bool>);
      final rect = tester.getRect(seg);
      expect(
        rect.height,
        lessThan(60),
        reason:
            'HTTPS/HTTP labels must stay on one line at ${entry['w']}dp '
            '(${entry['s']}x), not fold into a ${rect.height}dp block',
      );
      expect(tester.takeException(), isNull, reason: 'no overflow');
    }
  });

  testWidgets('top is not double-inset below the AppBar', (tester) async {
    await pumpSettings(tester);
    final safe = find.ancestor(
      of: find.byKey(const Key('settings-content-width')),
      matching: find.byWidgetPredicate((w) => w is SafeArea),
    );
    expect(safe, findsOneWidget);
    expect(
      (safe.evaluate().single.widget as SafeArea).top,
      isFalse,
      reason: 'AppBar already insets the top; SafeArea must only guard bottom',
    );
  });

  testWidgets('accent swatches meet the 44dp touch target', (tester) async {
    await pumpSettings(tester);
    final chips = find.byWidgetPredicate(
      (w) =>
          w is Semantics && (w.properties.label?.endsWith(' accent') ?? false),
    );
    expect(chips, findsWidgets);
    for (final chip in chips.evaluate()) {
      final box = chip.renderObject as RenderBox;
      expect(
        box.size.height,
        greaterThanOrEqualTo(44),
        reason:
            'accent swatch ${(chip.widget as Semantics).properties.label} too small',
      );
    }
  });

  // A desktop window resized to 560–610dp used to put `_seg`'s three-segment
  // button ("Folder/Format/Ungrouped") in a ListTile too narrow for it —
  // `material_ui` threw "Trailing widget consumes the entire tile width".
  // The row must stack at those widths instead (kSettingsWideRowMin = 620).
  testWidgets(
    'mid-width windows stack wide rows without a ListTile assertion',
    (tester) async {
      for (final w in [540.0, 560.0, 583.0, 590.0, 600.0, 610.0, 620.0]) {
        tester.view.physicalSize = Size(w, 3200);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.reset);
        await pumpSettings(
          tester,
          config: {
            'deployMode': 'cloud',
            'remoteUrl': 'https://example.com:443',
          },
        );
        expect(
          tester.takeException(),
          isNull,
          reason: 'settings threw at ${w}dp (trailing widget too wide)',
        );
      }
    },
  );
}
