// Layout regression: the settings screen must not overflow on narrow
// screens, in both Local and Cloud deploy modes (the Cloud protocol row is a
// bare Row + Spacer + SegmentedButton). Any RenderFlex overflow surfaces as a
// FlutterError and fails the test.

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/screens/settings_screen.dart';

void main() {
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
    await tester.pump(); // settle async deploy-mode load
    await tester.pump(const Duration(milliseconds: 50));
  }

  void expectNoOverflow(WidgetTester tester, String reason) {
    expect(tester.takeException(), isNull, reason: reason);
  }

  /// The Cloud protocol HTTPS/HTTP button must sit flush against the right
  /// edge of the card (the user-facing requirement), not in the middle.
  void expectProtocolButtonRightAligned(WidgetTester tester) {
    final btn = tester.widget<FittedBox>(
      find.ancestor(of: find.text('HTTPS'), matching: find.byType(FittedBox)),
    );
    expect(btn.alignment, Alignment.centerRight, reason: 'button alignment');
    // Measure the button itself (find.text('HTTPS') is just the first
    // segment label and sits mid-button).
    final segRect = tester.getRect(find.byType(SegmentedButton<bool>).first);
    final screenWidth =
        tester.view.physicalSize.width / tester.view.devicePixelRatio;
    // ListView has 16px horizontal padding; the button must hug that edge.
    expect(
      segRect.right,
      closeTo(screenWidth - 16, 24),
      reason: 'HTTPS/HTTP button must hug the card right edge',
    );
  }

  testWidgets('settings Local mode fits a 320dp phone width', (tester) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await pumpSettings(tester);

    expectNoOverflow(tester, 'Local mode at 320dp');
    expect(find.text('Managed Directories'), findsOneWidget);
  });

  testWidgets('settings Local mode fits 360dp with 1.3x text scale', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(360, 800);
    tester.view.devicePixelRatio = 1.0;
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.view.reset);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);

    await pumpSettings(tester);

    expectNoOverflow(tester, 'Local mode at 360dp 1.3x');
  });

  testWidgets('settings Cloud mode fits a 320dp phone width', (tester) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await pumpSettings(
      tester,
      config: {'deployMode': 'cloud', 'remoteUrl': 'https://example.com:443'},
    );

    expectNoOverflow(tester, 'Cloud mode at 320dp');
    expect(find.text('HTTPS'), findsOneWidget);
    expect(find.text('HTTP'), findsOneWidget);
    expect(find.text('Connect'), findsOneWidget);
    expectProtocolButtonRightAligned(tester);
  });

  testWidgets('settings Cloud mode fits 360dp with 1.3x text scale', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(360, 800);
    tester.view.devicePixelRatio = 1.0;
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.view.reset);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);

    await pumpSettings(
      tester,
      config: {'deployMode': 'cloud', 'remoteUrl': 'https://example.com:443'},
    );

    expectNoOverflow(tester, 'Cloud mode at 360dp 1.3x');
    expectProtocolButtonRightAligned(tester);
  });

  testWidgets(
    'settings Cloud mode right-aligns protocol button on wide screens',
    (tester) async {
      // Desktop-width window: the old loose-Flexible layout parked the button
      // mid-card (Spacer/Flexible split the leftover space and FittedBox stayed
      // at the left of its slot). Must be flush right at any width.
      tester.view.physicalSize = const Size(800, 600);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await pumpSettings(
        tester,
        config: {'deployMode': 'cloud', 'remoteUrl': 'https://example.com:443'},
      );

      expectNoOverflow(tester, 'Cloud mode at 800dp');
      expectProtocolButtonRightAligned(tester);
    },
  );
}
