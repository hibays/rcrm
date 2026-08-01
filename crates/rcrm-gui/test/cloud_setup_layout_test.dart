// Layout regression: the cloud setup card must not overflow on narrow
// screens (the HTTPS/HTTP segmented button used to overflow the card on
// phones). Any RenderFlex overflow surfaces as a FlutterError and fails the
// test.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/screens/cloud_setup_screen.dart';

void main() {
  testWidgets('cloud setup card fits a 320dp phone width', (tester) async {
    SharedPreferences.setMockInitialValues({});
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      const ProviderScope(child: MaterialApp(home: CloudSetupScreen())),
    );
    await tester.pump();

    expect(
      tester.takeException(),
      isNull,
      reason: 'no overflow at 320dp width',
    );
    expect(find.text('HTTPS'), findsOneWidget);
    expect(find.text('HTTP'), findsOneWidget);
  });

  testWidgets('cloud setup card fits a 360dp phone width with large text', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    tester.view.physicalSize = const Size(360, 800);
    tester.view.devicePixelRatio = 1.0;
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.view.reset);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);

    await tester.pumpWidget(
      const ProviderScope(child: MaterialApp(home: CloudSetupScreen())),
    );
    await tester.pump();

    expect(
      tester.takeException(),
      isNull,
      reason: 'no overflow with 1.3x text scale',
    );
  });
}
