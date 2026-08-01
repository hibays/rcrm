import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:rcrm_gui/app.dart';

void main() {
  testWidgets('App renders without crashing', (WidgetTester tester) async {
    // The app loads the deploy mode from shared_preferences on startup.
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(const ProviderScope(child: RcrmApp()));
    // Let the async deploy-mode load settle and rebuild the initial screen.
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    // Initial route is /setup → LibrarySetupScreen
    expect(find.byType(MaterialApp), findsOneWidget);
    expect(find.text('RCrm Media Library'), findsOneWidget);
  });
}
