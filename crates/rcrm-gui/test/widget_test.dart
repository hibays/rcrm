import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/app.dart';

void main() {
  testWidgets('App renders without crashing', (WidgetTester tester) async {
    await tester.pumpWidget(const ProviderScope(child: RcrmApp()));
    await tester.pump();
    // Initial route is /setup → LibrarySetupScreen
    expect(find.byType(MaterialApp), findsOneWidget);
    expect(find.text('RCrm Media Library'), findsOneWidget);
  });
}
