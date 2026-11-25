// The Managed Directories dialog auto-saves every edit. System back goes
// through SmartDialog's binding-level pop monitor (there is no ModalRoute in
// the overlay), wired via `onBack` to the editor's _finish. Back must drain the
// pending auto-save and dismiss WITH the final list — not dismiss silently and
// let the caller re-read a config whose last write has not landed.

import 'dart:async';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/screens/settings_screen.dart';

void main() {
  testWidgets('system back waits for the pending save and returns the list', (
    tester,
  ) async {
    final writes = <List<String>>[];
    final gate = Completer<void>();
    Future<void> Function()? finish;
    List<String>? result;

    await tester.pumpWidget(
      MaterialApp(
        // Mirror the app: .init() installs the binding-level pop monitor that
        // routes system back to a dialog's onBack (the bare constructor does
        // not), and the overlay needs a Directionality ancestor.
        navigatorObservers: [FlutterSmartDialog.observer],
        builder: FlutterSmartDialog.init(),
        home: Scaffold(
          body: Builder(
            builder: (ctx) => TextButton(
              child: const Text('open'),
              onPressed: () async {
                result = await SmartDialog.show<List<String>>(
                              clickMaskDismiss: false,
                  onBack: () async {
                    await finish?.call();
                    return true;
                  },
                  builder: (_) => DirEditor(
                    initialDirs: const ['/a', '/b'],
                    registerFinish: (f) => finish = f,
                    onChanged: (dirs) async {
                      await gate.future; // slow write
                      writes.add(dirs);
                    },
                  ),
                );
              },
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
    expect(find.text('Managed Directories'), findsOneWidget);
    expect(finish, isNotNull, reason: 'editor registers _finish for onBack');

    // Produce a pending auto-save without touching the filesystem: removing an
    // initial directory calls _commit(), which queues onChanged behind a gate.
    await tester.tap(find.byIcon(Icons.close).first);
    await tester.pump();
    expect(writes, isEmpty, reason: 'the queued write is still gated');

    // Simulate the binding-level back: onBack awaits _finish, which drains
    // _writes. The write is gated, so the dialog must not settle yet.
    final backDone = tester.binding.handlePopRoute();
    await tester.pump();
    expect(writes, isEmpty, reason: 'write is still gated');
    expect(result, isNull, reason: 'dialog must not settle before the write');

    gate.complete();
    await backDone;
    await tester.pumpAndSettle();
    expect(writes.length, 1, reason: 'pending write landed before dismiss');
    expect(find.text('Managed Directories'), findsNothing);
    expect(result, ['/b'], reason: 'back dismisses WITH the final list');
  });
}
