// A visible "copied"/"saved" toast must not eat the first tap on a dialog
// button. flutter_smart_dialog checks its notify queue before its dialog
// queue, so an untagged `dismiss` closed the toast instead of the dialog and
// the action never ran. Worst case: the folder editor's Done/back both became
// dead while `_finishing` latched true. Every dialog button now dismisses with
// `status: SmartStatus.dialog`, which routes straight to the dialog queue.

import 'package:material_ui/material_ui.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('a dialog button acts on the first tap even with a notify up', (
    tester,
  ) async {
    String? choice;
    await tester.binding.setSurfaceSize(const Size(800, 600));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      MaterialApp(
        navigatorObservers: [FlutterSmartDialog.observer],
        builder: FlutterSmartDialog.init(),
        home: Scaffold(
          body: Center(
            child: ElevatedButton(
              onPressed: () async {
                choice = await SmartDialog.show<String>(
                  builder: (_) => AlertDialog(
                    actions: [
                      TextButton(
                        onPressed: () => SmartDialog.dismiss(
                          status: SmartStatus.dialog,
                          result: 'done',
                        ),
                        child: const Text('Done'),
                      ),
                    ],
                  ),
                );
              },
              child: const Text('open'),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();

    SmartDialog.showNotify(msg: 'Saved', notifyType: NotifyType.success);
    await tester.pumpAndSettle();

    await tester.tap(find.text('Done'));
    await tester.pumpAndSettle();
    expect(choice, 'done', reason: 'first tap must run the dialog action');

    // Drain the notify's own auto-dismiss timer before the tree is torn down.
    await tester.pump(const Duration(seconds: 3));
    await tester.pumpAndSettle();
  });
}
