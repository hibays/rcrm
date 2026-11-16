// test/media_item_menu_test.dart
// The item menu: which rows it offers, that a choice comes back, and that it
// opens where the pointer was — downward when there is room, upward when there
// is not.
//
// The panel itself is the shared menu (its geometry is pinned in
// `smart_popup_menu_test.dart`); what this file owns is the ITEM menu's
// contract: the rows depend on what the item is, and "Show in folder" exists only
// where the caller can really reveal one.

import 'package:flutter/services.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/widgets/media_item_menu.dart';
import 'package:rcrm_gui/widgets/smart_popup_menu.dart';

MediaItem _item({bool video = true}) => MediaItem(
  name: video ? 'clip.mp4' : 'photo.jpg',
  path: video ? '/Videos/clip.mp4' : '/Photos/photo.jpg',
  url:
      'http://127.0.0.1:8080${video ? '/Videos/clip.mp4' : '/Photos/photo.jpg'}',
  type: video ? MediaType.video : MediaType.image,
  size: 1024,
);

Future<void> _pump(
  WidgetTester tester, {
  required Offset at,
  bool video = true,
  VoidCallback? onOpen,
  VoidCallback? onReveal,
}) async {
  // The default 800x600 surface is used on purpose: `setSurfaceSize` changes the
  // render view without changing the MediaQuery the dialog overlay reads, so an
  // upward menu would be measured against one height and positioned against
  // another. The default surface keeps the two the same, which is the real
  // app's condition.
  await tester.pumpWidget(
    MaterialApp(
      theme: RCrmTheme.dark,
      navigatorObservers: [FlutterSmartDialog.observer],
      builder: FlutterSmartDialog.init(),
      home: Scaffold(
        body: Builder(
          builder: (context) => Center(
            child: ElevatedButton(
              onPressed: () => showMediaItemMenu(
                context: context,
                item: _item(video: video),
                at: at,
                isVideo: video,
                onOpen: onOpen ?? () {},
                onReveal: onReveal,
              ),
              child: const Text('ask'),
            ),
          ),
        ),
      ),
    ),
  );
  await tester.tap(find.text('ask'));
  await tester.pumpAndSettle();
}

void main() {
  // What `app.dart` does once at startup: menus align to the target's own left
  // edge. The tests below assert vertical placement only, but the menu should be
  // measured under the same configuration the app runs.
  setUp(() {
    SmartDialog.config.attach = SmartConfigAttach(
      attachAlignmentType: SmartAttachAlignmentType.inside,
    );
  });

  testWidgets('a video offers play, details, reveal and the two copies', (
    tester,
  ) async {
    await _pump(tester, at: const Offset(300, 200), onReveal: () {});

    expect(find.text('Play'), findsOneWidget);
    expect(find.text('Details'), findsOneWidget);
    expect(find.text('Show in folder'), findsOneWidget);
    expect(find.text('Copy name'), findsOneWidget);
    expect(find.text('Copy path'), findsOneWidget);
  });

  testWidgets('an image opens rather than plays, and hides reveal when it '
      'cannot happen', (tester) async {
    await _pump(tester, at: const Offset(300, 200), video: false);

    expect(find.text('Open'), findsOneWidget);
    expect(find.text('Play'), findsNothing);
    expect(find.text('Details'), findsOneWidget);
    expect(
      find.text('Show in folder'),
      findsNothing,
      reason: 'the photo tab has no free folder view to reveal into',
    );
  });

  testWidgets('a choice is handed back as the action', (tester) async {
    var opened = 0;
    await _pump(
      tester,
      at: const Offset(300, 200),
      onOpen: () => opened++,
    );

    await tester.tap(find.text('Play'));
    await tester.pumpAndSettle();
    expect(opened, 1);
    expect(find.text('Copy name'), findsNothing, reason: 'the menu is gone');
  });

  testWidgets('opens downward when there is room below the pointer', (
    tester,
  ) async {
    await _pump(tester, at: const Offset(300, 100), onReveal: () {});

    final rows = find.byType(SmartPopupMenuItem<MediaItemMenuAction>);
    expect(rows, findsNWidgets(5));
    final first = tester.getRect(rows.first);
    expect(
      first.top,
      closeTo(108, 1),
      reason: "the panel's top-left starts at the pointer, and its own 8dp of "
          'menu padding is the first row',
    );
  });

  testWidgets('flips upward when the pointer is near the bottom', (
    tester,
  ) async {
    await _pump(tester, at: const Offset(300, 500), onReveal: () {});

    final rows = find.byType(SmartPopupMenuItem<MediaItemMenuAction>);
    expect(rows, findsNWidgets(5));
    final last = tester.getRect(rows.last);
    expect(
      last.bottom,
      closeTo(492, 1),
      reason: "the panel's bottom-left ends at the pointer, so the menu stays "
          'on screen above it (minus its own 8dp of menu padding)',
    );
  });

  testWidgets('Copy name puts the file name on the clipboard', (tester) async {
    final calls = <MethodCall>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        calls.add(call);
        return null;
      },
    );
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      ),
    );

    await _pump(tester, at: const Offset(300, 200), onReveal: () {});
    await tester.tap(find.text('Copy name'));
    await tester.pumpAndSettle();

    final copies = calls.where((c) => c.method == 'Clipboard.setData').toList();
    expect(copies, isNotEmpty);
    expect((copies.last.arguments as Map)['text'], 'clip.mp4');

    // The desktop confirmation is a notify with its own dismissal timer; run it
    // out so the test ends with no pending surface.
    await tester.pump(const Duration(seconds: 4));
    await tester.pumpAndSettle();
  });
}
