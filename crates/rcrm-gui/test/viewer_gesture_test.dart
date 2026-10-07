// test/viewer_gesture_test.dart
// The REAL image viewer's two horizontal/vertical gestures must be mutually
// exclusive: a pull-to-dismiss owns the gesture it started, and dragging
// sideways afterwards must not also slide the pager to another picture.
//
// Mounts the actual ImageViewerScreen (not a harness replica) and reads the
// position counter in its chrome, which is the visible symptom: pull the photo
// down, drift sideways, let go — the viewer either springs back on picture 1
// or it has quietly turned the page.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/screens/image_viewer_screen.dart';

MediaItem _image(String name) => MediaItem(
  name: name,
  path: '/albums/$name',
  url: 'http://127.0.0.1:1/albums/$name',
  type: MediaType.image,
  size: 2048,
  modified: DateTime(2026, 9, 30, 2, 24),
  albumName: 'albums',
);

final _items = [_image('a.jpg'), _image('b.jpg'), _image('c.jpg')];

Future<void> _openViewer(WidgetTester tester) async {
  await tester.binding.setSurfaceSize(const Size(800, 600));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      theme: RCrmTheme.dark,
      home: Builder(
        builder: (context) => Scaffold(
          body: Center(
            child: ElevatedButton(
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => ImageViewerScreen(items: _items),
                ),
              ),
              child: const Text('open'),
            ),
          ),
        ),
      ),
    ),
  );
  await tester.tap(find.text('open'));
  await tester.pumpAndSettle();
  expect(find.text('1 / 3'), findsOneWidget);
}

void main() {
  testWidgets('a pull that drifts sideways never turns the page', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // Engage the pull vertically first (8px of downward travel is enough),
    // then drift far enough sideways that the pager would have flipped.
    final gesture = await tester.startGesture(center);
    await gesture.moveBy(const Offset(0, 20));
    await tester.pump();
    for (var i = 0; i < 8; i++) {
      await gesture.moveBy(const Offset(-50, 5));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await gesture.up();
    await tester.pumpAndSettle();

    // The short pull springs back, and the picture is still the first one.
    expect(find.byType(ImageViewerScreen), findsOneWidget);
    expect(find.text('1 / 3'), findsOneWidget);
    expect(find.text('2 / 3'), findsNothing);
  });

  testWidgets('a pure sideways drag still turns the page', (tester) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 8; i++) {
      await gesture.moveBy(const Offset(-50, 0));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await gesture.up();
    await tester.pumpAndSettle();

    expect(find.text('2 / 3'), findsOneWidget);
  });

  testWidgets('a pull past the threshold closes the viewer', (tester) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 12; i++) {
      await gesture.moveBy(const Offset(0, 20));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await gesture.up();
    await tester.pumpAndSettle();

    expect(find.byType(ImageViewerScreen), findsNothing);
  });
}
