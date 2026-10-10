// test/viewer_gesture_test.dart
// The REAL image viewer's two horizontal/vertical gestures must be mutually
// exclusive: whichever axis a gesture commits to owns it to the end, so a
// pull-to-dismiss that drifts sideways never turns the page, and a sideways
// page switch that dives down never pulls the photo (or dismisses) either.
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
import 'package:rcrm_gui/widgets/viewer_zoom.dart';

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

/// Vertical travel the page really paints, read off the live `Transform`s: the
/// pull's own translate — it wraps the whole page, so it is an ANCESTOR of the
/// viewport, not a descendant — plus the pan inside the zoom viewport. Zero at
/// rest; non-zero means the pull moved the photo.
double paintedDy(WidgetTester tester) {
  final viewport = find.byType(ZoomableViewport).first;
  final pulled = tester
      .widgetList<Transform>(
        find.ancestor(of: viewport, matching: find.byType(Transform)),
      )
      .fold<double>(0, (dy, t) => dy + t.transform.getTranslation().y);
  final panned = tester
      .widgetList<Transform>(
        find.descendant(of: viewport, matching: find.byType(Transform)),
      )
      .first
      .transform
      .getTranslation()
      .y;
  return pulled + panned;
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
    expect(paintedDy(tester), 0, reason: 'the photo starts at rest');

    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 8; i++) {
      await gesture.moveBy(const Offset(-50, 0));
      await tester.pump(const Duration(milliseconds: 16));
      // The page owns this gesture, so the pull contributes nothing *while*
      // the drag runs — not merely nothing once it is over.
      expect(
        paintedDy(tester),
        0,
        reason: 'a sideways swipe must never pull the photo down',
      );
    }
    await gesture.up();
    await tester.pumpAndSettle();

    expect(find.text('2 / 3'), findsOneWidget);
  });

  testWidgets('a diagonal drag that leads sideways never pulls', (tester) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));
    expect(paintedDy(tester), 0, reason: 'the photo starts at rest');

    // Sideways clearly dominates: 320px across against 40px down, the shape of
    // the bug report (the page turned AND the photo slid down with it). The
    // sideways travel has to clear the pager's quarter-page snap threshold
    // (200px here) on distance alone — the harness's events carry no timestamps,
    // so the release velocity that could also flip a page is 0 in a test.
    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 8; i++) {
      await gesture.moveBy(const Offset(-40, 5));
      await tester.pump(const Duration(milliseconds: 16));
      expect(
        paintedDy(tester),
        0,
        reason: 'once the page owns the gesture the pull must do nothing',
      );
    }
    await gesture.up();
    await tester.pumpAndSettle();

    // The page still switched, and the release closed nothing.
    expect(find.text('2 / 3'), findsOneWidget);
    expect(
      find.byType(ImageViewerScreen),
      findsOneWidget,
      reason: 'the page switch owns the gesture, so letting go must not dismiss',
    );
  });

  testWidgets('a diagonal drag that leads downwards still pulls', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // 40px across, 64px down: the pull dominates, so the axis lock must hand
    // it the gesture. 64px stays under the 72px dismissal threshold at this
    // surface height, so the viewer is still there to be inspected.
    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 8; i++) {
      await gesture.moveBy(const Offset(5, 8));
      await tester.pump(const Duration(milliseconds: 16));
    }
    expect(
      paintedDy(tester),
      greaterThan(0),
      reason: 'a downward-leading diagonal is still a pull',
    );
    await gesture.up();
    await tester.pumpAndSettle();

    expect(find.byType(ImageViewerScreen), findsOneWidget);
    expect(find.text('1 / 3'), findsOneWidget);
    expect(find.text('2 / 3'), findsNothing);
  });

  testWidgets('a sideways swipe that dives down never dismisses', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // Sideways first — the page is decided within the first move — then the
    // finger dives far enough down to have pulled the viewer away on its own.
    // The page switch owns the whole gesture, so the dive must contribute
    // nothing: this is the bug report's gesture (swipe across, finger sinking
    // as it goes), where the pull used to take the gesture over mid-swipe.
    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 8; i++) {
      await gesture.moveBy(const Offset(-40, 0));
      await tester.pump(const Duration(milliseconds: 16));
    }
    for (var i = 0; i < 12; i++) {
      await gesture.moveBy(const Offset(0, 20));
      await tester.pump(const Duration(milliseconds: 16));
      expect(
        paintedDy(tester),
        0,
        reason: 'a lane change after the page switch is not a pull',
      );
    }
    await gesture.up();
    await tester.pumpAndSettle();

    expect(
      find.byType(ImageViewerScreen),
      findsOneWidget,
      reason: 'the page switch owns the gesture, so the dive must not dismiss',
    );
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

  testWidgets('a zoomed photo cannot be pulled away', (tester) async {
    // The way out of a zoom is zooming out. While the picture is enlarged, a
    // downward drag pans it (and does nothing once it is already at the top
    // edge) — it must never yank the whole viewer off the screen, which is what
    // pulling a zoomed photo used to do at the top edge.
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // Live scale of the transform the viewport is really painting, so this test
    // cannot pass by failing to zoom in the first place.
    double paintedScale() {
      final transforms = tester.widgetList<Transform>(
        find.descendant(
          of: find.byType(ZoomableViewport),
          matching: find.byType(Transform),
        ),
      );
      return transforms.first.transform.getMaxScaleOnAxis();
    }

    // Zoom in with a pinch, exactly as a user would.
    final p1 = await tester.startGesture(center - const Offset(40, 0));
    final p2 = await tester.startGesture(center + const Offset(40, 0));
    for (var i = 0; i < 8; i++) {
      await p1.moveBy(const Offset(-8, 0));
      await p2.moveBy(const Offset(8, 0));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await p1.up();
    await p2.up();
    await tester.pumpAndSettle();
    expect(
      paintedScale(),
      greaterThan(1.2),
      reason: 'the pinch must really have zoomed before the pull is tested',
    );

    // Pan AWAY from the top edge before pulling. At the very top the translation
    // clamp (dy <= 0, see ViewerZoom.clampTranslation) makes a downward drag a
    // no-op in BOTH the old and the new code, so that state cannot tell them
    // apart. Scrolled down the picture, the old code treated the pull as a
    // dismissal — which is exactly the behaviour this test is about.
    final pan = await tester.startGesture(center);
    for (var i = 0; i < 6; i++) {
      await pan.moveBy(const Offset(0, -20));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await pan.up();
    await tester.pumpAndSettle();
    final before = paintedDy(tester);
    expect(
      before,
      lessThan(-0.5),
      reason: 'the picture must really be scrolled off its top edge first',
    );

    // Now the same downward drag that closes the viewer at 1x.
    final pull = await tester.startGesture(center);
    for (var i = 0; i < 12; i++) {
      await pull.moveBy(const Offset(0, 20));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await pull.up();
    await tester.pumpAndSettle();

    expect(
      find.byType(ImageViewerScreen),
      findsOneWidget,
      reason: 'a zoomed picture must survive a downward drag anywhere, '
          'not only at its top edge',
    );
    expect(
      paintedDy(tester),
      greaterThan(before + 5),
      reason: 'the drag must PAN the picture; being ignored is the old '
          'behaviour this test exists to rule out',
    );
    expect(find.text('1 / 3'), findsOneWidget);
  });
}
