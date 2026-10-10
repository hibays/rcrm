// test/viewer_zoom_test.dart
// The image viewer's zoom geometry, and the two failures it exists to prevent:
//   * the letterbox must never be part of the transform (zooming a photo must
//     not zoom the black around it), and
//   * no pan position may reveal empty space — the picture either covers the
//     viewport or sits centred in it. Dragging must never produce a black
//     screen.
// Plus the pull-to-dismiss rule: distance AND velocity, because distance alone
// made short, fast flicks bounce back.

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/widgets/viewer_zoom.dart';

const _viewport = Size(400, 600);
const _landscape = Size(1440, 1000); // wider than the viewport → bars top/bottom
const _portrait = Size(1000, 2000); // taller → bars left/right

/// The photo's on-screen rect for [m].
Rect _shown(Matrix4 m, Size content, Size viewport) {
  final fitted = ViewerZoom.fitContain(viewport, content);
  final scale = ViewerZoom.scaleOf(m);
  final t = ViewerZoom.translationOf(m);
  return Rect.fromLTWH(
    t.dx,
    t.dy,
    fitted.width * scale,
    fitted.height * scale,
  );
}

/// Asserts the invariant: every axis is either covered edge-to-edge or
/// centred. Anything else is a black gap the user can see.
void _expectNoGap(Rect shown, Size viewport) {
  void axis(double shownStart, double shownSize, double viewportSize) {
    if (shownSize >= viewportSize - 0.01) {
      expect(shownStart, lessThanOrEqualTo(0.01));
      expect(shownStart + shownSize, greaterThanOrEqualTo(viewportSize - 0.01));
    } else {
      expect(shownStart, closeTo((viewportSize - shownSize) / 2, 0.01));
    }
  }

  axis(shown.left, shown.width, viewport.width);
  axis(shown.top, shown.height, viewport.height);
}

void main() {
  group('fitContain', () {
    test('fits a wide photo to the viewport width', () {
      final fitted = ViewerZoom.fitContain(_viewport, _landscape);
      expect(fitted.width, closeTo(400, 0.01));
      expect(fitted.height, closeTo(277.78, 0.01));
    });

    test('fits a tall photo to the viewport height', () {
      final fitted = ViewerZoom.fitContain(_viewport, _portrait);
      expect(fitted.height, closeTo(600, 0.01));
      expect(fitted.width, closeTo(300, 0.01));
    });

    test('unknown content falls back to the viewport', () {
      expect(ViewerZoom.fitContain(_viewport, Size.zero), _viewport);
    });
  });

  group('matrix clamping', () {
    test('no scale/translation combination can open a gap', () {
      for (final content in [_landscape, _portrait, const Size(400, 600)]) {
        for (var s = 1.0; s <= ViewerZoom.maxScale; s += 0.25) {
          for (var t = -3000.0; t <= 3000.0; t += 137) {
            for (final translation in [Offset(t, t), Offset(-t, t), Offset(t, -t)]) {
              final m = ViewerZoom.matrixFor(
                viewport: _viewport,
                content: content,
                scale: s,
                translation: translation,
              );
              _expectNoGap(_shown(m, content, _viewport), _viewport);
            }
          }
        }
      }
    });

    test('a photo smaller than the viewport stays centred', () {
      final m = ViewerZoom.matrixFor(
        viewport: _viewport,
        content: _landscape,
        scale: 1,
        translation: const Offset(9999, -9999),
      );
      final shown = _shown(m, _landscape, _viewport);
      expect(shown.center.dx, closeTo(200, 0.01));
      expect(shown.center.dy, closeTo(300, 0.01));
    });
  });

  group('zoomAbout', () {
    test('keeps the content point under the focal point', () {
      final start = ViewerZoom.identity(
        viewport: _viewport,
        content: _landscape,
      );
      // Inside the photo, away from the edges, so the result is not clamped.
      const focal = Offset(120, 300);
      final zoomed = ViewerZoom.zoomAbout(
        current: start,
        viewport: _viewport,
        content: _landscape,
        factor: 3,
        focalPoint: focal,
      );
      // Content point under the focal point before…
      final t0 = ViewerZoom.translationOf(start);
      final point = (focal - t0) / ViewerZoom.scaleOf(start);
      // …must still be under it after.
      final t1 = ViewerZoom.translationOf(zoomed);
      final moved = t1 + point * ViewerZoom.scaleOf(zoomed);
      expect(moved.dx, closeTo(focal.dx, 0.01));
      expect(moved.dy, closeTo(focal.dy, 0.01));
    });

    test('a focal point at the edge is clamped instead of opening a gap', () {
      final zoomed = ViewerZoom.zoomAbout(
        current: ViewerZoom.identity(viewport: _viewport, content: _landscape),
        viewport: _viewport,
        content: _landscape,
        factor: 3,
        focalPoint: const Offset(5, 5),
      );
      _expectNoGap(_shown(zoomed, _landscape, _viewport), _viewport);
    });

    test('never zooms below fit, and recentres on the way out', () {
      var m = ViewerZoom.zoomAbout(
        current: ViewerZoom.identity(viewport: _viewport, content: _landscape),
        viewport: _viewport,
        content: _landscape,
        factor: 4,
        focalPoint: const Offset(10, 10),
      );
      m = ViewerZoom.zoomAbout(
        current: m,
        viewport: _viewport,
        content: _landscape,
        factor: 1 / 50,
      );
      expect(ViewerZoom.scaleOf(m), closeTo(1.0, 0.001));
      _expectNoGap(_shown(m, _landscape, _viewport), _viewport);
    });

    test('caps at maxScale', () {
      final m = ViewerZoom.zoomAbout(
        current: ViewerZoom.identity(viewport: _viewport, content: _landscape),
        viewport: _viewport,
        content: _landscape,
        factor: 100,
      );
      expect(ViewerZoom.scaleOf(m), closeTo(ViewerZoom.maxScale, 0.001));
    });
  });

  group('actual size', () {
    test('a 1440px photo on a 400px viewport is 3.6x', () {
      expect(
        ViewerZoom.actualSizeScale(viewport: _viewport, content: _landscape),
        closeTo(3.6, 0.01),
      );
    });

    test('a photo below screen resolution has nothing to offer', () {
      expect(
        ViewerZoom.actualSizeScale(
          viewport: _viewport,
          content: const Size(200, 150),
        ),
        1.0,
      );
    });
  });

  group('pull to dismiss', () {
    test('progress runs 0 → 1 across the threshold', () {
      final threshold = dismissThreshold(800);
      expect(dismissProgress(0, 800), 0);
      expect(dismissProgress(threshold / 2, 800), closeTo(0.5, 0.01));
      expect(dismissProgress(threshold * 3, 800), 1);
    });

    test('a tall screen does not demand a marathon drag', () {
      expect(dismissThreshold(2400), lessThanOrEqualTo(132));
      expect(dismissThreshold(400), greaterThanOrEqualTo(72));
    });

    test('distance alone closes it', () {
      expect(
        shouldDismissPull(distance: 200, velocity: 0, viewportHeight: 800),
        isTrue,
      );
    });

    test('a short, slow pull springs back', () {
      expect(
        shouldDismissPull(distance: 30, velocity: 120, viewportHeight: 800),
        isFalse,
      );
    });

    test('a quick flick closes even when it travelled little', () {
      expect(
        shouldDismissPull(distance: 40, velocity: 1200, viewportHeight: 800),
        isTrue,
      );
    });

    test('an upward flick never dismisses', () {
      expect(
        shouldDismissPull(distance: 10, velocity: -2000, viewportHeight: 800),
        isFalse,
      );
    });

    test('the photo follows the finger vertically, resists the rest', () {
      expect(pullOffsetDelta(const Offset(100, 100)), const Offset(35, 100));
      expect(pullOffsetDelta(const Offset(-100, -100)), const Offset(-35, -35));
    });
  });

  group('ZoomableViewport', () {
    const childKey = ValueKey('photo');

    Future<ZoomableViewportState> pump(
      WidgetTester tester, {
      required TransformationController controller,
      Size contentSize = _landscape,
      Size viewport = _viewport,
      ValueChanged<Offset>? onTapAt,
    }) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Center(
              child: SizedBox(
                width: viewport.width,
                height: viewport.height,
                child: ZoomableViewport(
                  controller: controller,
                  contentSize: contentSize,
                  onTapAt: onTapAt,
                  child: Container(key: childKey, color: Colors.red),
                ),
              ),
            ),
          ),
        ),
      );
      await tester.pump();
      return tester.state<ZoomableViewportState>(
        find.byType(ZoomableViewport),
      );
    }

    /// The photo's rect relative to the viewport's own top-left (the test
    /// surface centres the viewport, so global rects would be offset).
    Rect shownRect(WidgetTester tester) {
      final origin = tester.getTopLeft(find.byType(ZoomableViewport));
      return tester.getRect(find.byKey(childKey)).shift(-origin);
    }

    testWidgets('at rest the photo is letterboxed and centred', (tester) async {
      final c = TransformationController();
      addTearDown(c.dispose);
      await pump(tester, controller: c);
      final shown = shownRect(tester);
      expect(shown.width, closeTo(400, 0.5));
      expect(shown.height, closeTo(277.8, 0.5));
      expect(shown.center.dx, closeTo(200, 0.5));
      expect(shown.center.dy, closeTo(300, 0.5));
      // …and the widget itself still occupies the whole viewport, so taps and
      // drags land even in the letterbox.
      expect(tester.getRect(find.byType(ZoomableViewport)).size, _viewport);
    });

    testWidgets('zooming in then dragging can never reveal empty space', (
      tester,
    ) async {
      final c = TransformationController();
      addTearDown(c.dispose);
      final state = await pump(tester, controller: c);
      state.zoomBy(3);
      await tester.pump();
      expect(state.scale, closeTo(3, 0.001));
      // Zooming about the middle keeps the photo centred in the taller axis.
      var shown = shownRect(tester);
      expect(shown.center.dx, closeTo(200, 0.5));

      // Drag the photo far beyond its own edges, in both directions.
      await tester.drag(
        find.byType(ZoomableViewport),
        const Offset(-5000, -5000),
      );
      await tester.pump();
      shown = shownRect(tester);
      expect(shown.left, lessThanOrEqualTo(0.5));
      expect(shown.top, lessThanOrEqualTo(0.5));
      expect(shown.right, greaterThanOrEqualTo(399.5));
      expect(shown.bottom, greaterThanOrEqualTo(599.5));

      await tester.drag(
        find.byType(ZoomableViewport),
        const Offset(5000, 5000),
      );
      await tester.pump();
      shown = shownRect(tester);
      expect(shown.left, lessThanOrEqualTo(0.5));
      expect(shown.top, lessThanOrEqualTo(0.5));
      expect(shown.right, greaterThanOrEqualTo(399.5));
      expect(shown.bottom, greaterThanOrEqualTo(599.5));
    });

    testWidgets('a pinch zooms and a pinch back out recentres', (tester) async {
      final c = TransformationController();
      addTearDown(c.dispose);
      final state = await pump(tester, controller: c);
      final center = tester.getCenter(find.byType(ZoomableViewport));
      final g1 = await tester.startGesture(center - const Offset(30, 0));
      final g2 = await tester.startGesture(center + const Offset(30, 0));
      await g1.moveBy(const Offset(-90, 0));
      await g2.moveBy(const Offset(90, 0));
      await tester.pump();
      expect(state.scale, greaterThan(1.2));

      await g1.moveBy(const Offset(120, 0));
      await g2.moveBy(const Offset(-120, 0));
      await tester.pump();
      await g1.up();
      await g2.up();
      await tester.pump();
      expect(state.scale, closeTo(1.0, 0.02));
      _expectNoGap(_shown(c.value, _landscape, _viewport), _viewport);
    });

    testWidgets('the wheel zooms about the cursor', (tester) async {
      final c = TransformationController();
      addTearDown(c.dispose);
      final state = await pump(tester, controller: c);
      final pointer = TestPointer(1, PointerDeviceKind.mouse);
      final at = tester.getTopLeft(find.byType(ZoomableViewport)) +
          const Offset(80, 60);
      pointer.hover(at);
      await tester.sendEventToBinding(pointer.scroll(const Offset(0, -120)));
      await tester.pump();
      expect(state.scale, greaterThan(1.0));
      _expectNoGap(_shown(c.value, _landscape, _viewport), _viewport);
    });

    testWidgets('taps are reported in viewport coordinates', (tester) async {
      final c = TransformationController();
      addTearDown(c.dispose);
      final taps = <Offset>[];
      await pump(tester, controller: c, onTapAt: taps.add);
      await tester.tapAt(
        tester.getTopLeft(find.byType(ZoomableViewport)) + const Offset(30, 40),
      );
      await tester.pump();
      expect(taps, hasLength(1));
      expect(taps.single.dx, closeTo(30, 0.5));
      expect(taps.single.dy, closeTo(40, 0.5));
    });

    testWidgets('1:1 is offered only when there are pixels to spend', (
      tester,
    ) async {
      final c = TransformationController();
      addTearDown(c.dispose);
      final state = await pump(tester, controller: c);
      expect(state.canShowActualSize, isTrue);
      state.zoomToActualSize();
      await tester.pump();
      expect(state.scale, closeTo(3.6, 0.01));
      _expectNoGap(_shown(c.value, _landscape, _viewport), _viewport);

      // A photo below screen resolution: no such affordance.
      final small = TransformationController();
      addTearDown(small.dispose);
      final smallState = await pump(
        tester,
        controller: small,
        contentSize: const Size(200, 150),
      );
      expect(smallState.canShowActualSize, isFalse);
    });

    testWidgets('without a decoded size the fallback aspect still frames it', (
      tester,
    ) async {
      final c = TransformationController();
      addTearDown(c.dispose);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Center(
              child: SizedBox(
                width: _viewport.width,
                height: _viewport.height,
                child: ZoomableViewport(
                  controller: c,
                  fallbackAspect: 1.44, // 1440 / 1000
                  child: Container(key: childKey, color: Colors.red),
                ),
              ),
            ),
          ),
        ),
      );
      final shown = tester.getRect(find.byKey(childKey));
      expect(shown.width, closeTo(400, 0.5));
      expect(shown.height, closeTo(277.8, 0.5));
    });
  });
}
