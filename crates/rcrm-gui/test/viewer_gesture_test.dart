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
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/screens/image_viewer_screen.dart';
import 'package:rcrm_gui/services/item_cache_limit.dart';
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

Future<void> _openViewer(WidgetTester tester, {List<MediaItem>? items}) async {
  final list = items ?? _items;
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
                  builder: (_) => ImageViewerScreen(items: list),
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
  expect(find.text('1 / ${list.length}'), findsOneWidget);
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

/// The pager's own settled page, 0-based, read off the real `PageController`.
/// A switch has to land ON a page (not mid-slide) and move exactly one page.
double settledPage(WidgetTester tester) =>
    tester.widget<PageView>(find.byType(PageView)).controller!.page!;

/// Records every `SystemChrome.setEnabledSystemUIMode` the app really sends,
/// in order, as the engine's own mode strings (the channel payload is the
/// enum's `toString()`, e.g. `SystemUiMode.immersiveSticky`), so the test can
/// assert what the OS was actually told to do — not what a helper was asked.
List<String> recordSystemUiModes(WidgetTester tester) {
  final calls = <String>[];
  tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
    SystemChannels.platform,
    (call) async {
      if (call.method == 'SystemChrome.setEnabledSystemUIMode') {
        calls.add(call.arguments as String);
      }
      return null;
    },
  );
  addTearDown(
    () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      null,
    ),
  );
  return calls;
}

/// The chrome fade a page badge is wrapped in (`_chromeChip`). A badge has
/// exactly one `AnimatedOpacity` ancestor — the chip wrapper — because the
/// screen's own `_chrome` only wraps the top bar, the strip and the arrows.
double chipOpacity(WidgetTester tester, Finder chip) => tester
    .widget<AnimatedOpacity>(
      find.ancestor(of: chip, matching: find.byType(AnimatedOpacity)),
    )
    .opacity;

/// Drives one lifecycle transition through the real `flutter/lifecycle`
/// channel, which is what the engine sends on resume.
Future<void> setLifecycle(WidgetTester tester, AppLifecycleState state) async {
  await tester.binding.defaultBinaryMessenger.handlePlatformMessage(
    'flutter/lifecycle',
    const StringCodec().encodeMessage(state.toString()),
    (_) {},
  );
}

void main() {
  testWidgets('a pull that drifts sideways never turns the page', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // Engage the pull vertically first (8px of downward travel is enough),
    // then drift far enough sideways that the pager would have flipped. The
    // vertical travel is deliberately small: 20px up front plus 8 × 5px = 60px
    // of pull, under the 93.6px dismissal threshold at this surface height
    // (600 × 0.156), so the viewer survives to be inspected — the subject here
    // is the axis lock, not the threshold.
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
    // One gesture, exactly one image: the release snap must land ON page 1 and
    // must not skip past it — the safety property the switching cooldown
    // exists for, whatever its duration.
    expect(find.text('3 / 3'), findsNothing, reason: 'a swipe must not skip');
    expect(
      settledPage(tester),
      closeTo(1, 0.01),
      reason: 'the pager settles on a real page, not mid-slide',
    );
  });

  testWidgets('one switch press advances exactly one image', (tester) async {
    await _openViewer(tester);
    expect(find.text('1 / 3'), findsOneWidget);

    // Arrow buttons and ←/→ share the same `_goTo` path; a key press is that
    // path without the desktop hover chrome in the way. One press must never
    // double-fire into two pages.
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowRight);
    await tester.pumpAndSettle();

    expect(find.text('2 / 3'), findsOneWidget);
    expect(find.text('3 / 3'), findsNothing, reason: 'one press, one image');
    expect(settledPage(tester), closeTo(1, 0.01));
  });

  testWidgets('a second switch inside the OLD cooldown is no longer swallowed', (
    tester,
  ) async {
    await _openViewer(tester);
    expect(find.text('1 / 3'), findsOneWidget);

    // Two deliberate "next image" switches 220ms apart: inside the old 300ms
    // cooldown, where the second press was dropped and this test failed, and
    // outside the new 200ms one. This is the case the user asked for — pressing
    // next again as soon as the slide is done instead of waiting the lock out.
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowRight);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 220));
    await tester.sendKeyEvent(LogicalKeyboardKey.arrowRight);
    await tester.pumpAndSettle();

    expect(
      find.text('3 / 3'),
      findsOneWidget,
      reason: 'both switches must land: the second press was not swallowed',
    );
    expect(
      settledPage(tester),
      closeTo(2, 0.01),
      reason: 'two presses move exactly two pages — no skip, no double-fire',
    );
  });

  testWidgets('a diagonal drag that leads sideways never pulls', (
    tester,
  ) async {
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
      reason:
          'the page switch owns the gesture, so letting go must not dismiss',
    );
  });

  testWidgets('a diagonal drag that leads downwards still pulls', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // 40px across, 64px down: the pull dominates, so the axis lock must hand
    // it the gesture. 64px stays under the 93.6px dismissal threshold at this
    // surface height (600 × 0.156), so the viewer is still there to be
    // inspected.
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

  testWidgets('a pull well past the threshold closes the viewer', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // 12 × 20px = 240px of downward travel: well past the dismissal threshold
    // at this surface height, both the 93.6px it is now (600 × 0.156) and the
    // 72px it was before. The intent this test has always had is unchanged —
    // past the threshold, letting go closes the viewer.
    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 12; i++) {
      await gesture.moveBy(const Offset(0, 20));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await gesture.up();
    await tester.pumpAndSettle();

    expect(find.byType(ImageViewerScreen), findsNothing);
  });

  testWidgets('a pull past the OLD threshold no longer dismisses', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // 4 × 20px = 80px of downward travel. Under the old threshold (72px at
    // this surface height) this dismissed — the red case this change exists
    // for — while the raised threshold (93.6px) is not reached, so the viewer
    // must spring back. Velocity is 0 here (the harness's events carry no
    // timestamps), so the flick path cannot close it either: the distance
    // threshold is the only thing this test can be measuring.
    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 4; i++) {
      await gesture.moveBy(const Offset(0, 20));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await gesture.up();
    await tester.pumpAndSettle();

    expect(
      find.byType(ImageViewerScreen),
      findsOneWidget,
      reason: '80px is short of the raised threshold, so the viewer stays',
    );
    expect(find.text('1 / 3'), findsOneWidget);
  });

  testWidgets('a deliberate pull still dismisses', (tester) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // 6 × 20px = 120px: a real, unhurried pull, ~28% past the raised threshold
    // (93.6px). This is the guard against the other failure mode — a threshold
    // made so heavy that dismissing on purpose stops working.
    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 6; i++) {
      await gesture.moveBy(const Offset(0, 20));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await gesture.up();
    await tester.pumpAndSettle();

    expect(
      find.byType(ImageViewerScreen),
      findsNothing,
      reason: 'a deliberate 120px pull must still close the viewer',
    );
  });

  testWidgets('a small pull still springs back instead of dismissing', (
    tester,
  ) async {
    await _openViewer(tester);
    final center = tester.getCenter(find.byType(ImageViewerScreen));
    expect(paintedDy(tester), 0, reason: 'the photo starts at rest');

    // Six 5px steps: the finger travels 30px, of which the axis lock spends
    // the first 5px deciding, so the pull itself measures 25px — about a
    // quarter of the 93.6px threshold, and under the 72px one it replaced. A
    // nudge at the top edge must snap back whatever the threshold is.
    final gesture = await tester.startGesture(center);
    for (var i = 0; i < 6; i++) {
      await gesture.moveBy(const Offset(0, 5));
      await tester.pump(const Duration(milliseconds: 16));
    }
    expect(
      paintedDy(tester),
      greaterThan(0),
      reason: 'the small pull must really have moved the photo',
    );
    await gesture.up();
    await tester.pumpAndSettle();

    expect(
      find.byType(ImageViewerScreen),
      findsOneWidget,
      reason: 'a small pull must snap back, never dismiss',
    );
    expect(paintedDy(tester), 0, reason: 'and it must have sprung back');
    expect(find.text('1 / 3'), findsOneWidget);
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
      reason:
          'a zoomed picture must survive a downward drag anywhere, '
          'not only at its top edge',
    );
    expect(
      paintedDy(tester),
      greaterThan(before + 5),
      reason:
          'the drag must PAN the picture; being ignored is the old '
          'behaviour this test exists to rule out',
    );
    expect(find.text('1 / 3'), findsOneWidget);
  });

  // ── The pull while a live photo plays ───────────────────────────
  //
  // Live playback cannot be started in this harness: `_playLive` needs a
  // live-photo URL (HTTP range requests) and a real media_kit `Player` (native
  // libmpv), and neither exists under `flutter test`. What is pinned instead is
  // the rule the page's one pull gate consults — the same gate that stops the
  // pull when a sideways page drag owns the gesture, which is the exclusivity
  // the report asks for. That gate returns before `_dragEngaged` is set, so a
  // blocked pull contributes no offset, no scale/fade, and no dismissal on
  // release (the behaviour the pull tests above pin for the pager's case).
  test('a playing live photo blocks the pull, exactly like a zoom does', () {
    expect(pullAllowed(zoomed: false, livePlaying: true), isFalse);
    expect(pullAllowed(zoomed: true, livePlaying: false), isFalse);
    expect(pullAllowed(zoomed: false, livePlaying: false), isTrue);
  });

  // ── Page badges belong to the chrome ────────────────────────────
  testWidgets('a page badge hides with the chrome and never travels with the '
      'pull', (tester) async {
    // A .gif is always animated, so its badge — the bottom-right chip — exists
    // with no decode and no network round trip, in the same chrome layer the
    // live photo's bottom-left badge sits in.
    await _openViewer(tester, items: [_image('a.gif')]);
    final badge = find.byIcon(Icons.motion_photos_on);
    expect(badge, findsOneWidget);
    expect(chipOpacity(tester, badge), 1);

    final atRest = tester.getTopLeft(badge);
    final center = tester.getCenter(find.byType(ImageViewerScreen));

    // 80px of pull: enough to move the photo, under the 93.6px dismissal
    // threshold at this surface height, so the viewer survives to be read.
    final gesture = await tester.startGesture(center);
    await gesture.moveBy(const Offset(0, 20));
    await tester.pump();
    for (var i = 0; i < 12; i++) {
      await gesture.moveBy(const Offset(0, 5));
      await tester.pump(const Duration(milliseconds: 16));
    }

    expect(
      paintedDy(tester),
      greaterThan(0),
      reason: 'the pull really did move the photo',
    );
    expect(
      tester.getTopLeft(badge),
      atRest,
      reason:
          'a badge inside the pulled/scaled layer comes down with the '
          'finger',
    );
    expect(
      chipOpacity(tester, badge),
      0,
      reason: 'the pull hid the chrome, so the badge goes with it',
    );

    await gesture.up();
    await tester.pumpAndSettle();
  });

  testWidgets('the badge is gone while the chrome is hidden and back when it '
      'is shown', (tester) async {
    await _openViewer(tester, items: [_image('a.gif')]);
    final badge = find.byIcon(Icons.motion_photos_on);
    expect(chipOpacity(tester, badge), 1);

    final center = tester.getCenter(find.byType(ImageViewerScreen));
    await tester.tapAt(center);
    await tester.pump(const Duration(milliseconds: 320));
    expect(
      chipOpacity(tester, badge),
      0,
      reason: 'hiding the controls has to take the badge with them',
    );

    await tester.tapAt(center);
    await tester.pump(const Duration(milliseconds: 320));
    expect(chipOpacity(tester, badge), 1);
  });

  // ── Status bar follows the chrome (mobile) ──────────────────────
  //
  // Android keeps showing the status bar over a full-screen photo unless the
  // viewer tells the OS to go immersive, so the mode the app sends has to
  // follow the one chrome flag (`_ImageViewerScreenState._showUI`). These
  // tests read the real platform channel, which is the only place that fact
  // is observable. The tests run on the desktop VM, where the branch is
  // unreachable, so `debugViewerMobile` is turned on for this group only —
  // every other test in this file keeps the real `isMobile` and sends no
  // platform call at all (which is also why they would fail if the viewer
  // went immersive unconditionally).
  group('status bar follows the chrome (mobile)', () {
    setUp(() => debugViewerMobile = true);
    tearDown(() => debugViewerMobile = isMobile);

    testWidgets('hiding the chrome goes immersive, showing it restores '
        'edge-to-edge', (tester) async {
      final modes = recordSystemUiModes(tester);
      await _openViewer(tester);
      final center = tester.getCenter(find.byType(ImageViewerScreen));

      await tester.tapAt(center);
      await tester.pump(const Duration(milliseconds: 320));
      expect(
        modes.last,
        SystemUiMode.immersiveSticky.toString(),
        reason: 'the chrome is hidden, so the status bar must go with it',
      );

      await tester.tapAt(const Offset(60, 300));
      await tester.pump(const Duration(milliseconds: 320));
      expect(
        modes.last,
        SystemUiMode.edgeToEdge.toString(),
        reason: 'the chrome is back, so the status bar must be back too',
      );
    });

    testWidgets('leaving the viewer after a pull-to-dismiss restores the '
        'normal mode (no immersion leak)', (tester) async {
      final modes = recordSystemUiModes(tester);
      await _openViewer(tester);
      final center = tester.getCenter(find.byType(ImageViewerScreen));

      // 6 × 20px = 120px: the deliberate pull that dismisses (see the tests
      // above). Engaging the pull is what hides the chrome, so this is also
      // the path that goes immersive on the way out.
      final gesture = await tester.startGesture(center);
      for (var i = 0; i < 6; i++) {
        await gesture.moveBy(const Offset(0, 20));
        await tester.pump(const Duration(milliseconds: 16));
      }
      await gesture.up();
      await tester.pumpAndSettle();
      expect(find.byType(ImageViewerScreen), findsNothing);

      expect(
        modes.last,
        SystemUiMode.edgeToEdge.toString(),
        reason: 'the route is gone, so the app must be back in its normal mode',
      );
      // The hide happened before the restore — otherwise this test would pass
      // on a viewer that never went immersive at all.
      expect(modes, contains(SystemUiMode.immersiveSticky.toString()));
    });

    testWidgets('the bar state on the first frame matches the chrome (shown), '
        'so entering does not flash-hide it', (tester) async {
      final modes = recordSystemUiModes(tester);
      await _openViewer(tester);

      // The chrome starts visible, so the mode the viewer sends on entry is
      // the app's normal one — not immersive, and not nothing.
      expect(modes, [
        SystemUiMode.edgeToEdge.toString(),
      ], reason: 'entering the viewer must not hide the status bar');
    });

    testWidgets('leaving by the back button/gesture (the PopScope path) also '
        'restores the normal mode', (tester) async {
      final modes = recordSystemUiModes(tester);
      await _openViewer(tester);
      final center = tester.getCenter(find.byType(ImageViewerScreen));

      // Hide the chrome first, so this exit really has an immersion to undo.
      await tester.tapAt(center);
      await tester.pump(const Duration(milliseconds: 320));
      expect(modes.last, SystemUiMode.immersiveSticky.toString());

      // The system back button/gesture pops the route directly, without going
      // through the viewer's own `_close()`.
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.byType(ImageViewerScreen), findsNothing);

      expect(
        modes.last,
        SystemUiMode.edgeToEdge.toString(),
        reason: 'a back exit must not leave the app immersive either',
      );
    });

    testWidgets('regaining focus re-asserts the hidden chrome — as a real '
        'transition, because a repeated mode is swallowed', (tester) async {
      final modes = recordSystemUiModes(tester);
      await _openViewer(tester);
      final center = tester.getCenter(find.byType(ImageViewerScreen));

      await tester.tapAt(center);
      await tester.pump(const Duration(milliseconds: 320));
      expect(modes.last, SystemUiMode.immersiveSticky.toString());
      final beforeResume = modes.length;

      // Android shows the bars again by itself when the window loses and
      // regains focus, and the request that hid them is one-shot: the engine
      // routes every non-edge-to-edge mode through the deprecated
      // `View.setSystemUiVisibility`, which ignores an unchanged value — which
      // is also why the engine's own re-apply on `onPostResume` cannot put the
      // bars back down. So the resume has to re-establish the state, and as a
      // flag *change*.
      await setLifecycle(tester, AppLifecycleState.inactive);
      await tester.pump();
      await setLifecycle(tester, AppLifecycleState.resumed);
      await tester.pumpAndSettle();

      expect(
        modes.sublist(beforeResume),
        [
          SystemUiMode.edgeToEdge.toString(),
          SystemUiMode.immersiveSticky.toString(),
        ],
        reason:
            'the hidden chrome must be re-established on resume, and as a '
            'flag change: a repeat of the same mode never reaches the window',
      );
      expect(find.byType(ImageViewerScreen), findsOneWidget);
    });
  });
}
