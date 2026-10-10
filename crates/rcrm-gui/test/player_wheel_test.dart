// test/player_wheel_test.dart
// One notch of the mouse wheel does ONE thing.
//
// Regression (user report): in fullscreen with the playlist open, a wheel over
// the playlist scrolled the list AND changed the player's volume. The volume
// path lived in `Listener.onPointerSignal` on the whole fullscreen stack — an
// ancestor of the playlist — and it acted on the notch directly. Two things
// follow from that, and both are pinned here:
//
//   * `PointerSignalResolver` arbitrates only BETWEEN REGISTRANTS, and it does
//     not resolve until the entire hit-test path has been dispatched, so a
//     `Scrollable` that registers cannot stop a listener that acts directly
//     (`one notch ... reaches the player`).
//   * A `Scrollable` registers only when the notch would really move it, so a
//     wheel over a playlist with nothing left to scroll would reach the player
//     even after switching to the resolver. The "a panel owns the screen" gate
//     is what refuses that one.
//
// The screen itself cannot be pumped here: it owns a media_kit `Player`, which
// cannot be faked cheaply. So this file drives the screen's real wheel layer,
// `PlayerWheelLayer` (`utils/wheel_guard.dart`), which is the whole decision —
// the resolver registration, the gate, the volume arithmetic — laid over the
// fullscreen body's shape (`Stack` whose last, hit-first child is the playlist).
// The only substitution is inside the sheet: its rows use a fixed-height
// placeholder instead of `VideoCard`, because `VideoCard` without a thumbnail
// service overflows its poster placeholder in a widget test, which has nothing
// to do with wheel arbitration. The sheet's own structure (dimmed backdrop,
// right-side panel, `Listener` → `ListView.builder`) is copied from
// `widgets/episode_picker_panel.dart`.

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/wheel_guard.dart';

const Size _surface = Size(1000, 700); // landscape: the sheet is a side panel
const double _rowHeight = 86; // the panel's row height

/// The screen's volume arithmetic, verbatim: a notch is 5 points, clamped.
double _nextVolume(double current, double delta) =>
    (current + (delta > 0 ? -5.0 : 5.0)).clamp(0.0, 100.0);

/// The episode sheet, structurally as `EpisodePickerPanel` builds it in
/// landscape: a dimmed backdrop that swallows taps, and a `ListView` in a
/// right-side container.
Widget _episodeSheet(int rows) => Container(
  color: Colors.black.withValues(alpha: 0.45),
  alignment: Alignment.centerRight,
  child: Container(
    width: 460,
    height: double.infinity,
    color: const Color(0xFF1A1A1A),
    child: Listener(
      child: ListView.builder(
        padding: const EdgeInsets.only(top: 4, bottom: 16),
        itemCount: rows,
        itemBuilder: (_, i) => SizedBox(
          height: _rowHeight,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
            child: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                'episode $i',
                style: const TextStyle(color: Colors.white, fontSize: 13),
              ),
            ),
          ),
        ),
      ),
    ),
  ),
);

/// The fullscreen body's shape, minus the `Player`: whatever [wheel] is wraps a
/// `Stack` whose last (topmost, hit-first) child is the episode sheet.
///
/// [wheel] is the screen's wheel path — [PlayerWheelLayer] after the fix, and
/// the bare `Listener` of [_unguardedWheel] to reproduce the bug. The `Stack` is
/// identical either way, which is the point: the fix is about who arbitrates the
/// notch, not about z-order.
Widget _playerFrame({
  required int rows,
  required Widget Function(Widget stack) wheel,
}) => MaterialApp(
  home: Scaffold(
    backgroundColor: Colors.black,
    body: wheel(
      Stack(
        children: [
          const Positioned.fill(
            child: ColoredBox(color: Colors.black), // stands in for the video
          ),
          Positioned.fill(child: _episodeSheet(rows)),
        ],
      ),
    ),
  ),
);

/// The pre-fix wheel path: a `Listener` over the whole stack that acts on the
/// notch directly.
Widget _unguardedWheel(Widget child, ValueChanged<double> onWheel) => Listener(
  onPointerSignal: (event) {
    if (event is PointerScrollEvent) onWheel(event.scrollDelta.dy);
  },
  child: child,
);

/// One real mouse-wheel notch at [at], dispatched through the binding so the
/// pointer-signal resolver arbitrates it exactly as it does in the app.
Future<void> _wheel(WidgetTester tester, Offset at, double dy) async {
  final pointer = TestPointer(1, PointerDeviceKind.mouse);
  pointer.hover(at);
  await tester.sendEventToBinding(
    PointerScrollEvent(position: at, scrollDelta: Offset(0, dy)),
  );
}

/// The wheel's landing spot: inside the sheet, over its list.
Offset _overSheetList(WidgetTester tester) =>
    tester.getCenter(find.byType(ListView));

double _listOffset(WidgetTester tester) => tester
    .state<ScrollableState>(
      find.descendant(
        of: find.byType(ListView),
        matching: find.byType(Scrollable),
      ),
    )
    .position
    .pixels;

void main() {
  testWidgets('unguarded, one notch over the playlist scrolls it AND reaches '
      'the player', (tester) async {
    // The bug itself, and the reason the fix cannot be "let the scrollable win
    // the resolver": a listener that acts directly never enters the resolver, so
    // both consumers run for the same notch. If this ever stops being true the
    // guard would be unnecessary, and this test should be deleted rather than
    // "fixed".
    await tester.binding.setSurfaceSize(_surface);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    var volume = 100.0;
    await tester.pumpWidget(
      _playerFrame(
        rows: 40,
        wheel: (stack) => _unguardedWheel(stack, (dy) {
          volume = _nextVolume(volume, dy);
        }),
      ),
    );

    await _wheel(tester, _overSheetList(tester), 300);
    await tester.pump();

    expect(
      _listOffset(tester),
      greaterThan(0),
      reason: 'the playlist itself scrolls',
    );
    expect(
      volume,
      lessThan(100),
      reason: 'and the same notch reached the player — the reported bug',
    );
  });

  testWidgets('with the playlist open, the wheel scrolls it and leaves the '
      'player alone', (tester) async {
    await tester.binding.setSurfaceSize(_surface);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    var volume = 100.0;
    await tester.pumpWidget(
      _playerFrame(
        rows: 40,
        wheel: (stack) => PlayerWheelLayer(
          volume: () => volume,
          nextVolume: _nextVolume,
          setVolume: (v) => volume = v,
          gate: () => true, // the episode sheet is open
          child: stack,
        ),
      ),
    );

    await _wheel(tester, _overSheetList(tester), 300);
    await tester.pump();

    expect(_listOffset(tester), greaterThan(0), reason: 'the panel scrolls');
    expect(
      volume,
      100,
      reason:
          'a panel owns the screen: the wheel changes nothing in the player',
    );
  });

  testWidgets('a playlist with nothing left to scroll still keeps the wheel '
      'off the player', (tester) async {
    // The resolver alone cannot carry this case: `Scrollable` registers only
    // when the notch would really move it, so a playlist that is too short (or
    // already at its end) registers nothing and the notch would fall through to
    // the player. The panel gate is what refuses it.
    await tester.binding.setSurfaceSize(_surface);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    var volume = 100.0;
    await tester.pumpWidget(
      _playerFrame(
        rows: 0,
        wheel: (stack) => PlayerWheelLayer(
          volume: () => volume,
          nextVolume: _nextVolume,
          setVolume: (v) => volume = v,
          gate: () => true,
          child: stack,
        ),
      ),
    );

    await _wheel(tester, const Offset(800, 350), 300);
    await tester.pump();

    expect(_listOffset(tester), 0, reason: 'nothing in the panel can move');
    expect(volume, 100, reason: 'and the player still gets nothing');
  });

  testWidgets('with no panel open the wheel over the video still changes the '
      'volume', (tester) async {
    await tester.binding.setSurfaceSize(_surface);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    var volume = 100.0;
    await tester.pumpWidget(
      _playerFrame(
        rows: 40,
        wheel: (stack) => PlayerWheelLayer(
          volume: () => volume,
          nextVolume: _nextVolume,
          setVolume: (v) => volume = v,
          gate: () => false,
          child: stack,
        ),
      ),
    );

    // Left of the sheet: the video area.
    await _wheel(tester, const Offset(150, 350), 120);
    await tester.pump();

    expect(volume, 95, reason: 'the feature the guard must not weaken');
    expect(_listOffset(tester), 0, reason: 'the panel is not scrolled');

    // Wheel up again: back to where it started.
    await _wheel(tester, const Offset(150, 350), -120);
    await tester.pump();
    expect(volume, 100);
  });

  testWidgets('a notch at the volume limit is a no-op, panel or not', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(_surface);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    var volume = 100.0;
    var setCalls = 0;
    await tester.pumpWidget(
      _playerFrame(
        rows: 40,
        wheel: (stack) => PlayerWheelLayer(
          volume: () => volume,
          nextVolume: _nextVolume,
          setVolume: (v) {
            setCalls++;
            volume = v;
          },
          gate: () => false,
          child: stack,
        ),
      ),
    );

    // Already at 100: turning the wheel up must change nothing and must not
    // pretend the player used the notch.
    await _wheel(tester, const Offset(150, 350), -120);
    await tester.pump();

    expect(volume, 100);
    expect(setCalls, 0);
  });

  test('wheel decisions: a plain vertical notch, and no panel open', () {
    const at = Offset(10, 10);
    expect(
      wheelGuardDeltaOrZero(
        const PointerScrollEvent(position: at, scrollDelta: Offset(0, 120)),
        panelOpen: false,
      ),
      120,
    );
    expect(
      wheelGuardDeltaOrZero(
        const PointerScrollEvent(position: at, scrollDelta: Offset(0, 120)),
        panelOpen: true,
      ),
      0,
      reason: 'a panel owns the screen',
    );
    expect(
      wheelGuardDeltaOrZero(
        const PointerScrollEvent(position: at, scrollDelta: Offset(120, 0)),
        panelOpen: false,
      ),
      0,
      reason: 'a horizontal wheel is not a volume notch',
    );
  });
}
