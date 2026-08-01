// Regression test for the image-viewer "slow swipe / hold at partial page"
// position race (image_viewer_screen.dart).
//
// Root cause (verified against Flutter 3.44 sources): the page offset is
// driven manually via pageController.jumpTo inside InteractiveViewer's
// onInteractionUpdate. jumpTo ends with goBallistic(0.0), and PageView's
// default pageSnapping wraps the physics in PageScrollPhysics whose
// createBallisticSimulation snaps to the nearest page even at velocity 0.
// So every jumpTo starts a snap-back spring; while the finger holds still at
// a partial swipe the spring visibly slides the page back (position race),
// and during slow swipes it fights the finger (flicker).
//
// The fix has two parts, both asserted here:
//  1. pageSnapping: false  — jumpTo ends idle; release snapping is handled
//     by _onInteractionEnd's own animateToPage.
//  2. Drag tracking anchored in GLOBAL focal point coordinates instead of
//     the recognizer's local focalPointDelta, so the page's own movement can
//     never be re-read as finger movement.

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

/// Mirrors the fixed drag wiring of _ViewerPageState.
class ViewerDragHarness extends StatefulWidget {
  final bool useGlobalFocal;
  final bool pageSnapping;
  const ViewerDragHarness({
    super.key,
    required this.useGlobalFocal,
    this.pageSnapping = true,
  });
  @override
  State<ViewerDragHarness> createState() => _ViewerDragHarnessState();
}

class _ViewerDragHarnessState extends State<ViewerDragHarness> {
  late final PageController _pageController;
  int interactionStarts = 0;
  Offset? _dragStartGlobal;
  double _dragStartOffset = 0;
  double _pageDragOffset = 0;

  @override
  void initState() {
    super.initState();
    _pageController = PageController();
  }

  @override
  void dispose() {
    _pageController.dispose();
    super.dispose();
  }

  void _onInteractionStart(ScaleStartDetails d) {
    interactionStarts++;
    if (d.pointerCount > 1) {
      _dragStartGlobal = null;
      _pageDragOffset = -1;
      return;
    }
    _dragStartGlobal = d.focalPoint;
    _dragStartOffset = _pageController.offset;
    _pageDragOffset = _pageController.offset;
  }

  void _onInteractionUpdate(ScaleUpdateDetails d) {
    if (d.pointerCount != 1) {
      _dragStartGlobal = null;
      _pageDragOffset = -1;
      return;
    }
    if (widget.useGlobalFocal) {
      final start = _dragStartGlobal;
      if (start == null) {
        _dragStartGlobal = d.focalPoint;
        _dragStartOffset = _pageController.offset;
        return;
      }
      final target = (_dragStartOffset - (d.focalPoint.dx - start.dx)).clamp(
        0.0,
        _pageController.position.maxScrollExtent,
      );
      if ((target - _pageController.offset).abs() > 0.01) {
        _pageController.jumpTo(target);
      }
      return;
    }
    if (_pageDragOffset < 0) return;
    _pageDragOffset -= d.focalPointDelta.dx;
    _pageDragOffset = _pageDragOffset.clamp(
      0.0,
      _pageController.position.maxScrollExtent,
    );
    _pageController.jumpTo(_pageDragOffset);
  }

  void _onInteractionEnd(ScaleEndDetails d) {
    _dragStartGlobal = null;
    _pageDragOffset = 0;
  }

  @override
  Widget build(BuildContext context) {
    return Directionality(
      textDirection: TextDirection.ltr,
      child: MediaQuery(
        data: const MediaQueryData(size: Size(400, 800)),
        child: PageView.builder(
          controller: _pageController,
          physics: const NeverScrollableScrollPhysics(),
          pageSnapping: widget.pageSnapping,
          itemCount: 3,
          itemBuilder: (context, index) => InteractiveViewer(
            transformationController: TransformationController(),
            scaleEnabled: true,
            minScale: 1.0,
            maxScale: 6.0,
            panEnabled: true,
            onInteractionStart: _onInteractionStart,
            onInteractionUpdate: _onInteractionUpdate,
            onInteractionEnd: _onInteractionEnd,
            child: ColoredBox(color: Colors.primaries[index % 10]),
          ),
        ),
      ),
    );
  }
}

Future<({int holdLen0, double holdOffset})> _runScenario(
  WidgetTester tester,
  _ViewerDragHarnessState state,
  List<double> offsets,
) async {
  // 1) Slow drag: 60 px in 2 px steps (past touch slop).
  final g = await tester.startGesture(
    const Offset(200, 400),
    kind: PointerDeviceKind.touch,
  );
  for (var i = 0; i < 30; i++) {
    await g.moveBy(const Offset(-2, 0));
    await tester.pump(const Duration(milliseconds: 8));
  }
  // 2) HOLD: idle frames only (no movement) for 300 ms.
  for (var i = 0; i < 20; i++) {
    await tester.pump(const Duration(milliseconds: 15));
  }
  final holdLen0 = offsets.length;
  final holdOffset = state._pageController.offset;
  // 3) Micro-jitter while holding: real fingers emit tiny moves.
  for (var i = 0; i < 10; i++) {
    await g.moveBy(const Offset(1, 0));
    await tester.pump(const Duration(milliseconds: 16));
    await g.moveBy(const Offset(-1, 0));
    await tester.pump(const Duration(milliseconds: 16));
  }
  await g.up();
  await tester.pump(const Duration(milliseconds: 16));
  return (holdLen0: holdLen0, holdOffset: holdOffset);
}

void main() {
  testWidgets('fixed: custom drag path is active and wins the gesture arena', (
    tester,
  ) async {
    await tester.pumpWidget(
      const ViewerDragHarness(useGlobalFocal: true, pageSnapping: false),
    );
    final state = tester.state<_ViewerDragHarnessState>(
      find.byType(ViewerDragHarness),
    );
    final g = await tester.startGesture(
      const Offset(200, 400),
      kind: PointerDeviceKind.touch,
    );
    for (var i = 0; i < 30; i++) {
      await g.moveBy(const Offset(-2, 0));
      await tester.pump(const Duration(milliseconds: 8));
    }
    await g.up();
    await tester.pump(const Duration(milliseconds: 16));
    expect(
      state.interactionStarts,
      1,
      reason: 'the InteractiveViewer path must drive the page',
    );
    expect(
      state._pageController.offset,
      closeTo(60.0, 1.0),
      reason: 'page must track the finger 1:1',
    );
  });

  testWidgets(
    'fixed: holding at a partial page neither drifts nor oscillates',
    (tester) async {
      final offsets = <double>[];
      await tester.pumpWidget(
        const ViewerDragHarness(useGlobalFocal: true, pageSnapping: false),
      );
      final state = tester.state<_ViewerDragHarnessState>(
        find.byType(ViewerDragHarness),
      );
      state._pageController.addListener(
        () => offsets.add(state._pageController.offset),
      );
      final hold = await _runScenario(tester, state, offsets);

      final during = offsets.skip(hold.holdLen0);
      final minV = during.isEmpty
          ? 0.0
          : during.reduce((a, b) => a < b ? a : b);
      final maxV = during.isEmpty
          ? 0.0
          : during.reduce((a, b) => a > b ? a : b);
      expect(
        maxV - minV,
        lessThan(2.0),
        reason: 'no oscillation while the finger holds still',
      );
      expect(
        (state._pageController.offset - hold.holdOffset).abs(),
        lessThan(2.0),
        reason: 'no snap-back drift while holding at a partial page',
      );
      expect(
        state._pageController.offset,
        closeTo(60.0, 2.0),
        reason: 'page stays where the finger left it',
      );
    },
  );

  testWidgets(
    'baseline: old wiring (local delta + default pageSnapping) snaps back '
    'while holding — documents the race the fix removes',
    (tester) async {
      final offsets = <double>[];
      await tester.pumpWidget(
        const ViewerDragHarness(useGlobalFocal: false, pageSnapping: true),
      );
      final state = tester.state<_ViewerDragHarnessState>(
        find.byType(ViewerDragHarness),
      );
      state._pageController.addListener(
        () => offsets.add(state._pageController.offset),
      );
      final hold = await _runScenario(tester, state, offsets);

      // The snap-back spring pulls the page from ~60px back toward page 0
      // while the finger holds still.
      expect(
        (state._pageController.offset - hold.holdOffset).abs(),
        greaterThanOrEqualTo(10.0),
        reason:
            'baseline must exhibit the snap-back race; if this fails, '
            'Flutter changed PageView pageSnapping defaults',
      );
    },
  );
}
