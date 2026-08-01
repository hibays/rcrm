// Diagnostic: which path drives page switching on DESKTOP (mouse drag)?
// Real viewer config:
//   - ScrollConfiguration(dragDevices: {touch, mouse, trackpad})
//   - PageView physics: NeverScrollableScrollPhysics (current, broken?)
//     vs PageScrollPhysics (previous, working)
//   - InteractiveViewer panEnabled: !isDesktop || _isZoomed  (false on desktop
//     at scale 1)

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class DesktopDragHarness extends StatefulWidget {
  final bool usePageScrollPhysics;
  final bool pageSnapping;
  final bool manualEnabled;
  const DesktopDragHarness({
    super.key,
    required this.usePageScrollPhysics,
    required this.pageSnapping,
    this.manualEnabled = true,
  });
  @override
  State<DesktopDragHarness> createState() => _DesktopDragHarnessState();
}

class _DesktopDragHarnessState extends State<DesktopDragHarness> {
  late final PageController _pageController;
  int interactionStarts = 0;
  Offset? _dragStartGlobal;
  double _dragStartOffset = 0;

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
    if (!widget.manualEnabled) return;
    if (d.pointerCount > 1) {
      _dragStartGlobal = null;
      return;
    }
    _dragStartGlobal = d.focalPoint;
    _dragStartOffset = _pageController.offset;
  }

  void _onInteractionUpdate(ScaleUpdateDetails d) {
    if (!widget.manualEnabled) return;
    if (d.pointerCount != 1) {
      _dragStartGlobal = null;
      return;
    }
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
  }

  void _onInteractionEnd(ScaleEndDetails d) {
    if (!widget.manualEnabled) {
      _dragStartGlobal = null;
      return;
    }
    final wasPageDrag = _dragStartGlobal != null;
    _dragStartGlobal = null;
    // ignore: avoid_print
    debugPrint(
      '  [end] wasPageDrag=$wasPageDrag velocity=${d.velocity.pixelsPerSecond.dx} '
      'offset=${_pageController.offset} viewport=${_pageController.position.viewportDimension} '
      'page=${_pageController.page} max=${_pageController.position.maxScrollExtent}',
    );
    // When zoomed, never trigger page change — just spring back.
    if (!wasPageDrag) return;
    final pageWidth = _pageController.position.viewportDimension;
    if (pageWidth <= 0) return;
    final startPage = (_dragStartOffset / pageWidth).round();
    final maxPage = (_pageController.position.maxScrollExtent / pageWidth)
        .round();
    final offset = _pageController.offset;
    final delta = offset - startPage * pageWidth;
    // ignore: avoid_print
    debugPrint('  [end] startPage=$startPage maxPage=$maxPage delta=$delta');

    final velocity = d.velocity.pixelsPerSecond.dx;
    final vxAbs = velocity.abs();
    if (delta.abs() > pageWidth * 0.25 || vxAbs > 800) {
      // Decide direction: prefer delta, but use velocity when delta is
      // near 0 (PageView clamps offset at edges, zeroing delta even
      // though the user's swipe had clear direction).
      final bool goNext;
      if (delta.abs() > 1.0) {
        goNext = delta > 0;
      } else {
        goNext = velocity < 0; // finger moving left → next page
      }
      final target = goNext ? startPage + 1 : startPage - 1;
      final clamped = target.clamp(0, maxPage);
      _pageController.animateToPage(
        clamped,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    } else {
      // Spring back to current page.
      _pageController.animateToPage(
        startPage,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Directionality(
      textDirection: TextDirection.ltr,
      child: MediaQuery(
        data: const MediaQueryData(size: Size(800, 600)),
        child: ScrollConfiguration(
          behavior: ScrollConfiguration.of(context).copyWith(
            dragDevices: {
              PointerDeviceKind.touch,
              PointerDeviceKind.mouse,
              PointerDeviceKind.trackpad,
            },
          ),
          child: PageView.builder(
            controller: _pageController,
            physics: widget.usePageScrollPhysics
                ? const PageScrollPhysics()
                : const NeverScrollableScrollPhysics(),
            pageSnapping: widget.pageSnapping,
            itemCount: 3,
            itemBuilder: (context, index) => InteractiveViewer(
              transformationController: TransformationController(),
              scaleEnabled: true,
              minScale: 1.0,
              maxScale: 6.0,
              // Desktop: only enable InteractiveViewer pan when zoomed.
              panEnabled: false,
              onInteractionStart: _onInteractionStart,
              onInteractionUpdate: _onInteractionUpdate,
              onInteractionEnd: _onInteractionEnd,
              child: ColoredBox(color: Colors.primaries[index % 10]),
            ),
          ),
        ),
      ),
    );
  }
}

void main() {
  for (final cfg in [
    (
      name: 'NATIVE-only: PageScrollPhysics+manual off (old desktop path)',
      never: false,
      snap: true,
      manual: false,
    ),
    (
      name: 'A CURRENT: NeverScrollable+pageSnapping=false',
      never: true,
      snap: false,
      manual: true,
    ),
  ]) {
    testWidgets('desktop mouse drag 320px — ${cfg.name}', (tester) async {
      await tester.pumpWidget(
        DesktopDragHarness(
          usePageScrollPhysics: !cfg.never,
          pageSnapping: cfg.snap,
          manualEnabled: cfg.manual,
        ),
      );
      final state = tester.state<_DesktopDragHarnessState>(
        find.byType(DesktopDragHarness),
      );
      final trace = <double>[];
      state._pageController.addListener(
        () => trace.add(state._pageController.offset),
      );
      final g = await tester.startGesture(
        const Offset(400, 300),
        kind: PointerDeviceKind.mouse,
      );
      // Slow, LARGE swipe: 320 px over 24 steps x 30ms ≈ 444 px/s (< 800),
      // so page change must come from the delta (> 25%) branch alone.
      for (var i = 0; i < 24; i++) {
        await g.moveBy(const Offset(-13.33, 0));
        await tester.pump(const Duration(milliseconds: 30));
      }
      final duringDrag = state._pageController.offset;
      await g.up();
      await tester.pumpAndSettle();
      // ignore: avoid_print
      debugPrint(
        '[${cfg.name}] interactionStarts=${state.interactionStarts} '
        'duringDrag=$duringDrag settled=${state._pageController.offset} '
        'page=${state._pageController.page} trace=${trace.take(6).toList()}...${trace.length}',
      );
      if (cfg.never) {
        // Manual jumpTo path must track the finger while dragging.
        expect(
          duringDrag,
          greaterThan(150),
          reason: 'NeverScrollable: manual jumpTo must track the finger',
        );
      }
    });
  }

  testWidgets('animateToPage completes under NeverScrollableScrollPhysics', (
    tester,
  ) async {
    await tester.pumpWidget(
      const DesktopDragHarness(
        usePageScrollPhysics: false,
        pageSnapping: false,
        manualEnabled: false,
      ),
    );
    final state = tester.state<_DesktopDragHarnessState>(
      find.byType(DesktopDragHarness),
    );
    state._pageController.animateToPage(
      1,
      duration: const Duration(milliseconds: 250),
      curve: Curves.easeOut,
    );
    await tester.pumpAndSettle();
    // ignore: avoid_print
    debugPrint(
      '[animateToPage under NeverScrollable] page=${state._pageController.page} '
      'offset=${state._pageController.offset}',
    );
    expect(
      state._pageController.page,
      closeTo(1.0, 0.01),
      reason: 'animateToPage must complete even with NeverScrollable physics',
    );
  });
}
