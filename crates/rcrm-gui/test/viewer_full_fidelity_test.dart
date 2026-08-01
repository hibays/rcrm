// Full-fidelity replica of _ViewerPage's gesture stack, testing large swipes
// on both touch and mouse. Mirrors image_viewer_screen.dart exactly:
//   Listener(onPointerDown/Move/Up)  -> vertical dismiss only
//   Transform.translate/scale        -> dismiss visuals
//   InteractiveViewer(panEnabled: !isDesktop || _isZoomed, scale/pan handlers)
//   GestureDetector(onTapDown/onTap) -> tap/zoom UI
//   ColoredBox -> stand-in for PooledImage
// Inside: PageView(NeverScrollableScrollPhysics, pageSnapping: false) with the
// same ScrollConfiguration(dragDevices: {touch, mouse, trackpad}).

import 'dart:async';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class ViewerPage extends StatefulWidget {
  final bool isDesktop;
  final PageController pageController;
  final bool withTapLayer;
  const ViewerPage({
    super.key,
    required this.isDesktop,
    required this.pageController,
    this.withTapLayer = true,
  });

  @override
  State<ViewerPage> createState() => _ViewerPageState();
}

class _ViewerPageState extends State<ViewerPage> {
  bool _isZoomed = false;
  bool _dragEngaged = false;
  Offset _dismissOffset = Offset.zero;
  Offset _dragStart = Offset.zero;
  Offset? _dragStartGlobal;
  double _dragStartOffset = 0;
  Timer? _tapTimer;
  int starts = 0;
  int updates = 0;

  void _onZoomChange(TransformationController c) {
    final z = c.value.getMaxScaleOnAxis() > 1.01;
    if (z != _isZoomed && mounted) setState(() => _isZoomed = z);
  }

  void _onInteractionStart(ScaleStartDetails d) {
    starts++;
    if (_isZoomed || d.pointerCount > 1) {
      _dragStartGlobal = null;
      return;
    }
    _dragStartGlobal = d.focalPoint;
    _dragStartOffset = widget.pageController.offset;
  }

  void _onInteractionUpdate(ScaleUpdateDetails d) {
    updates++;
    if (updates == 1 || updates == 12 || updates == 24) {
      // ignore: avoid_print
      debugPrint(
        '[u$updates] pc=${d.pointerCount} focal=${d.focalPoint} '
        'startGlobal=$_dragStartGlobal startOff=$_dragStartOffset '
        'off=${widget.pageController.offset}',
      );
    }
    if (_isZoomed) {
      _dragStartGlobal = null;
      return;
    }
    if (d.pointerCount != 1) {
      _dragStartGlobal = null;
      return;
    }
    final start = _dragStartGlobal;
    if (start == null) {
      _dragStartGlobal = d.focalPoint;
      _dragStartOffset = widget.pageController.offset;
      return;
    }
    final target = (_dragStartOffset - (d.focalPoint.dx - start.dx)).clamp(
      0.0,
      widget.pageController.position.maxScrollExtent,
    );
    if ((target - widget.pageController.offset).abs() > 0.01) {
      widget.pageController.jumpTo(target);
    }
  }

  void _onInteractionEnd(ScaleEndDetails d) {
    final wasPageDrag = _dragStartGlobal != null;
    _dragStartGlobal = null;
    if (!wasPageDrag || _isZoomed) return;
    final pageWidth = widget.pageController.position.viewportDimension;
    if (pageWidth <= 0) return;
    final startPage = (_dragStartOffset / pageWidth).round();
    final maxPage = (widget.pageController.position.maxScrollExtent / pageWidth)
        .round();
    final offset = widget.pageController.offset;
    final delta = offset - startPage * pageWidth;
    final velocity = d.velocity.pixelsPerSecond.dx;
    final vxAbs = velocity.abs();
    if (delta.abs() > pageWidth * 0.25 || vxAbs > 800) {
      final bool goNext;
      if (delta.abs() > 1.0) {
        goNext = delta > 0;
      } else {
        goNext = velocity < 0;
      }
      final target = goNext ? startPage + 1 : startPage - 1;
      widget.pageController.animateToPage(
        target.clamp(0, maxPage),
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    } else {
      widget.pageController.animateToPage(
        startPage,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    }
  }

  void _onPtrDown(PointerDownEvent e) {
    _dragEngaged = false;
    _dragStart = e.localPosition;
  }

  void _onPtrMove(PointerMoveEvent e) {
    if (!_dragEngaged) {
      final dx = (e.localPosition.dx - _dragStart.dx).abs();
      final dy = e.localPosition.dy - _dragStart.dy;
      if (dy < 10 || dx > dy * 2) return;
      _dragEngaged = true;
    }
    setState(() => _dismissOffset += e.localDelta);
  }

  void _onPtrUp(PointerUpEvent e) {
    _dragEngaged = false;
    setState(() => _dismissOffset = Offset.zero);
  }

  @override
  Widget build(BuildContext context) {
    final controller = TransformationController();
    controller.addListener(() => _onZoomChange(controller));
    final imageContent = InteractiveViewer(
      transformationController: controller,
      scaleEnabled: true,
      minScale: 1.0,
      maxScale: 6.0,
      panEnabled: !widget.isDesktop || _isZoomed,
      onInteractionStart: _onInteractionStart,
      onInteractionUpdate: _onInteractionUpdate,
      onInteractionEnd: _onInteractionEnd,
      child: widget.withTapLayer
          ? GestureDetector(
              behavior: HitTestBehavior.translucent,
              onTap: () {
                if (_tapTimer == null) {
                  _tapTimer = Timer(const Duration(milliseconds: 300), () {
                    _tapTimer = null;
                  });
                } else {
                  _tapTimer!.cancel();
                  _tapTimer = null;
                }
              },
              child: const SizedBox.expand(
                child: ColoredBox(color: Colors.blueGrey),
              ),
            )
          : const SizedBox.expand(child: ColoredBox(color: Colors.blueGrey)),
    );
    return Container(
      color: Colors.black,
      child: Listener(
        onPointerDown: _onPtrDown,
        onPointerMove: _onPtrMove,
        onPointerUp: _onPtrUp,
        child: Transform.translate(
          offset: _dismissOffset,
          child: Transform.scale(
            scale: 1.0,
            child: Stack(children: [imageContent]),
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _tapTimer?.cancel();
    super.dispose();
  }
}

void main() {
  for (final kind in [PointerDeviceKind.touch, PointerDeviceKind.mouse]) {
    for (final isDesktop in [true, false]) {
      for (final withTapLayer in [true, false]) {
        testWidgets(
          'large swipe $kind desktop=$isDesktop tapLayer=$withTapLayer flips page',
          (tester) async {
            final pageController = PageController();
            await tester.pumpWidget(
              Directionality(
                textDirection: TextDirection.ltr,
                child: MediaQuery(
                  data: const MediaQueryData(size: Size(800, 600)),
                  child: Center(
                    child: SizedBox(
                      width: 800,
                      height: 600,
                      child: ScrollConfiguration(
                        behavior: const ScrollBehavior().copyWith(
                          dragDevices: {
                            PointerDeviceKind.touch,
                            PointerDeviceKind.mouse,
                            PointerDeviceKind.trackpad,
                          },
                        ),
                        child: PageView.builder(
                          controller: pageController,
                          physics: const NeverScrollableScrollPhysics(),
                          pageSnapping: false,
                          itemCount: 3,
                          itemBuilder: (context, index) => ViewerPage(
                            isDesktop: isDesktop,
                            pageController: pageController,
                            withTapLayer: withTapLayer,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            );
            // Large slow swipe: 480 px of 800 (60%), under the velocity branch.
            debugPrint(
              'viewer rect: ${tester.getRect(find.byType(ViewerPage).first)}',
            );
            debugPrint(
              'interactive rect: ${tester.getRect(find.byType(InteractiveViewer).first)}',
            );
            debugPrint(
              'stack rect: ${tester.getRect(find.byType(Stack).first)}',
            );
            debugPrint(
              'pageview size: ${tester.getSize(find.byType(PageView))}',
            );
            final g = await tester.startGesture(
              const Offset(600, 300),
              kind: kind,
            );
            for (var i = 0; i < 4; i++) {
              await g.moveBy(const Offset(-20, 0));
              await tester.pump(const Duration(milliseconds: 30));
            }
            for (var i = 0; i < 20; i++) {
              await g.moveBy(const Offset(-20, 0));
              await tester.pump(const Duration(milliseconds: 30));
            }
            await g.up();
            await tester.pumpAndSettle();
            final state = tester.state<_ViewerPageState>(
              find.byType(ViewerPage).first,
            );
            debugPrint(
              '[swipe $kind desktop=$isDesktop tapLayer=$withTapLayer] '
              'page=${pageController.page} offset=${pageController.offset} '
              'starts=${state.starts} updates=${state.updates}',
            );
            expect(
              pageController.page,
              closeTo(1.0, 0.05),
              reason:
                  '60% swipe must flip to the next page ($kind, desktop=$isDesktop, tapLayer=$withTapLayer)',
            );
            pageController.dispose();
          },
        );
      }
    }
  }
}
