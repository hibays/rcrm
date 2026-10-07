// widgets/viewer_zoom.dart
// Zoom, pan and pull-to-dismiss geometry for the image viewer.
//
// The viewer displays a photo at "fit contain" size and transforms ONLY the
// photo — never the letterbox around it. That is the whole point: with the
// scrollable surface being the screen itself (the old InteractiveViewer setup),
// zooming scaled the empty margins too and panning could drag the picture
// clean off the screen, leaving nothing but black.
//
// So the content rect is computed first (fitContain), the child is laid out at
// exactly that size, and every gesture maps through Matrix4 in which the
// translation is clamped:
//   * zoomed in  → the picture covers the viewport, edges never cross inside;
//   * zoomed out → the picture is locked to the centre.
// There is no pan position that shows empty space, at any scale.

import 'dart:math' as math;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';

/// Geometry for one photo page.
abstract final class ViewerZoom {
  /// Maximum zoom, relative to the fit-contain size.
  static const double maxScale = 6.0;

  /// Above this the page counts as zoomed (pan instead of page swipe).
  static const double zoomedAt = 1.01;

  /// Displayed size of [content] (in pixels) fitted inside [viewport].
  static Size fitContain(Size viewport, Size content) {
    if (viewport.isEmpty || content.isEmpty) return viewport;
    final s = math.min(
      viewport.width / content.width,
      viewport.height / content.height,
    );
    return Size(content.width * s, content.height * s);
  }

  static double scaleOf(Matrix4 m) => m.getMaxScaleOnAxis();

  static Offset translationOf(Matrix4 m) {
    final t = m.getTranslation();
    return Offset(t.x, t.y);
  }

  static bool isZoomed(Matrix4 m) => scaleOf(m) > zoomedAt;

  /// The translation closest to [translation] that leaves no empty space:
  /// centred while the picture is smaller than the viewport, otherwise bounded
  /// so its edges can never come inside the viewport's.
  static Offset clampTranslation({
    required Size viewport,
    required Size displayed,
    required Offset translation,
  }) {
    double axis(double viewportSide, double shownSide, double t) {
      if (shownSide <= viewportSide) return (viewportSide - shownSide) / 2;
      return t.clamp(viewportSide - shownSide, 0.0);
    }

    return Offset(
      axis(viewport.width, displayed.width, translation.dx),
      axis(viewport.height, displayed.height, translation.dy),
    );
  }

  /// Matrix placing [content] inside [viewport] at [scale], clamped.
  static Matrix4 matrixFor({
    required Size viewport,
    required Size content,
    required double scale,
    required Offset translation,
  }) {
    final fitted = fitContain(viewport, content);
    final displayed = Size(fitted.width * scale, fitted.height * scale);
    final t = clampTranslation(
      viewport: viewport,
      displayed: displayed,
      translation: translation,
    );
    return Matrix4.identity()
      ..translateByDouble(t.dx, t.dy, 0, 1)
      ..scaleByDouble(scale, scale, scale, 1);
  }

  /// The matrix for a fresh page: fitted and centred.
  static Matrix4 identity({required Size viewport, required Size content}) =>
      matrixFor(
        viewport: viewport,
        content: content,
        scale: 1,
        translation: Offset.zero,
      );

  /// Zooms [current] by [factor] while keeping the content point under
  /// [focalPoint] (viewport coordinates) where it is. Defaults to the centre.
  static Matrix4 zoomAbout({
    required Matrix4 current,
    required Size viewport,
    required Size content,
    required double factor,
    Offset? focalPoint,
  }) {
    final scale = scaleOf(current);
    if (scale <= 0) return identity(viewport: viewport, content: content);
    final next = (scale * factor).clamp(1.0, maxScale);
    final f = focalPoint ?? viewport.center(Offset.zero);
    final t = translationOf(current);
    final k = next / scale;
    // viewportPoint = t + scale * contentPoint  →  keep contentPoint fixed.
    final moved = f - (f - t) * k;
    return matrixFor(
      viewport: viewport,
      content: content,
      scale: next,
      translation: moved,
    );
  }

  /// Scale that renders one image pixel per logical pixel (the "1:1" chip).
  /// 1.0 when the picture is already at or below screen resolution.
  static double actualSizeScale({required Size viewport, required Size content}) {
    final fitted = fitContain(viewport, content);
    if (fitted.width <= 0) return 1;
    return (content.width / fitted.width).clamp(1.0, maxScale);
  }

  /// True while the picture is pinned to the top of the viewport — the point
  /// at which dragging further down may hand the gesture to pull-to-dismiss.
  static bool atTopEdge(Matrix4 m) {
    if (!isZoomed(m)) return true;
    return translationOf(m).dy >= -0.5;
  }
}

/// Pull-to-dismiss threshold in logical pixels: a fixed ceiling with a
/// proportional floor, so a tall phone does not demand a marathon drag.
double dismissThreshold(double viewportHeight) =>
    math.min(132, math.max(72, viewportHeight * 0.12));

/// 0..1 progress of a pull, used for the fade and the shrink.
double dismissProgress(double distance, double viewportHeight) =>
    (distance / dismissThreshold(viewportHeight)).clamp(0.0, 1.0);

/// How far the photo follows the finger during a pull: vertical travel is
/// 1:1, sideways tremor is damped, and upward travel is resisted so changing
/// your mind mid-pull is smooth instead of a wall.
Offset pullOffsetDelta(Offset delta) =>
    Offset(delta.dx * 0.35, delta.dy >= 0 ? delta.dy : delta.dy * 0.35);

/// Whether releasing a pull-down closes the viewer.
///
/// Distance alone feels deaf to a quick flick, which is what made the old
/// gesture bounce back on short, fast flicks: velocity counts too.
bool shouldDismissPull({
  required double distance,
  required double velocity,
  required double viewportHeight,
}) {
  if (distance <= 0) return false;
  if (distance >= dismissThreshold(viewportHeight)) return true;
  return velocity > 700;
}

// ── The viewport widget ─────────────────────────────────────────────

/// Hosts one photo: lays it out at fit-contain size, applies the clamped
/// zoom/pan matrix, and owns the zoom gestures.
///
/// Tap and long-press stay with the caller (the child keeps its own
/// recognizers); this widget reports taps in **viewport** coordinates so
/// zoom-to-point maths never has to reason about the transform.
class ZoomableViewport extends StatefulWidget {
  final TransformationController controller;

  /// Intrinsic pixel size of the image; null until it has been decoded, in
  /// which case [fallbackAspect] (or the viewport itself) stands in.
  final Size? contentSize;

  /// Known aspect ratio (width / height) from a cheaper decode — usually the
  /// grid thumbnail. Lets the zoom geometry be right on the first frame.
  final double? fallbackAspect;

  /// Whether a drag pans/zooms the picture. The viewer drops this while a
  /// pull-to-dismiss owns the gesture, so the photo cannot move twice.
  final bool panEnabled;

  /// The photo. Laid out at the fitted size, so it should fill its box.
  final Widget child;

  /// Reported whenever the zoom state crosses [ViewerZoom.zoomedAt].
  final ValueChanged<bool>? onZoomChanged;

  /// Mirrors [ViewerZoom.atTopEdge] for the pull-to-dismiss gesture.
  final ValueNotifier<bool>? atTopEdge;

  /// Single tap in viewport coordinates (the caller applies its own
  /// single/double-tap timing).
  final ValueChanged<Offset>? onTapAt;

  /// Forwarded to the page-swipe protocol, exactly as before.
  final void Function(ScaleStartDetails)? onScaleStart;
  final void Function(ScaleUpdateDetails)? onScaleUpdate;
  final void Function(ScaleEndDetails)? onScaleEnd;

  const ZoomableViewport({
    super.key,
    required this.controller,
    required this.child,
    this.contentSize,
    this.fallbackAspect,
    this.panEnabled = true,
    this.onZoomChanged,
    this.atTopEdge,
    this.onTapAt,
    this.onScaleStart,
    this.onScaleUpdate,
    this.onScaleEnd,
  });

  @override
  State<ZoomableViewport> createState() => ZoomableViewportState();
}

class ZoomableViewportState extends State<ZoomableViewport> {
  /// Cached from the last layout; gesture handlers run outside build, and the
  /// viewport only ever changes through layout.
  Size _viewport = Size.zero;
  bool _wasZoomed = false;
  double _gestureStartScale = 1;
  Offset _lastFocal = Offset.zero;

  Size get _content => _geometryContent ?? _viewport;

  /// The box the photo really occupies: true pixels when they are known, else
  /// the cheaper aspect ratio, else the viewport.
  Size? get _geometryContent {
    final px = widget.contentSize;
    if (px != null && !px.isEmpty) return px;
    final a = widget.fallbackAspect;
    if (a != null && a > 0) return Size(a, 1);
    return null;
  }

  double get _scale => ViewerZoom.scaleOf(widget.controller.value);

  bool get _isZoomed => _scale > ViewerZoom.zoomedAt;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onControllerChanged);
    _wasZoomed = _isZoomed;
    WidgetsBinding.instance.addPostFrameCallback((_) => _publishEdgeState());
  }

  @override
  void didUpdateWidget(covariant ZoomableViewport oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller.removeListener(_onControllerChanged);
      widget.controller.addListener(_onControllerChanged);
      _wasZoomed = _isZoomed;
    }
    if (oldWidget.contentSize != widget.contentSize ||
        oldWidget.fallbackAspect != widget.fallbackAspect) {
      // The decoded size arrived: re-clamp what the old geometry allowed.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          _apply(_scale, ViewerZoom.translationOf(widget.controller.value));
        }
      });
    }
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onControllerChanged);
    super.dispose();
  }

  /// The controller is the source of truth for the matrix, so every write —
  /// gesture, chrome button, reset — has to repaint this viewport and refresh
  /// the edge flag. (The child widget instance is unchanged, so the subtree
  /// below the transform is not rebuilt.)
  void _onControllerChanged() {
    _publishEdgeState();
    if (mounted) setState(() {});
  }

  // ── Zoom commands (used by the viewer chrome and the info sheet) ──

  /// Zoom by [factor] about the middle of the viewport — what a zoom button
  /// means. (Zooming about the fitted rect's origin would slide the photo.)
  void zoomBy(double factor) =>
      zoomAt(_viewport.center(Offset.zero), _scale * factor);

  /// 1:1 — one image pixel per logical pixel.
  void zoomToActualSize() {
    final px = widget.contentSize;
    if (px == null) return;
    final target = ViewerZoom.actualSizeScale(viewport: _viewport, content: px);
    zoomAt(_viewport.center(Offset.zero), target);
  }

  /// Zoom to [scale] keeping [focalPoint] (viewport coordinates) in place.
  void zoomAt(Offset focalPoint, double scale) {
    final m = ViewerZoom.zoomAbout(
      current: widget.controller.value,
      viewport: _viewport,
      content: _content,
      factor: scale / _scale,
      focalPoint: focalPoint,
    );
    _write(m);
  }

  void reset() => _apply(1, Offset.zero);

  double get scale => _scale;

  /// True when one image pixel is at least one logical pixel — below that the
  /// "1:1" affordance would do nothing.
  bool get canShowActualSize {
    final px = widget.contentSize;
    if (px == null) return false;
    return ViewerZoom.actualSizeScale(viewport: _viewport, content: px) >
        ViewerZoom.zoomedAt;
  }

  void _apply(double scale, Offset translation) {
    _write(
      ViewerZoom.matrixFor(
        viewport: _viewport,
        content: _content,
        scale: scale.clamp(1.0, ViewerZoom.maxScale),
        translation: translation,
      ),
    );
  }

  void _write(Matrix4 m) {
    widget.controller.value = m;
    _publishZoom();
  }

  void _publishZoom() {
    if (_isZoomed != _wasZoomed) {
      _wasZoomed = _isZoomed;
      widget.onZoomChanged?.call(_isZoomed);
    }
  }

  void _publishEdgeState() {
    widget.atTopEdge?.value = ViewerZoom.atTopEdge(widget.controller.value);
  }

  // ── Gestures ──────────────────────────────────────────────────────

  void _onScaleStart(ScaleStartDetails d) {
    _gestureStartScale = _scale;
    _lastFocal = d.localFocalPoint;
    widget.onScaleStart?.call(d);
  }

  void _onScaleUpdate(ScaleUpdateDetails d) {
    final focal = d.localFocalPoint;
    final pinching = d.pointerCount > 1;
    if (pinching || (widget.panEnabled && _scale > ViewerZoom.zoomedAt)) {
      var translation = ViewerZoom.translationOf(widget.controller.value);
      // Follow the fingers (a pinch focal point moves as well as spreads).
      translation += focal - _lastFocal;
      final target = (_gestureStartScale * d.scale).clamp(
        1.0,
        ViewerZoom.maxScale,
      );
      final k = _scale <= 0 ? 1.0 : target / _scale;
      translation = focal - (focal - translation) * k;
      _apply(target, translation);
    }
    _lastFocal = focal;
    // The page-swipe protocol runs regardless: it reads the global focal
    // point and moves the pager only when this page is at rest.
    widget.onScaleUpdate?.call(d);
  }

  void _onScaleEnd(ScaleEndDetails d) {
    widget.onScaleEnd?.call(d);
  }

  void _onPointerSignal(PointerSignalEvent event) {
    if (event is! PointerScrollEvent) return;
    if (event.scrollDelta.dy == 0) return;
    final factor = event.scrollDelta.dy < 0 ? 1.15 : 1 / 1.15;
    zoomAt(event.localPosition, (_scale * factor).clamp(1.0, ViewerZoom.maxScale));
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (ctx, constraints) {
        _viewport = Size(constraints.maxWidth, constraints.maxHeight);
        final content = _content;
        final fitted = ViewerZoom.fitContain(_viewport, content);
        // Re-derive from the controller every build: it is the source of
        // truth, and re-deriving also re-clamps after a size change.
        final matrix = ViewerZoom.matrixFor(
          viewport: _viewport,
          content: content,
          scale: _scale,
          translation: ViewerZoom.translationOf(widget.controller.value),
        );
        return ClipRect(
          child: Listener(
            onPointerSignal: _onPointerSignal,
            child: GestureDetector(
              behavior: HitTestBehavior.opaque,
              onScaleStart: _onScaleStart,
              onScaleUpdate: _onScaleUpdate,
              onScaleEnd: _onScaleEnd,
              onTapUp: widget.onTapAt == null
                  ? null
                  : (d) => widget.onTapAt!(d.localPosition),
              child: Stack(
                clipBehavior: Clip.none,
                children: [
                  Positioned(
                    left: 0,
                    top: 0,
                    width: fitted.width,
                    height: fitted.height,
                    child: Transform(
                      transform: matrix,
                      alignment: Alignment.topLeft,
                      child: widget.child,
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}
