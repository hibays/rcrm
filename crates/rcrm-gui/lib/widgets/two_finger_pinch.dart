// widgets/two_finger_pinch.dart
//
// The plumbing of a two-finger pinch over a scrollable grid — the RAW pointers,
// not the gesture arena.
//
// Why a `Listener` and not `GestureDetector(onScaleStart/Update)`: a
// `ScaleGestureRecognizer` competes with the grid's own vertical drag in the
// arena, and on a scrollable surface the drag usually wins (Flutter's own
// issue trackers carry several reports of `onScaleStart` never firing inside a
// `ListView`). A `Listener` never enters the arena, so a pinch can be READ
// without stealing the scroll. The one thing it must do is keep the grid still
// while it is being read: the builder is told when two fingers are down so the
// caller can hand the scrollable `NeverScrollableScrollPhysics` for that
// moment. Without that the grid would scroll under the fingers that are trying
// to size it.
//
// What this widget does NOT do is decide what the pinch MEANS. It reports the
// cumulative scale of the gesture and the start/end moments; the column maths
// lives in `utils/library_columns.dart` and the caller owns its own start value
// (a widget that kept one would have to be told which list is being pinched).

import 'package:flutter/gestures.dart';
import 'package:material_ui/material_ui.dart';

typedef PinchChildBuilder = Widget Function(BuildContext context, bool pinching);

class TwoFingerPinch extends StatefulWidget {
  /// Two fingers have landed and the gesture starts. Callers capture their
  /// current column count here: the scale is relative to THIS moment.
  final VoidCallback? onStart;

  /// Cumulative scale since [onStart]: 1 at the start, >1 when the fingers moved
  /// apart, <1 when they came together. Never zero and never non-finite.
  final ValueChanged<double> onScale;

  /// The gesture ended (a finger lifted). The caller persists whatever it
  /// changed live.
  final VoidCallback? onEnd;

  /// Builds the surface. [pinching] is true while two fingers are driving it.
  final PinchChildBuilder builder;

  const TwoFingerPinch({
    super.key,
    required this.onScale,
    required this.builder,
    this.onStart,
    this.onEnd,
  });

  @override
  State<TwoFingerPinch> createState() => _TwoFingerPinchState();
}

class _TwoFingerPinchState extends State<TwoFingerPinch> {
  /// The pointers currently down, in the order they landed. Only the first two
  /// are the gesture; a third finger changes nothing (a resting thumb must not
  /// rescale the grid).
  final Map<int, Offset> _points = <int, Offset>{};

  /// The two pointers that ARE the gesture. A third finger is tracked (so lifting
  /// it changes nothing) but is not part of the span and must not end it.
  final List<int> _pair = <int>[];

  bool _active = false;
  double _startSpan = 0;

  /// A trackpad pinch arrives as a pointer PAN/ZOOM, not as two touch pointers.
  /// It is only taken up once its scale really deviates from 1: a two-finger
  /// trackpad scroll is the same event with scale 1, and that one belongs to the
  /// scrollable.
  bool _panZoom = false;

  double get _span {
    final first = _points.values.first;
    final second = _points.values.elementAt(1);
    return (first - second).distance;
  }

  void _down(PointerDownEvent e) {
    if (_points.isEmpty) {
      // A fresh set of pointers cannot inherit the last gesture's state.
      _active = false;
      _startSpan = 0;
    }
    _points[e.pointer] = e.localPosition;
    if (_active || _points.length != 2) return;
    final span = _span;
    if (!span.isFinite || span <= 0) return;
    _startSpan = span;
    _pair
      ..clear()
      ..addAll(_points.keys.take(2));
    setState(() => _active = true);
    widget.onStart?.call();
  }

  void _move(PointerMoveEvent e) {
    if (!_points.containsKey(e.pointer)) return;
    _points[e.pointer] = e.localPosition;
    _report();
  }

  void _report() {
    if (!_active || _panZoom || _points.length < 2) return;
    if (!_startSpan.isFinite || _startSpan <= 0) return;
    final scale = _span / _startSpan;
    if (!scale.isFinite || scale <= 0) return;
    widget.onScale(scale);
  }

  void _up(PointerEvent e) {
    final wasInPair = _pair.contains(e.pointer);
    _points.remove(e.pointer);
    if (!_active || !wasInPair) return;
    // Releasing EITHER of the two fingers ends the gesture. Continuing with the
    // surviving one would map a single-finger drag onto the columns, which is a
    // scroll that suddenly resizes the grid. A third finger lifting is not that
    // — the pair is still down and still spans the grid.
    _end();
  }

  void _end() {
    _panZoom = false;
    _startSpan = 0;
    _pair.clear();
    if (!_active) return;
    setState(() => _active = false);
    widget.onEnd?.call();
  }

  void _panZoomStart(PointerPanZoomStartEvent e) {
    // Nothing yet: see _panZoomUpdate.
  }

  void _panZoomUpdate(PointerPanZoomUpdateEvent e) {
    final scale = e.scale;
    if (!scale.isFinite || scale <= 0) return;
    if (!_panZoom) {
      // 1% is the point at which this is a pinch and not the two-finger scroll
      // that shares the same event shape.
      if ((scale - 1).abs() < 0.01) return;
      _panZoom = true;
      setState(() => _active = true);
      widget.onStart?.call();
    }
    widget.onScale(scale);
  }

  void _panZoomEnd(PointerPanZoomEndEvent e) {
    if (!_panZoom) return;
    _end();
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      // The Listener must be hit-testable in its own right: its child is a
      // scrollable in the app but may be a non-hit-testing widget (an empty
      // state, a test's SizedBox), and `deferToChild` would then never see a
      // pointer at all.
      behavior: HitTestBehavior.translucent,
      onPointerDown: _down,
      onPointerMove: _move,
      onPointerUp: _up,
      onPointerCancel: _up,
      onPointerPanZoomStart: _panZoomStart,
      onPointerPanZoomUpdate: _panZoomUpdate,
      onPointerPanZoomEnd: _panZoomEnd,
      child: widget.builder(context, _active),
    );
  }
}