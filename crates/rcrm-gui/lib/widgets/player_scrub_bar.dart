// widgets/player_scrub_bar.dart
// The player's one draggable bar — the progress control and the volume slider
// are this same widget at two sizes.
//
// Material's `Slider` is already the right INPUT: tap anywhere on the bar to
// jump there, drag to scrub, arrow keys when it holds focus, semantics for
// free. What it is not is a player's progress bar, and that is the half this
// file supplies:
//
//  * **No thumb at rest.** A settings slider has a knob you grab; a progress
//    bar is a readout first. The thumb appears while the pointer is on the bar
//    or a drag is running, and the track thickens at the same time (3 -> 6dp):
//    that is what lets a thin line be both unobtrusive on a paused frame and
//    easy to hit.
//  * **A time tooltip follows the pointer down to the pixel**, with a 1px
//    guide line through the bar. "What is at this x?" is the one question a
//    progress bar cannot answer on its own, and it is the difference between
//    scrubbing to roughly there and scrubbing to there.
//
// ## The geometry is a pure function, and it does not move
//
// Flutter lays a Slider's track out with `BaseSliderTrackShape.getPreferredRect`:
//
//     trackLeft  = max(thumbWidth, overlayWidth) / 2
//     trackWidth = boxWidth - max(thumbWidth, overlayWidth)
//
// so the pointer-to-value mapping depends on the sizes of the two shapes this
// widget ANIMATES. Growing the thumb radius out of nothing would therefore move
// both ends of the track — and the value under a stationary pointer — while the
// hover plays. The overlay is instead pinned at `kOverlayRatio` times the thumb
// radius and only its ALPHA animates, which keeps `max(thumbWidth,
// overlayWidth)` equal to the overlay's width at every frame. The track's ends
// never move, [ScrubBarGeometry] is exact for every frame of the animation
// rather than only at its ends, and it is unit-tested as the arithmetic it is.
//
// (Flutter 3.47 can pin the track to the full box instead, with
// `SliderThemeData.padding` — the mapping then needs no reconstruction at all.
// Not used here: it would raise this crate's floor above the 3.44 in the
// version matrix to save arithmetic that is tested.)

import 'package:flutter/gestures.dart' show PointerDeviceKind;
import 'package:flutter/material.dart';

import '../config/theme.dart';

/// How much wider the hover/focus halo is than the thumb it sits behind.
///
/// Anything > 1 keeps `max(thumbWidth, overlayWidth)` on the overlay's side for
/// the whole 0..1 thumb animation, which is what makes the track geometry a
/// constant. See the file header.
const double kScrubOverlayRatio = 1.6;

/// Track and thumb sizes for one bar, in the density the bar was given.
///
/// [track] is the resting thickness and [trackActive] the thickness while the
/// bar is engaged — the same pairing a video.js progress bar has, where the
/// holder is `0.3em` tall and grows to `0.5em` under the cursor.
@immutable
class ScrubBarStyle {
  final double track;
  final double trackActive;

  /// Thumb radius when the bar is engaged. The resting radius is always 0.
  final double thumb;

  const ScrubBarStyle({
    required this.track,
    required this.trackActive,
    required this.thumb,
  });

  ScrubBarStyle copyWith({double? track, double? trackActive, double? thumb}) =>
      ScrubBarStyle(
        track: track ?? this.track,
        trackActive: trackActive ?? this.trackActive,
        thumb: thumb ?? this.thumb,
      );

  /// Width the track gives up, [kScrubOverlayRatio] radii at each end.
  double get inset => thumb * kScrubOverlayRatio;
}

/// Where the track really is inside a bar's box, and the pointer <-> value
/// mapping that follows from it.
///
/// Pure on purpose: the tooltip's position and the value a drag reports have to
/// agree, and both are derived from here rather than from two copies of the
/// same arithmetic.
@immutable
class ScrubBarGeometry {
  /// Left edge of the track, in the bar's own coordinates.
  final double left;

  /// Width of the track. Never negative — a bar narrower than its own halo
  /// still has to lay out, and `Rect.fromLTRB` flipping the edges (which is
  /// what `getPreferredRect` does with a negative width) is not something the
  /// rest of this file should have to model.
  final double width;

  const ScrubBarGeometry(this.left, this.width);

  factory ScrubBarGeometry.of(double boxWidth, ScrubBarStyle style) {
    final inset = style.inset;
    if (boxWidth <= inset) return ScrubBarGeometry(boxWidth / 2, 0);
    return ScrubBarGeometry(inset / 2, boxWidth - inset);
  }

  /// The value a pointer at [x] sits on, as a 0..1 fraction of the track.
  double fractionAt(double x) =>
      width <= 0 ? 0 : ((x - left) / width).clamp(0.0, 1.0);

  /// Where [fraction] sits, in the bar's own coordinates.
  double xOf(double fraction) => left + fraction.clamp(0.0, 1.0) * width;
}

/// A progress/volume bar: a thin line at rest that comes alive under the
/// pointer, with the time (or percentage) under the cursor above it.
///
/// The caller owns [min]/[max] and the meaning of the value, so the progress
/// control keeps its 0..1 fraction and the volume slider its 0..100 — the
/// width budget and the existing tests both speak those units.
class PlayerScrubBar extends StatefulWidget {
  final double value;

  /// Buffered end, in the same units as [value]. Null means nothing is
  /// buffered ahead of the playhead, which is not the same as zero.
  final double? buffer;

  final double min;
  final double max;

  final ScrubBarStyle style;

  /// The played part — the one thing on the bar that is the accent colour.
  final Color activeColor;
  final Color thumbColor;
  final Color? inactiveColor;
  final Color? bufferColor;

  /// Text for the tooltip and for the slider's accessibility value, given a
  /// value in [min]..[max]. Null means no tooltip at all (a bar whose value is
  /// not worth reading out).
  final String Function(double value)? label;

  /// Spoken name of the control, e.g. "Playback position".
  final String? semanticsLabel;

  /// A drag beginning/ending, with the same units as [value]. Optional; a null
  /// pair means the bar cannot be dragged at all, not that it is silent.
  final ValueChanged<double>? onChangeStart;
  final ValueChanged<double>? onChanged;
  final ValueChanged<double>? onChangeEnd;

  const PlayerScrubBar({
    super.key,
    required this.value,
    required this.style,
    required this.activeColor,
    required this.thumbColor,
    this.buffer,
    this.min = 0,
    this.max = 1,
    this.inactiveColor,
    this.bufferColor,
    this.label,
    this.semanticsLabel,
    this.onChangeStart,
    this.onChanged,
    this.onChangeEnd,
  });

  @override
  State<PlayerScrubBar> createState() => _PlayerScrubBarState();
}

class _PlayerScrubBarState extends State<PlayerScrubBar>
    with TickerProviderStateMixin {
  static const _growMs = 150;
  static const _tipMs = 120;

  /// The tooltip's way out, deliberately slower than its way in.
  static const _tipOutMs = 220;

  /// Gap between the tooltip and the top of the bar.
  static const _tipGap = 6.0;

  /// The Slider's OWN focus node, so this bar can see the keyboard land on it
  /// and give the track the same engaged look a hover does. Without it a Tab
  /// into the seek bar would leave nothing on screen to say where the focus is.
  final _focus = FocusNode(debugLabel: 'PlayerScrubBar');
  late final _grow = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: _growMs),
  );
  late final _tip = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: _tipMs),
  );

  bool _hovering = false;

  /// Where the tooltip is anchored, in the bar's own coordinates. Null until a
  /// pointer has ever been on the bar.
  ///
  /// Deliberately NOT cleared when the pointer leaves: the tooltip fades out
  /// over [_tipMs], and dropping the anchor with the pointer would make it jump
  /// to the playhead on its way out.
  double? _pointerX;

  /// True while a contact is on the bar — a finger, or a held mouse button.
  bool _dragging = false;

  /// Whether the bar can be dragged at all. A disabled bar never grows and
  /// never annotates itself: video.js's own skin does the same
  /// (`.vjs-progress-holder.disabled { font-size: 1em }`), because an enlarged
  /// track under the cursor is a promise of interactivity and a bar with no
  /// duration to seek within cannot keep it.
  bool get _interactive => widget.onChanged != null;

  bool get _engaged =>
      _interactive && (_hovering || _dragging || _focus.hasFocus);
  bool get _wantsTip =>
      widget.label != null &&
      _interactive &&
      (_hovering || _dragging) &&
      _pointerX != null;

  @override
  void initState() {
    super.initState();
    _focus.addListener(_sync);
  }

  @override
  void dispose() {
    _focus.removeListener(_sync);
    _focus.dispose();
    _grow.dispose();
    _tip.dispose();
    super.dispose();
  }

  /// Points the two animations at what the bar is doing right now.
  ///
  /// `disableAnimations` is honoured rather than ignored: this is hover
  /// decoration, and a reader who asked the platform for no motion should not
  /// get a 150ms flourish for moving the mouse.
  ///
  /// The tooltip leaves more slowly than it arrives, so a pointer skimming
  /// across the bar does not strobe. Load-bearing the other way round too: the
  /// bar itself must feel immediate under the cursor.
  void _sync() {
    if (!mounted) return;
    final idle = MediaQuery.disableAnimationsOf(context);
    final growTo = _engaged ? 1.0 : 0.0;
    final tipTo = _wantsTip ? 1.0 : 0.0;
    if (idle) {
      _grow.value = growTo;
      _tip.value = tipTo;
      return;
    }
    _grow.animateTo(growTo, curve: Curves.easeOutCubic);
    _tip.animateTo(
      tipTo,
      duration: Duration(milliseconds: tipTo == 1.0 ? _tipMs : _tipOutMs),
      curve: Curves.easeOutCubic,
    );
  }

  void _setPointer(double? x, {required bool hovering}) {
    // A mouse move is not automatically a repaint: the pointer's POSITION only
    // matters while a readout is being shown, so a bar with no label rebuilds
    // when the pointer arrives or leaves and not once per pixel in between.
    if (hovering == _hovering && (widget.label == null || x == _pointerX)) {
      return;
    }
    setState(() {
      if (x != null) _pointerX = x;
      _hovering = hovering;
    });
    _sync();
  }

  /// A contact on the bar, from the POINTER rather than from the Slider's
  /// `onChangeStart`.
  ///
  /// The two are not the same fact: a caller may wire no start callback at all
  /// (the bar's own tests do), and the engaged look plus the drag tooltip must
  /// not silently depend on a callback that exists to announce scrubbing to
  /// somebody else.
  void _setDragging(bool dragging) {
    if (!mounted) return;
    setState(() => _dragging = dragging && _interactive);
    _sync();
  }

  /// The 0..1 fraction of the caller's range that [PlayerScrubBar.value] sits
  /// at — the form the tooltip's anchor is computed in.
  double get _fraction {
    final span = widget.max - widget.min;
    if (span <= 0) return 0;
    return ((widget.value - widget.min) / span).clamp(0.0, 1.0);
  }

  /// A 0..1 fraction back in the caller's units — what the tooltip's label
  /// function and the Slider both speak.
  double _valueAt(double fraction) =>
      widget.min + fraction * (widget.max - widget.min);

  /// Names the Slider for a reader, without adding a semantics node to every
  /// bar that has no name to give.
  Widget _labelled(Widget child) {
    final label = widget.semanticsLabel;
    if (label == null) return child;
    return Semantics(label: label, child: child);
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (ctx, c) {
        final boxWidth = c.maxWidth;
        final boxHeight = c.maxHeight.isFinite ? c.maxHeight : 32.0;
        final geometry = ScrubBarGeometry.of(boxWidth, widget.style);
        final rtl = Directionality.of(ctx) == TextDirection.rtl;

        return MouseRegion(
          onEnter: (e) => _setPointer(e.localPosition.dx, hovering: true),
          onHover: (e) => _setPointer(e.localPosition.dx, hovering: true),
          onExit: (_) => _setPointer(null, hovering: false),
          child: Listener(
            // The pointer's own position, not the thumb's: during a touch drag
            // there is no hover to read, and the painted thumb is inset from
            // the track's ends by the rounded-track clamp, so anchoring to it
            // would let the tooltip drift away from the finger.
            onPointerDown: (e) {
              _setPointer(e.localPosition.dx, hovering: _hovering);
              _setDragging(true);
            },
            onPointerMove: (e) =>
                _setPointer(e.localPosition.dx, hovering: _hovering),
            onPointerUp: (e) {
              _setDragging(false);
              // A touch has no hover to fall back on once it lifts, so the bar
              // goes back to its resting state here; a mouse keeps the pointer.
              if (e.kind != PointerDeviceKind.mouse) {
                _setPointer(null, hovering: false);
              }
            },
            onPointerCancel: (e) {
              _setDragging(false);
              _setPointer(null, hovering: false);
            },
            child: AnimatedBuilder(
              animation: Listenable.merge([_grow, _tip]),
              builder: (_, _) {
                final t = _grow.value;
                final engaged = Curves.easeOutCubic.transform(t);
                final tipT = Curves.easeOutCubic.transform(_tip.value);
                final anchorX = _pointerX != null
                    ? geometry.fractionAt(_pointerX!)
                    : _fraction;
                final anchor = geometry.xOf(rtl ? 1 - anchorX : anchorX);

                return Stack(
                  // The tooltip is painted ABOVE this box; the Stack is told
                  // not to cut it off.
                  clipBehavior: Clip.none,
                  children: [
                    SliderTheme(
                      data: SliderThemeData(
                        trackHeight: _lerp(
                          widget.style.track,
                          widget.style.trackActive,
                          engaged,
                        ),
                        // A player's played and remaining parts are the SAME
                        // thickness; Material's default grows the played part
                        // by `additionalActiveTrackHeight` (2dp), which on a
                        // 3dp track is the whole personality of the control.
                        trackShape: const _PlayerTrackShape(),
                        thumbShape: RoundSliderThumbShape(
                          enabledThumbRadius: widget.style.thumb * engaged,
                          disabledThumbRadius: widget.style.thumb * engaged,
                        ),
                        overlayShape: RoundSliderOverlayShape(
                          overlayRadius:
                              widget.style.thumb * kScrubOverlayRatio,
                        ),
                        activeTrackColor: widget.activeColor,
                        inactiveTrackColor:
                            widget.inactiveColor ?? RCrmColors.silverDim,
                        secondaryActiveTrackColor:
                            widget.bufferColor ?? const Color(0x59FFFFFF),
                        thumbColor: widget.thumbColor,
                        // The halo's SIZE is fixed (see the file header); its
                        // arrival is what animates.
                        overlayColor: widget.thumbColor.withValues(
                          alpha: 0.16 * engaged,
                        ),
                        disabledActiveTrackColor: widget.activeColor.withValues(
                          alpha: 0.38,
                        ),
                        disabledInactiveTrackColor:
                            widget.inactiveColor ?? RCrmColors.silverDim,
                        disabledSecondaryActiveTrackColor:
                            widget.bufferColor ?? const Color(0x59FFFFFF),
                        disabledThumbColor: widget.thumbColor.withValues(
                          alpha: 0.38,
                        ),
                      ),
                      // The Slider carries the VALUE; the name is this
                      // ancestor's, because `Slider` has nowhere to put one —
                      // and only when there is one, so the common case has no
                      // extra semantics node in the tree at all.
                      child: _labelled(
                        Slider(
                          focusNode: _focus,
                          // The Slider speaks the CALLER's units — a 0..1
                          // fraction for progress, 0..100 for volume — so its
                          // value, its callbacks and its accessibility text are
                          // all the same number the caller already reasons in.
                          // Only the tooltip's anchor needs the 0..1 form.
                          value: widget.value.clamp(widget.min, widget.max),
                          min: widget.min,
                          max: widget.max,
                          secondaryTrackValue: widget.buffer?.clamp(
                            widget.min,
                            widget.max,
                          ),
                          // Passed straight through: a null `onChanged` is
                          // what makes the Slider refuse the touch, and the
                          // bar's own engaged state comes from the pointer, not
                          // from these.
                          onChangeStart: widget.onChangeStart,
                          onChanged: widget.onChanged,
                          onChangeEnd: widget.onChangeEnd,
                          semanticFormatterCallback: (v) =>
                              widget.label?.call(v) ?? '',
                        ),
                      ),
                    ),
                    if (tipT > 0.001) ...[
                      Positioned(
                        left: anchor - 0.5,
                        top: 0,
                        height: boxHeight,
                        child: IgnorePointer(
                          child: Opacity(
                            opacity: tipT * 0.45,
                            child: const SizedBox(
                              width: 1,
                              child: ColoredBox(color: Colors.white),
                            ),
                          ),
                        ),
                      ),
                      Positioned.fill(
                        child: IgnorePointer(
                          child: CustomSingleChildLayout(
                            delegate: _TipLayout(anchorX: anchor),
                            child: Opacity(
                              opacity: tipT,
                              child: Padding(
                                // The delegate lands the child's box on the
                                // bar's top edge; the gap is padding so the
                                // pill's shadow has somewhere to paint.
                                padding: const EdgeInsets.only(bottom: _tipGap),
                                child: _Tooltip(
                                  // The tooltip reads in the caller's units,
                                  // like the Slider it annotates.
                                  text: widget.label!(_valueAt(anchorX)),
                                ),
                              ),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ],
                );
              },
            ),
          ),
        );
      },
    );
  }

  static double _lerp(double a, double b, double t) => a + (b - a) * t;
}

/// `RoundedRectSliderTrackShape` with Material's thicker played segment turned
/// off, so the played, buffered and remaining parts of the bar are one line of
/// one weight. `additionalActiveTrackHeight` is a paint-time argument rather
/// than a theme field, so this is the only way to say so.
class _PlayerTrackShape extends RoundedRectSliderTrackShape {
  const _PlayerTrackShape();

  @override
  void paint(
    PaintingContext context,
    Offset offset, {
    required RenderBox parentBox,
    required SliderThemeData sliderTheme,
    required Animation<double> enableAnimation,
    required TextDirection textDirection,
    required Offset thumbCenter,
    Offset? secondaryOffset,
    bool isDiscrete = false,
    bool isEnabled = false,
    double additionalActiveTrackHeight = 2,
  }) {
    super.paint(
      context,
      offset,
      parentBox: parentBox,
      sliderTheme: sliderTheme,
      enableAnimation: enableAnimation,
      textDirection: textDirection,
      thumbCenter: thumbCenter,
      secondaryOffset: secondaryOffset,
      isDiscrete: isDiscrete,
      isEnabled: isEnabled,
      additionalActiveTrackHeight: 0,
    );
  }
}

/// Centres the tooltip on the pointer and keeps it inside the bar, lifting it
/// clear of the bar's own box.
class _TipLayout extends SingleChildLayoutDelegate {
  final double anchorX;

  const _TipLayout({required this.anchorX});

  @override
  BoxConstraints getConstraintsForChild(BoxConstraints constraints) =>
      BoxConstraints.loose(Size(constraints.maxWidth, double.infinity));

  @override
  Offset getPositionForChild(Size size, Size child) {
    final maxX = size.width - child.width;
    final x = maxX <= 0 ? 0.0 : (anchorX - child.width / 2).clamp(0.0, maxX);
    return Offset(x, -child.height);
  }

  @override
  bool shouldRelayout(_TipLayout old) => old.anchorX != anchorX;
}

class _Tooltip extends StatelessWidget {
  final String text;

  const _Tooltip({required this.text});

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: const Color(0xF20E0E0E),
        borderRadius: BorderRadius.circular(RCrmRadii.sm),
        // Flat by default applies to surfaces at REST. This one exists only
        // while a pointer is on the bar, over video of any brightness.
        boxShadow: const [
          BoxShadow(
            color: Color(0x66000000),
            blurRadius: 8,
            offset: Offset(0, 2),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        child: Text(
          text,
          maxLines: 1,
          softWrap: false,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 11.5,
            fontWeight: FontWeight.w500,
            // Digits that keep their width, so the tooltip does not twitch as
            // the numbers change under a moving pointer.
            fontFeatures: [FontFeature.tabularFigures()],
          ),
        ),
      ),
    );
  }
}
