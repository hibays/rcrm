import 'dart:async';
import 'package:flutter/material.dart';

class MarqueeText extends StatefulWidget {
  final String text;
  final TextStyle? style;
  final double velocity;
  final double blankSpace;
  final Duration pauseAfterRound;
  final Duration startAfter;
  final CrossAxisAlignment crossAxisAlignment;

  /// Fraction of the travel used for the eased ramp-up at the start and
  /// ramp-down at the end. The middle portion scrolls at constant velocity.
  /// 0.0 = always linear (hard start/stop); higher = softer, slower ends.
  final double easeFraction;

  const MarqueeText({
    super.key,
    required this.text,
    this.style,
    this.velocity = 50.0,
    this.blankSpace = 40.0,
    this.pauseAfterRound = const Duration(seconds: 1),
    this.startAfter = Duration.zero,
    this.crossAxisAlignment = CrossAxisAlignment.center,
    this.easeFraction = 0.35,
  });

  @override
  State<MarqueeText> createState() => _MarqueeTextState();
}

class _MarqueeTextState extends State<MarqueeText>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl = AnimationController(
    vsync: this,
    duration: Duration.zero,
  );
  late Animation<double> _anim = const AlwaysStoppedAnimation(0);
  final GlobalKey _firstTextKey = GlobalKey();
  bool _overflow = false;
  bool _disposed = false;
  bool _running = false;
  // Precise on-screen width of one copy, measured from the rendered widget so
  // the scroll distance exactly equals the copy-to-copy spacing (no seam).
  double _textWidth = 0;

  double get _distance => _textWidth + widget.blankSpace;
  double get _easeFraction => widget.easeFraction.clamp(0.0, 0.49);

  @override
  void initState() {
    super.initState();
    _ctrl.addStatusListener(_onStatus);
  }

  @override
  void didUpdateWidget(MarqueeText old) {
    super.didUpdateWidget(old);
    if (old.text != widget.text || old.style != widget.style) {
      _stop();
      _overflow = false;
      _textWidth = 0;
      if (mounted) setState(() {});
    }
  }

  // Decide overflow from a cheap text measurement; the exact width used for
  // the scroll distance is taken from the rendered widget (see _maybeStart).
  void _measureOverflow(double avail) {
    final tp = TextPainter(
      text: TextSpan(text: widget.text, style: widget.style),
      maxLines: 1,
      textDirection: TextDirection.ltr,
    )..layout();
    final w = tp.width;
    tp.dispose();
    final overflow = avail.isFinite && avail > 0 && w > avail;
    if (overflow != _overflow) {
      _overflow = overflow;
      if (mounted) setState(() {});
    }
  }

  void _maybeStart() {
    if (!_overflow || _running || _disposed || !mounted) return;
    // Read the real rendered width of the first copy.
    final rb = _firstTextKey.currentContext?.findRenderObject() as RenderBox?;
    if (rb == null) return; // Not laid out yet; try next frame.
    final real = rb.size.width;
    if ((real - _textWidth).abs() > 0.1) {
      _textWidth = real;
      // Width changed -> rebuild with accurate distance, then start next frame.
      if (mounted) setState(() {});
      return;
    }
    _start();
  }

  void _start() {
    if (_running || !_overflow || _distance <= 0) return;
    _running = true;
    final d = _distance;
    final ease = d * _easeFraction;
    final linear = (d - 2 * ease).clamp(0.0, d);
    final wEase = ease / d;
    final wLinear = linear / d;
    final anim = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween(
          begin: 0.0,
          end: ease,
        ).chain(CurveTween(curve: Curves.easeIn)),
        weight: wEase,
      ),
      TweenSequenceItem(
        tween: Tween(begin: ease, end: ease + linear),
        weight: wLinear,
      ),
      TweenSequenceItem(
        tween: Tween(
          begin: ease + linear,
          end: d,
        ).chain(CurveTween(curve: Curves.easeOut)),
        weight: wEase,
      ),
    ]);
    _anim = anim.animate(_ctrl);
    final ms = ((d / widget.velocity) * 1000 * 1.25).round();
    _ctrl.duration = Duration(milliseconds: ms.clamp(600, 30000));
    _ctrl.reset();
    Future.delayed(widget.startAfter, () {
      if (_running && mounted && !_disposed) _ctrl.forward();
    });
  }

  void _stop() {
    _running = false;
    _ctrl.stop();
  }

  void _onStatus(AnimationStatus s) {
    if (s == AnimationStatus.completed) {
      // Resting position is the second copy at offset -d, which is pixel-
      // identical to the first copy at offset 0 (spacing == d). Wait, then
      // resume seamlessly.
      Future.delayed(widget.pauseAfterRound, () {
        if (_running && mounted && !_disposed) {
          _ctrl.reset();
          _ctrl.forward();
        }
      });
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _running = false;
    _ctrl.dispose();
    super.dispose();
  }

  // Offscreen cards (grid without keepAlive): stop the ticker so a big grid
  // doesn't run N infinite AnimationControllers. Resume seamlessly on return.
  @override
  void deactivate() {
    _running = false;
    _ctrl.stop();
    super.deactivate();
  }

  @override
  void activate() {
    super.activate();
    if (_overflow && !_disposed) _maybeStart();
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (ctx, constraints) {
        final avail = constraints.maxWidth;
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (!mounted) return;
          _measureOverflow(avail);
          if (_overflow) _maybeStart();
        });
        if (!_overflow) {
          return Text(
            widget.text,
            style: widget.style,
            softWrap: false,
            overflow: TextOverflow.visible,
          );
        }
        final crossAlign = widget.crossAxisAlignment == CrossAxisAlignment.start
            ? Alignment.topLeft
            : widget.crossAxisAlignment == CrossAxisAlignment.end
            ? Alignment.bottomLeft
            : Alignment.centerLeft;
        return ClipRect(
          child: AnimatedBuilder(
            animation: _anim,
            builder: (_, child) {
              final d = _distance;
              if (d <= 0) return child!;
              final offset = -_anim.value;
              return Transform.translate(
                offset: Offset(offset, 0),
                child: child,
              );
            },
            child: Align(
              alignment: crossAlign,
              child: Row(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    widget.text,
                    key: _firstTextKey,
                    style: widget.style,
                    softWrap: false,
                  ),
                  SizedBox(width: widget.blankSpace),
                  Text(widget.text, style: widget.style, softWrap: false),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}
