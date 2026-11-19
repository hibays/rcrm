// widgets/preview_surface.dart
// The whole inline-preview stack, as a PURE VIEW of an injected frame-ready
// boolean. Layering (bottom -> top), all fixed indices so nothing remounts:
//
//   0  poster            persistent still, IgnorePointer so taps pass through
//   1  fading video      AnimatedOpacity 0 -> 1 once a frame is ready
//   2  tap surface       full-card navigation / menu hits
//   3  seek strip        the preview's own progress control
//
// The poster is the bottom layer, NOT the video's fill: until the video fades
// in, the viewer sees the poster (the same image as the video's first frame),
// so there is never a black/background gap. The Video carries a transparent
// fill so any letterboxing also shows the poster rather than media_kit's black.
// Everything sits behind one stable ExcludeSemantics boundary (Windows AXTree).

import 'dart:async';

import 'package:material_ui/material_ui.dart';
import 'package:media_kit/media_kit.dart';

import '../config/theme.dart';
import 'media_item_menu.dart';
import 'player_scrub_bar.dart';

/// Long enough to cover the reveal without feeling sluggish.
const Duration kPreviewRevealDuration = Duration(milliseconds: 220);

/// Height of the seek strip laid over the card's bottom. The card's title strip
/// and duration chip step above it while previewing.
const double kPreviewStripHeight = 20.0;

class PreviewSurface extends StatelessWidget {
  /// True once the video has a decoded frame; drives the fade-in.
  final bool frameReady;

  /// Whether a preview is active. When false the video snaps back to transparent
  /// (Duration.zero) so ending a preview never fades in from nothing.
  final bool active;

  /// The persistent still frame — the bottom layer.
  final Widget poster;

  /// The media_kit `Video` (transparent fill), or a test stand-in.
  final Widget video;

  /// Shared preview player for the seek strip. Null in widget tests.
  final Player? player;

  /// Whether to show the seek strip (tests pass false; caller gates on player).
  final bool withSeek;

  /// Seek strip position from the card bottom (above the 36dp title strip).
  final double stripBottom;

  final VoidCallback? onTap;
  final void Function(Offset globalPosition)? onMenu;

  const PreviewSurface({
    super.key,
    required this.frameReady,
    required this.active,
    required this.poster,
    required this.video,
    this.player,
    this.withSeek = true,
    this.stripBottom = 0,
    this.onTap,
    this.onMenu,
  });

  @override
  Widget build(BuildContext context) => ExcludeSemantics(
    child: Stack(
      fit: StackFit.expand,
      children: [
        // index 0: persistent still, behind everything.
        IgnorePointer(child: poster),
        // index 1: video fades IN over the poster once a frame is ready.
        AnimatedOpacity(
          opacity: active && frameReady ? 1.0 : 0.0,
          duration: active ? kPreviewRevealDuration : Duration.zero,
          child: video,
        ),
        // index 2: full-card tap/menu surface (used to stop at the top 2/3 only
        // so media_kit's native controls got the bottom — those are gone now).
        Positioned.fill(
          child: GestureDetector(
            behavior: HitTestBehavior.translucent,
            onTap: onTap,
            onLongPressStart: onMenu == null
                ? null
                : (d) => requestItemMenu(onMenu, d.globalPosition, haptic: true),
            onSecondaryTapDown: onMenu == null
                ? null
                : (d) => requestItemMenu(onMenu, d.globalPosition),
          ),
        ),
        // index 3: the preview's own seek strip, when a player is available.
        if (withSeek && player != null)
          Positioned(
            left: 0,
            right: 0,
            bottom: stripBottom,
            child: PreviewControls(player: player!),
          )
        else
          const SizedBox.shrink(),
      ],
    ),
  );
}

/// Compact scrub style for the thumbnail-sized seek strip.
const kPreviewScrubStyle = ScrubBarStyle(track: 2.5, trackActive: 4, thumb: 4);

/// The preview's own progress control: the app's one [PlayerScrubBar] at
/// thumbnail scale, in the fixed dark-over-video tokens the player chrome uses.
/// It lives entirely inside PreviewSurface's ExcludeSemantics boundary, so its
/// Slider and focus nodes never reach the Windows accessibility bridge.
class PreviewControls extends StatefulWidget {
  final Player player;

  const PreviewControls({super.key, required this.player});

  @override
  State<PreviewControls> createState() => _PreviewControlsState();
}

class _PreviewControlsState extends State<PreviewControls> {
  StreamSubscription<Duration>? _positionSub;
  StreamSubscription<Duration>? _durationSub;
  Duration _position = Duration.zero;
  Duration _duration = Duration.zero;

  @override
  void initState() {
    super.initState();
    _position = widget.player.state.position;
    _duration = widget.player.state.duration;
    _positionSub = widget.player.stream.position.listen((d) {
      if (mounted) setState(() => _position = d);
    });
    _durationSub = widget.player.stream.duration.listen((d) {
      if (mounted) setState(() => _duration = d);
    });
  }

  @override
  void dispose() {
    _positionSub?.cancel();
    _durationSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final ms = _duration.inMilliseconds;
    final fraction = ms > 0
        ? (_position.inMilliseconds / ms).clamp(0.0, 1.0)
        : 0.0;
    return SizedBox(
      height: kPreviewStripHeight,
      child: DecoratedBox(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Colors.transparent, RCrmColors.playerScrim],
          ),
        ),
        child: PlayerScrubBar(
          value: fraction,
          style: kPreviewScrubStyle,
          activeColor: RCrmColors.playerAccent,
          thumbColor: RCrmColors.playerAccent,
          inactiveColor: RCrmColors.playerTrack,
          // No tooltip: a label pill would overflow this tiny card.
          onChanged: ms > 0
              ? (v) =>
                    widget.player.seek(Duration(milliseconds: (v * ms).round()))
              : null,
        ),
      ),
    );
  }
}
