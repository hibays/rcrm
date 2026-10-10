// widgets/player_controls.dart
// Video-player chrome: the bottom transport bar, the fullscreen top bar, the
// 2x badge and the brightness/volume gesture chip.
//
// These are pure presentation widgets. Playback state lives in the screen
// (screens/video_player_screen.dart) inside ValueNotifiers and is passed down,
// so the chrome never subscribes to a Player and can be laid out — and
// golden-tested — without a media backend.
//
// Width is the scarcest resource in a player: a portrait phone has ~360dp and
// a landscape phone ~640dp while the video wants all of it. The bar therefore
// plans itself against a measured width budget (planPlayerControlBar) instead
// of scaling everything up in fullscreen. Optional controls are admitted by
// priority; the volume slider is admitted LAST, from whatever is left over,
// and disappears (leaving its mute button) when that leftover is too small to
// drag. Nothing is ever squeezed or silently overflowed.

import 'dart:math' as math;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';

import '../config/theme.dart';
import '../utils/format.dart';

// ── Density ─────────────────────────────────────────────────────────

/// Control density for a size class — the player's answer to "how much room do
/// I actually have", never "am I fullscreen".
///
/// The compact tier is what a landscape phone (640x360dp) and a narrow desktop
/// window get: the same controls at a smaller tap target, not fewer controls.
@immutable
class PlayerChromeMetrics {
  /// Tap target of one icon button.
  final double tap;

  /// Icon glyph size inside a tap target.
  final double icon;

  /// Gap between neighbouring controls.
  final double gap;

  /// Horizontal padding of the bar.
  final double pad;

  /// Time-label font size.
  final double font;

  /// Height of the seek-slider row.
  final double seekHeight;

  final double trackHeight;
  final double thumbRadius;

  /// Widest the volume slider may grow when there is room to spare.
  final double volumeSliderMax;

  const PlayerChromeMetrics({
    required this.tap,
    required this.icon,
    required this.gap,
    required this.pad,
    required this.font,
    required this.seekHeight,
    required this.trackHeight,
    required this.thumbRadius,
    required this.volumeSliderMax,
  });

  static const compact = PlayerChromeMetrics(
    tap: 40,
    icon: 20,
    gap: 2,
    pad: 8,
    font: 11,
    seekHeight: 20,
    trackHeight: 3,
    thumbRadius: 5,
    volumeSliderMax: 96,
  );

  /// A bar narrower than the compact tier's floor (3 tap targets + gaps +
  /// padding = 140dp): the three unconditional controls must still fit rather
  /// than overflow. The app sets no minimum window size, so a desktop window
  /// really can be dragged this narrow, and everything optional is dropped by
  /// the plan at this width anyway.
  static const tiny = PlayerChromeMetrics(
    tap: 32,
    icon: 18,
    gap: 2,
    pad: 4,
    font: 10,
    seekHeight: 16,
    trackHeight: 3,
    thumbRadius: 4,
    volumeSliderMax: 72,
  );

  static const regular = PlayerChromeMetrics(
    tap: 40,
    icon: 22,
    gap: 4,
    pad: 12,
    font: 11.5,
    seekHeight: 22,
    trackHeight: 3,
    thumbRadius: 5,
    volumeSliderMax: 104,
  );

  static const expanded = PlayerChromeMetrics(
    tap: 44,
    icon: 22,
    gap: 6,
    pad: 16,
    font: 12,
    seekHeight: 24,
    trackHeight: 4,
    thumbRadius: 6,
    volumeSliderMax: 112,
  );

  /// Big screens in fullscreen have room to breathe: bigger targets, same bar.
  static const expandedFullscreen = PlayerChromeMetrics(
    tap: 48,
    icon: 24,
    gap: 6,
    pad: 16,
    font: 12.5,
    seekHeight: 26,
    trackHeight: 4,
    thumbRadius: 7,
    volumeSliderMax: 120,
  );

  /// Size class from the window's shortest side (the axis a landscape phone
  /// runs out of first), so the same rules serve phones, tablets and windows.
  static PlayerChromeMetrics of(Size window, {bool fullscreen = false}) {
    final shortest = window.shortestSide;
    if (shortest < 400) return compact;
    if (shortest < 600) return regular;
    return fullscreen ? expandedFullscreen : expanded;
  }

  /// Never spend more room than the bar actually got: a wide window can still
  /// hand the bar a narrow column, and the bar follows the column. Below the
  /// compact tier's floor the targets shrink once more ([tiny]); below *that*
  /// (a bar narrower than three 32dp targets + gaps + padding = 108dp) the plan
  /// starts dropping the controls that have an alternative path, so no width can
  /// overflow the row.
  PlayerChromeMetrics cappedTo(double maxWidth) {
    if (maxWidth < 140) return tiny;
    if (maxWidth < 340) return compact;
    if (maxWidth < 520 && (this == expanded || this == expandedFullscreen)) {
      return regular;
    }
    return this;
  }

  TextStyle get timeStyle => TextStyle(color: Colors.white54, fontSize: font);

  TextStyle get durationStyle =>
      TextStyle(color: Colors.white30, fontSize: font);

  /// The speed chip's label — painted AND measured with this exact style: a
  /// budget that measures a different weight than it paints is how a bar that
  /// "fits" overflows.
  TextStyle get chipStyle => TextStyle(
    color: Colors.white70,
    fontSize: font,
    fontWeight: FontWeight.w500,
  );
}

// ── Width budget ────────────────────────────────────────────────────

/// Smallest volume slider worth showing. Below this the mute button alone is
/// the better control: three icon-widths of travel cannot be aimed, and a
/// slider you cannot aim is worse than no slider.
const double kMinVolumeSliderWidth = 64;

/// What the bottom bar can afford to render at a given width.
@immutable
class PlayerControlPlan {
  final bool showPosition;
  final bool showDuration;
  final bool showPrev;
  final bool showNext;
  final bool showSpeed;
  final bool showEpisodes;

  /// The two essentials that can still be dropped when the bar is narrower than
  /// even the smallest tier's three buttons (a desktop window can be dragged to
  /// any width). Fullscreen goes first — the `F` shortcut and the title-bar
  /// button still do it — then mute, which the volume gestures and keys still
  /// do, and last the speed chip. Play/pause is the one that always stays, and
  /// it fits at any width.
  final bool showMute;
  final bool showFullscreen;

  /// 0 = no slider is budgeted (mute may itself have been dropped — see
  /// [showMute]; this field says nothing about whether it survived).
  final double volumeSliderWidth;

  /// Total width the planned controls need, including gaps and bar padding.
  final double contentWidth;

  const PlayerControlPlan({
    required this.showPosition,
    required this.showDuration,
    required this.showPrev,
    required this.showNext,
    required this.showSpeed,
    required this.showEpisodes,
    required this.volumeSliderWidth,
    required this.contentWidth,
    this.showMute = true,
    this.showFullscreen = true,
  });

  bool get showVolumeSlider => volumeSliderWidth > 0;

  @override
  String toString() =>
      'PlayerControlPlan(pos: $showPosition, dur: $showDuration, '
      'prev: $showPrev, next: $showNext, speed: $showSpeed, '
      'eps: $showEpisodes, mute: $showMute, fs: $showFullscreen, '
      'volume: $volumeSliderWidth, width: ${contentWidth.toStringAsFixed(1)})';
}

/// Chooses which controls the bar renders so that it fits [maxWidth].
///
/// Play/pause is unconditional — it is the action with no alternative path.
/// Mute, the fullscreen toggle and everything else are admitted in priority
/// order while they still fit, and the volume slider — the only control whose
/// job can be done by a neighbour — takes what remains, hiding rather than
/// shrinking into an unusable stub.
///
/// When even the three-button floor does not fit, the ladder keeps going:
/// fullscreen and then mute are dropped rather than letting the row overflow.
/// That case needs a window dragged below ~108dp, i.e. nobody's daily driver —
/// but it is reachable, and an overflow stripe is not an acceptable answer to it.
PlayerControlPlan planPlayerControlBar({
  required double maxWidth,
  required PlayerChromeMetrics m,
  required double positionWidth,
  required double durationWidth,
  required double speedWidth,
  required bool hasPrev,
  required bool hasNext,
  required bool hasEpisodes,
}) {
  double total({
    required bool position,
    required bool duration,
    required bool prev,
    required bool next,
    required bool speed,
    required bool episodes,
    double volume = 0,
    bool mute = true,
    bool fullscreen = true,
  }) {
    // Only controls that will really be painted may be budgeted for: a
    // reserved-but-absent skip button silently steals the volume slider's
    // space and then renders nothing.
    final showPrev = prev && hasPrev;
    final showNext = next && hasNext;
    final showEpisodes = episodes && hasEpisodes;
    // play/pause is always present; mute and fullscreen unless the ladder below
    // had to give them up.
    final widths = <double>[m.tap];
    if (mute) widths.add(m.tap);
    if (fullscreen) widths.add(m.tap);
    if (position) widths.add(positionWidth);
    if (duration) widths.add(durationWidth);
    if (showNext) widths.add(m.tap);
    if (showPrev) widths.add(m.tap);
    if (speed) widths.add(speedWidth);
    if (showEpisodes) widths.add(m.tap);
    if (volume > 0) widths.add(volume);
    return m.pad * 2 +
        widths.fold<double>(0, (a, b) => a + b) +
        m.gap * (widths.length - 1);
  }

  var showPosition = false;
  var showDuration = false;
  var showPrev = false;
  var showNext = false;
  var showSpeed = false;
  var showEpisodes = false;

  // Priority order: what the user needs to understand playback (time), then
  // transport (next/prev), then rate, then the episode list.
  void admit(bool Function() fits, void Function() mark) {
    if (fits()) mark();
  }

  admit(
    () =>
        total(
          position: true,
          duration: false,
          prev: false,
          next: false,
          speed: false,
          episodes: false,
        ) <=
        maxWidth,
    () => showPosition = true,
  );
  admit(
    () =>
        total(
          position: showPosition,
          duration: true,
          prev: false,
          next: false,
          speed: false,
          episodes: false,
        ) <=
        maxWidth,
    () => showDuration = true,
  );
  admit(
    () =>
        total(
          position: showPosition,
          duration: showDuration,
          prev: false,
          next: true,
          speed: false,
          episodes: false,
        ) <=
        maxWidth,
    () => showNext = true,
  );
  admit(
    () =>
        total(
          position: showPosition,
          duration: showDuration,
          prev: true,
          next: showNext,
          speed: false,
          episodes: false,
        ) <=
        maxWidth,
    () => showPrev = true,
  );
  admit(
    () =>
        total(
          position: showPosition,
          duration: showDuration,
          prev: showPrev,
          next: showNext,
          speed: true,
          episodes: false,
        ) <=
        maxWidth,
    () => showSpeed = true,
  );
  admit(
    () =>
        total(
          position: showPosition,
          duration: showDuration,
          prev: showPrev,
          next: showNext,
          speed: showSpeed,
          episodes: true,
        ) <=
        maxWidth,
    () => showEpisodes = true,
  );

  final withoutVolume = total(
    position: showPosition,
    duration: showDuration,
    prev: showPrev,
    next: showNext,
    speed: showSpeed,
    episodes: showEpisodes,
  );
  // The slider costs one more gap than the row it joins, so budget for it.
  final leftover = maxWidth - withoutVolume - m.gap;
  final volume = leftover >= kMinVolumeSliderWidth
      ? math.min(leftover, m.volumeSliderMax)
      : 0.0;

  // Last resort, narrower than even the smallest tier's three buttons: give up
  // the controls that have somewhere else to live, in the order that costs the
  // user least, so the row fits instead of painting an overflow stripe.
  var showMute = true;
  var showFullscreen = true;
  double widthWith(bool mute, bool fullscreen) => total(
    position: showPosition,
    duration: showDuration,
    prev: showPrev && hasPrev,
    next: showNext && hasNext,
    speed: showSpeed,
    episodes: showEpisodes && hasEpisodes,
    volume: volume,
    mute: mute,
    fullscreen: fullscreen,
  );
  if (widthWith(true, true) > maxWidth) {
    showFullscreen = false;
    if (widthWith(true, false) > maxWidth) showMute = false;
  }

  return PlayerControlPlan(
    showPosition: showPosition,
    showDuration: showDuration,
    showPrev: showPrev && hasPrev,
    showNext: showNext && hasNext,
    showSpeed: showSpeed,
    showEpisodes: showEpisodes && hasEpisodes,
    volumeSliderWidth: volume,
    showMute: showMute,
    showFullscreen: showFullscreen,
    contentWidth: widthWith(showMute, showFullscreen),
  );
}

// ── Bottom transport bar ────────────────────────────────────────────

class PlayerControlBar extends StatefulWidget {
  final bool playing;
  final Duration position;
  final Duration duration;
  final Duration buffer;

  /// 0..100, as media_kit reports it.
  final double volume;

  /// Current playback rate (mirrors the player, not a local guess).
  final double speed;

  /// True while the player is fullscreen (the button then exits it).
  final bool fullscreen;

  /// Safe-area insets of the surface it sits on (notch, home indicator).
  final EdgeInsets safe;

  final bool hasPrev;
  final bool hasNext;
  final bool hasEpisodes;

  final VoidCallback? onPlayPause;
  final ValueChanged<Duration>? onSeek;

  /// True when a drag on one of the bar's sliders (seek or volume) begins and
  /// false when it ends, so the screen can hold its auto-hide off: fading out
  /// the control bar — the slider under the finger included — is never what the
  /// user asked for. `false` means "the interaction has settled, start the idle
  /// countdown again", which is also how a wheel notch over the volume cluster
  /// reports itself. Optional; a bar without a listener behaves as before.
  final ValueChanged<bool>? onScrubActive;

  /// Fired once when a volume drag settles, so the caller can persist it.
  final ValueChanged<double>? onVolumeChanged;
  final VoidCallback? onVolumeChangeEnd;
  final VoidCallback? onToggleMute;
  final ValueChanged<double>? onSpeedChanged;
  final VoidCallback? onPrev;
  final VoidCallback? onNext;
  final VoidCallback? onEpisodes;
  final VoidCallback? onFullscreen;

  /// True while the speed menu is open and false when it closes, so the screen
  /// can hold its auto-hide off — a menu is a panel like the settings sheet.
  final ValueChanged<bool>? onMenuVisibilityChanged;

  const PlayerControlBar({
    super.key,
    required this.playing,
    required this.position,
    required this.duration,
    required this.buffer,
    required this.volume,
    required this.speed,
    required this.fullscreen,
    this.safe = EdgeInsets.zero,
    this.hasPrev = false,
    this.hasNext = false,
    this.hasEpisodes = false,
    this.onPlayPause,
    this.onSeek,
    this.onScrubActive,
    this.onVolumeChanged,
    this.onVolumeChangeEnd,
    this.onToggleMute,
    this.onSpeedChanged,
    this.onPrev,
    this.onNext,
    this.onEpisodes,
    this.onFullscreen,
    this.onMenuVisibilityChanged,
  });

  @override
  State<PlayerControlBar> createState() => _PlayerControlBarState();
}

class _PlayerControlBarState extends State<PlayerControlBar> {
  static const _speeds = [0.5, 0.75, 1.0, 1.25, 1.5, 2.0];

  /// Row height of one speed entry and the menu's own padding — the popup's
  /// upward offset is derived from these instead of repeating the numbers.
  static const double _speedItemHeight = 40;
  static const double _menuPadding = 16;

  /// Position the user is scrubbing to, or null when not dragging. Purely
  /// local interaction state — playback state stays in the screen.
  double? _scrub;

  static String formatSpeed(double s) =>
      s == s.roundToDouble() ? '${s.toInt()}x' : '${s}x';

  bool get _muted => widget.volume <= 0;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (ctx, constraints) {
        final window = MediaQuery.sizeOf(ctx);
        // The notch eats real estate the plan must not spend.
        final available = (constraints.maxWidth - widget.safe.horizontal).clamp(
          0.0,
          double.infinity,
        );
        final m = PlayerChromeMetrics.of(
          window,
          fullscreen: widget.fullscreen,
        ).cappedTo(available);

        final posText = formatMs(
          _scrubMs?.round() ?? widget.position.inMilliseconds,
        );
        final durText = formatMs(widget.duration.inMilliseconds);
        final speedText = formatSpeed(widget.speed);

        final plan = planPlayerControlBar(
          maxWidth: available,
          m: m,
          // Budget the wider of position/duration: scrubbing must not make
          // the bar re-plan (and re-flow) on every frame.
          positionWidth: math.max(
            _measure(ctx, posText, m.timeStyle),
            _measure(ctx, durText, m.timeStyle),
          ),
          durationWidth: _measure(ctx, ' / $durText', m.durationStyle),
          // The chip is the label plus its own horizontal padding, measured in
          // the style the chip actually paints (w500 — wider than timeStyle).
          speedWidth: _measure(ctx, speedText, m.chipStyle) + m.gap * 4 + 2,
          hasPrev: widget.hasPrev,
          hasNext: widget.hasNext,
          hasEpisodes: widget.hasEpisodes,
        );

        final duration = widget.duration.inMilliseconds.toDouble();
        final played = duration > 0
            ? (_scrubMs ?? widget.position.inMilliseconds.toDouble()) / duration
            : 0.0;

        // Both ends of a drag are announced; a null handler means "no seek
        // available", which is also when the slider refuses the touch.
        void scrub(bool active) => widget.onScrubActive?.call(active);
        // `secondaryTrackValue` may be null — Flutter only bounds it to [min, max],
        // it does not require it to be ahead of `value` — and null is the honest
        // answer when nothing is buffered ahead: after a seek into an unbuffered
        // region media_kit reports a buffered end BEHIND the position, and the
        // secondary track would be painted backwards from the thumb.
        final playedFraction = played.clamp(0.0, 1.0);
        final bufferedRaw = duration > 0
            ? (widget.buffer.inMilliseconds / duration).clamp(0.0, 1.0)
            : 0.0;
        final double? buffered = bufferedRaw > playedFraction
            ? bufferedRaw
            : null;

        return Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.bottomCenter,
              end: Alignment.topCenter,
              colors: [Color(0x80000000), Color(0x00000000)],
            ),
          ),
          padding: EdgeInsets.fromLTRB(
            m.pad + widget.safe.left,
            0,
            m.pad + widget.safe.right,
            m.pad / 2 + widget.safe.bottom,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                height: m.seekHeight,
                child: SliderTheme(
                  data: SliderThemeData(
                    trackHeight: m.trackHeight,
                    thumbShape: RoundSliderThumbShape(
                      enabledThumbRadius: m.thumbRadius,
                    ),
                    overlayShape: RoundSliderOverlayShape(
                      overlayRadius: m.thumbRadius * 2.4,
                    ),
                    activeTrackColor: RCrmColors.primary,
                    inactiveTrackColor: RCrmColors.silverDim,
                    thumbColor: RCrmColors.primary,
                    secondaryActiveTrackColor: const Color(0x66FFFFFF),
                  ),
                  child: Slider(
                    value: played.clamp(0.0, 1.0),
                    secondaryTrackValue: buffered,
                    // A drag on the bar is an interaction in progress, like an
                    // open panel: the screen holds its idle timer off for its
                    // duration and re-arms it at the end. Without this the bar
                    // — slider under the finger included — faded out two
                    // seconds into every scrub.
                    onChangeStart: widget.onSeek == null || duration <= 0
                        ? null
                        : (_) => scrub(true),
                    onChanged: widget.onSeek == null || duration <= 0
                        ? null
                        : (v) => setState(() => _scrub = v * duration),
                    onChangeEnd: widget.onSeek == null || duration <= 0
                        ? null
                        : (v) {
                            setState(() => _scrub = null);
                            widget.onSeek!(
                              Duration(milliseconds: (v * duration).round()),
                            );
                            scrub(false);
                          },
                  ),
                ),
              ),
              SizedBox(height: m.gap),
              Row(
                children: [
                  _iconButton(
                    m,
                    icon: widget.playing ? Icons.pause : Icons.play_arrow,
                    onPressed: widget.onPlayPause,
                    color: Colors.white70,
                    size: m.icon + 2,
                    tooltip: widget.playing ? 'Pause' : 'Play',
                  ),
                  // Volume: the mute button unless the width ladder had to give
                  // it up, the slider whatever the budget allowed. The gap
                  // belongs to the block — the budget counts one gap per painted
                  // control, so an unconditional gap here is a 2dp overflow at
                  // the narrowest widths.
                  if (plan.showMute) ...[
                    _gap(m),
                    _volumeGroup(m, plan.volumeSliderWidth),
                  ],
                  if (plan.showPosition) ...[
                    _gap(m),
                    Text(
                      posText,
                      style: m.timeStyle,
                      maxLines: 1,
                      softWrap: false,
                    ),
                  ],
                  if (plan.showDuration)
                    Text(
                      ' / ${formatMs(widget.duration.inMilliseconds)}',
                      style: m.durationStyle,
                      maxLines: 1,
                      softWrap: false,
                    ),
                  const Spacer(),
                  if (plan.showPrev)
                    _iconButton(
                      m,
                      icon: Icons.skip_previous,
                      onPressed: widget.onPrev,
                      tooltip: 'Previous',
                    ),
                  if (plan.showNext) ...[
                    _gap(m),
                    _iconButton(
                      m,
                      icon: Icons.skip_next,
                      onPressed: widget.onNext,
                      tooltip: 'Next',
                    ),
                  ],
                  if (plan.showSpeed) ...[_gap(m), _speedChip(m)],
                  if (plan.showEpisodes) ...[
                    _gap(m),
                    _iconButton(
                      m,
                      icon: Icons.playlist_play,
                      onPressed: widget.onEpisodes,
                      tooltip: 'Episodes',
                    ),
                  ],
                  if (plan.showFullscreen) ...[
                    _gap(m),
                    _iconButton(
                      m,
                      icon: widget.fullscreen
                          ? Icons.fullscreen_exit
                          : Icons.fullscreen,
                      onPressed: widget.onFullscreen,
                      tooltip: widget.fullscreen
                          ? 'Exit fullscreen'
                          : 'Fullscreen',
                    ),
                  ],
                ],
              ),
            ],
          ),
        );
      },
    );
  }

  /// The previewed position while the user drags the bar, in milliseconds.
  ///
  /// `_scrub` is ALREADY milliseconds — the slider reports a fraction, but the
  /// write site (`_scrub = v * duration`) has already scaled it. This getter used
  /// to multiply by the duration a second time, so the label showed
  /// `ms × ms` — the "random memory number" on the scrubber after the controls
  /// rewrite.
  ///
  /// Clamped to the media: a drag is bounded by the bar, but a duration that
  /// shrank (metadata arrived, or the stream re-reported it) can leave a stale
  /// value beyond the end, and `null` is the honest answer when the duration is
  /// not known yet — the bar then falls back to the player's own position.
  double? get _scrubMs {
    final s = _scrub;
    if (s == null || !s.isFinite) return null;
    final total = widget.duration.inMilliseconds.toDouble();
    if (total <= 0) return null;
    return s.clamp(0.0, total);
  }

  Widget _gap(PlayerChromeMetrics m) => SizedBox(width: m.gap);

  Widget _iconButton(
    PlayerChromeMetrics m, {
    required IconData icon,
    required VoidCallback? onPressed,
    String? tooltip,
    Color color = Colors.white54,
    double? size,
  }) {
    return IconButton(
      icon: Icon(icon, color: color, size: size ?? m.icon),
      onPressed: onPressed,
      tooltip: tooltip,
      padding: EdgeInsets.zero,
      // The painted box must BE `m.tap`: the width budget spends exactly that,
      // and the default padded tap target plus `VisualDensity.compact` were
      // silently shrinking a 44/48dp tier down to 40 — so the "bigger targets
      // in fullscreen" this file promises never happened.
      style: IconButton.styleFrom(
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
      ),
      visualDensity: VisualDensity.standard,
      constraints: BoxConstraints.tightFor(width: m.tap, height: m.tap),
      splashRadius: m.tap / 2,
    );
  }

  Widget _volumeGroup(PlayerChromeMetrics m, double sliderWidth) {
    return Listener(
      // Wheel over the volume cluster: desktop's fastest volume path. A wheel
      // notch is a settled change, so it persists immediately. In fullscreen
      // the screen owns the wheel (it also drives the volume overlay) — two
      // handlers would step the volume twice per notch.
      onPointerSignal: widget.fullscreen || widget.onVolumeChanged == null
          ? null
          : (event) {
              if (event is! PointerScrollEvent) return;
              final step = event.scrollDelta.dy < 0 ? 5.0 : -5.0;
              // Clamp and skip no-ops here rather than trusting the caller:
              // a notch at 100% must not write the same value back (and
              // schedule a prefs write for it).
              final next = (widget.volume + step).clamp(0.0, 100.0);
              if (next == widget.volume) return;
              widget.onVolumeChanged!(next);
              widget.onVolumeChangeEnd?.call();
              // A notch is an interaction that has already settled: the idle
              // countdown starts over rather than expiring while the user is
              // still working the wheel.
              widget.onScrubActive?.call(false);
            },
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          _iconButton(
            m,
            icon: _muted ? Icons.volume_off : Icons.volume_up,
            onPressed: widget.onToggleMute,
            tooltip: _muted ? 'Unmute' : 'Mute',
          ),
          if (sliderWidth > 0)
            SizedBox(
              width: sliderWidth,
              height: m.tap,
              child: SliderTheme(
                data: SliderThemeData(
                  trackHeight: m.trackHeight,
                  thumbShape: RoundSliderThumbShape(
                    enabledThumbRadius: m.thumbRadius,
                  ),
                  overlayShape: RoundSliderOverlayShape(
                    overlayRadius: m.thumbRadius * 2.4,
                  ),
                  activeTrackColor: Colors.white54,
                  inactiveTrackColor: RCrmColors.silverDim,
                  thumbColor: Colors.white,
                ),
                child: Slider(
                  value: widget.volume.clamp(0.0, 100.0),
                  max: 100,
                  // Announced the same way as the seek bar: a two-second drag
                  // for volume used to fade the bar — the slider under the
                  // finger included — out from under the user. A slider with no
                  // change handler is inert, so it announces nothing.
                  onChangeStart: widget.onVolumeChanged == null
                      ? null
                      : (_) => widget.onScrubActive?.call(true),
                  onChanged: widget.onVolumeChanged,
                  onChangeEnd: (_) {
                    widget.onVolumeChangeEnd?.call();
                    widget.onScrubActive?.call(false);
                  },
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _speedChip(PlayerChromeMetrics m) {
    final text = formatSpeed(widget.speed);
    return PopupMenuButton<double>(
      initialValue: widget.speed,
      onSelected: (s) {
        widget.onMenuVisibilityChanged?.call(false);
        widget.onSpeedChanged?.call(s);
      },
      // The menu is a panel too: while it is open the bar must not fade out
      // from under it (the screen arms its idle timer from this).
      onOpened: () => widget.onMenuVisibilityChanged?.call(true),
      onCanceled: () => widget.onMenuVisibilityChanged?.call(false),
      tooltip: 'Playback speed',
      // Open upward, clear of the bar, sized to the menu it will show.
      offset: Offset(0, -(_speedItemHeight * _speeds.length + _menuPadding)),
      itemBuilder: (_) => _speeds
          .map(
            (s) => PopupMenuItem(
              value: s,
              height: _speedItemHeight,
              child: Text(
                formatSpeed(s),
                style: TextStyle(
                  color: widget.speed == s
                      ? RCrmColors.primary
                      : Colors.white70,
                  fontSize: 13,
                ),
              ),
            ),
          )
          .toList(),
      child: Container(
        padding: EdgeInsets.symmetric(horizontal: m.gap * 2, vertical: 3),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(RCrmRadii.sm),
        ),
        child: Text(text, style: m.chipStyle),
      ),
    );
  }

  /// Width of [text] as it will really be painted: the ambient style (the
  /// theme's font — Roboto, Segoe UI, whatever the platform picked) merged
  /// with [style], at the user's font scaling. Budgeting with a different
  /// font than the one that renders is how a "fits" bar overflows.
  ///
  /// Memoised because the bar rebuilds on every position tick (up to 10/s while
  /// playing) and would otherwise re-layout the same three strings every time —
  /// text layout is the expensive part of this widget. The cache is keyed by the
  /// inputs that can change the answer: the text, the resolved style and the
  /// text scale.
  static final Map<(String, TextStyle, double), double> _widthCache = {};

  static double _measure(BuildContext context, String text, TextStyle style) {
    final effective = DefaultTextStyle.of(context).style.merge(style);
    final scale = MediaQuery.textScalerOf(context);
    final key = (text, effective, scale.scale(1));
    final cached = _widthCache[key];
    if (cached != null) return cached;
    final tp = TextPainter(
      text: TextSpan(text: text, style: effective),
      textScaler: scale,
      textDirection: TextDirection.ltr,
      maxLines: 1,
    )..layout();
    // Bounded: a library full of distinct titles could otherwise grow this map
    // for the life of the process, and the entries are only worth keeping while
    // the same few strings keep being measured (a bar with a fixed layout).
    if (_widthCache.length >= 128) _widthCache.clear();
    _widthCache[key] = tp.width;
    return tp.width;
  }
}

// ── Fullscreen top bar ──────────────────────────────────────────────

/// Fullscreen chrome: back on the left, title in the middle, settings on the
/// right — where the eye looks for them, and clear of the transport bar that
/// runs out of room first.
class PlayerTopBar extends StatelessWidget {
  final String title;
  final VoidCallback onBack;

  /// Null hides the settings button (windowed player).
  final VoidCallback? onSettings;

  /// Safe-area insets of the surface it sits on (notch, camera cutout).
  final EdgeInsets safe;

  const PlayerTopBar({
    super.key,
    required this.title,
    required this.onBack,
    this.onSettings,
    this.safe = EdgeInsets.zero,
  });

  @override
  Widget build(BuildContext context) {
    final m = PlayerChromeMetrics.of(
      MediaQuery.sizeOf(context),
      fullscreen: true,
    );
    return Container(
      padding: EdgeInsets.fromLTRB(
        m.pad / 2 + safe.left,
        m.pad / 2 + safe.top,
        m.pad / 2 + safe.right,
        m.pad,
      ),
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Color(0xB3000000), Color(0x00000000)],
        ),
      ),
      child: Row(
        children: [
          IconButton(
            icon: Icon(Icons.arrow_back, color: Colors.white, size: m.icon),
            onPressed: onBack,
            tooltip: 'Back',
            padding: EdgeInsets.zero,
            visualDensity: VisualDensity.compact,
            constraints: BoxConstraints.tightFor(width: m.tap, height: m.tap),
            splashRadius: m.tap / 2,
          ),
          SizedBox(width: m.gap * 2),
          Expanded(
            child: Text(
              title,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 15,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
          if (onSettings != null)
            IconButton(
              icon: Icon(Icons.settings, color: Colors.white, size: m.icon),
              onPressed: onSettings,
              tooltip: 'Playback settings',
              padding: EdgeInsets.zero,
              visualDensity: VisualDensity.compact,
              constraints: BoxConstraints.tightFor(width: m.tap, height: m.tap),
              splashRadius: m.tap / 2,
            ),
        ],
      ),
    );
  }
}

// ── Speed badge ─────────────────────────────────────────────────────

/// The "2x" chip shown while the 2x gesture is held.
///
/// Stays mounted while hidden so both the entrance and the exit animate, and
/// keeps the chevron pulse inside the AnimatedBuilder — a cached subtree here
/// would freeze the animation at its first frame.
class PlayerSpeedBadge extends StatefulWidget {
  final bool visible;
  const PlayerSpeedBadge({super.key, required this.visible});

  @override
  State<PlayerSpeedBadge> createState() => _PlayerSpeedBadgeState();
}

class _PlayerSpeedBadgeState extends State<PlayerSpeedBadge>
    with SingleTickerProviderStateMixin {
  late final AnimationController _pulse = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 900),
  );

  @override
  void initState() {
    super.initState();
    if (widget.visible) _pulse.repeat();
  }

  @override
  void didUpdateWidget(covariant PlayerSpeedBadge old) {
    super.didUpdateWidget(old);
    if (widget.visible == old.visible) return;
    if (widget.visible) {
      _pulse.repeat();
    } else {
      _pulse.stop();
    }
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  static const _accent = RCrmColors.primary;

  /// One chevron of the running-chevrons mark, its opacity offset by [phase].
  Widget _chevron(double phase) {
    final t = (_pulse.value + phase) % 1.0;
    final opacity = 0.30 + 0.70 * (0.5 + 0.5 * math.cos(2 * math.pi * t));
    return Icon(
      Icons.play_arrow,
      color: _accent.withValues(alpha: opacity),
      size: 18,
    );
  }

  @override
  Widget build(BuildContext context) {
    const motion = Duration(milliseconds: 180);
    return IgnorePointer(
      child: AnimatedOpacity(
        opacity: widget.visible ? 1.0 : 0.0,
        duration: widget.visible ? motion : const Duration(milliseconds: 240),
        curve: Curves.easeOutCubic,
        child: AnimatedScale(
          scale: widget.visible ? 1.0 : 0.94,
          duration: motion,
          curve: Curves.easeOutCubic,
          child: AnimatedBuilder(
            animation: _pulse,
            builder: (_, _) => Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              decoration: BoxDecoration(
                color: _accent.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(RCrmRadii.md + 2),
                border: Border.all(color: _accent.withValues(alpha: 0.5)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  SizedBox(
                    width: 34,
                    child: Stack(
                      children: [
                        _chevron(0),
                        Positioned(left: 10, child: _chevron(1 / 3)),
                        Positioned(left: 20, child: _chevron(2 / 3)),
                      ],
                    ),
                  ),
                  const SizedBox(width: 6),
                  const Text(
                    '2x',
                    style: TextStyle(
                      color: _accent,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ── Gesture feedback chip ───────────────────────────────────────────

/// Centre chip for the brightness/volume swipe gestures. Fades in and out
/// instead of popping, and stays mounted so the fade can finish — which means
/// it has to remember the last value while it fades away.
class PlayerGestureChip extends StatefulWidget {
  /// True for brightness — the icon and bar colour follow the gesture.
  final bool brightness;

  /// Null hides the chip.
  final int? value;

  const PlayerGestureChip({super.key, required this.brightness, this.value});

  @override
  State<PlayerGestureChip> createState() => _PlayerGestureChipState();
}

class _PlayerGestureChipState extends State<PlayerGestureChip> {
  int _last = 0;
  bool _lastBrightness = false;

  @override
  void initState() {
    super.initState();
    _last = widget.value ?? 0;
    _lastBrightness = widget.brightness;
  }

  @override
  void didUpdateWidget(covariant PlayerGestureChip old) {
    super.didUpdateWidget(old);
    // The icon and colour follow `brightness`, so a flip has to be picked up
    // even when no new value arrived (the chip stays mounted through its fade).
    _lastBrightness = widget.brightness;
    if (widget.value != null) _last = widget.value!;
  }

  @override
  Widget build(BuildContext context) {
    final shown = widget.value != null;
    final pct = (_last / 100).clamp(0.0, 1.0);
    return IgnorePointer(
      child: Center(
        child: AnimatedOpacity(
          opacity: shown ? 1.0 : 0.0,
          duration: shown
              ? const Duration(milliseconds: 120)
              : const Duration(milliseconds: 260),
          curve: Curves.easeOutCubic,
          child: AnimatedScale(
            scale: shown ? 1.0 : 0.96,
            duration: const Duration(milliseconds: 160),
            curve: Curves.easeOutCubic,
            child: Container(
              width: 160,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.6),
                borderRadius: BorderRadius.circular(RCrmRadii.md + 4),
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    _lastBrightness ? Icons.brightness_6 : Icons.volume_up,
                    color: Colors.white,
                    size: 28,
                  ),
                  const SizedBox(height: 8),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(2),
                    child: LinearProgressIndicator(
                      value: pct,
                      minHeight: 4,
                      backgroundColor: RCrmColors.silverDim,
                      valueColor: AlwaysStoppedAnimation(
                        _lastBrightness
                            ? const Color(0xFFFFD600)
                            : RCrmColors.primary,
                      ),
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '$_last%',
                    style: const TextStyle(color: Colors.white, fontSize: 13),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
