// widgets/player_overlays.dart
// The two things the player paints OVER the picture while something is being
// waited for: the buffering spinner, and the card that asks what to do next.
//
// Both are pure presentation. Whether the spinner is up, and what the next
// video is, are the screen's business (`screens/video_player_screen.dart`) —
// so neither widget here touches a `Player`.

import 'package:flutter/material.dart';

import '../config/theme.dart';

// ── Buffering ───────────────────────────────────────────────────────

/// The spinner for a player that is stalled rather than finished.
///
/// The picture is left alone: a scrim over a frame the user is waiting to see
/// again would hide the very thing that says the app is still working on it.
/// Just a disc, dark enough to read on a white frame, with the accent's arc in
/// it — the one place in the player where orange means "wait" rather than
/// "here" (docs/DESIGN.md, Loading States).
///
/// Stays mounted and fades, like the gesture chip, so the exit is a fade rather
/// than a disappearance. The caller owns the DELAY: a 200ms stall during a seek
/// is not worth a spinner, and only the caller can tell one from a real stall.
class PlayerBufferingIndicator extends StatelessWidget {
  final bool visible;

  /// Diameter of the disc.
  final double size;

  const PlayerBufferingIndicator({
    super.key,
    required this.visible,
    this.size = 54,
  });

  @override
  Widget build(BuildContext context) {
    final motion = MediaQuery.disableAnimationsOf(context)
        ? Duration.zero
        : const Duration(milliseconds: 160);
    return IgnorePointer(
      child: AnimatedOpacity(
        opacity: visible ? 1.0 : 0.0,
        duration: visible ? motion : const Duration(milliseconds: 240),
        curve: Curves.easeOutCubic,
        child: Center(
          child: AnimatedScale(
            scale: visible ? 1.0 : 0.94,
            duration: motion,
            curve: Curves.easeOutCubic,
            child: Container(
              width: size,
              height: size,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.42),
                shape: BoxShape.circle,
              ),
              child: SizedBox(
                width: size * 0.58,
                height: size * 0.58,
                child: CircularProgressIndicator(
                  strokeWidth: 2.5,
                  valueColor: const AlwaysStoppedAnimation(RCrmColors.primary),
                  backgroundColor: Colors.white.withValues(alpha: 0.14),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ── Up next ─────────────────────────────────────────────────────────

/// The card that gives the viewer a say in the autoplay.
///
/// `loopAll` used to jump to the next video the instant this one ended — the
/// one moment in playback where the app decides something on the user's behalf
/// and gives them no chance to disagree. This makes that decision visible and
/// reversible: the ring is the time left before it happens, "Play now" is
/// sooner, and the ✕ is never.
///
/// The countdown lives HERE, on the ring's own controller, so the time the ring
/// shows and the time until [onAdvance] fires cannot disagree — there is one
/// clock, and it is the one on screen.
class PlayerUpNextCard extends StatefulWidget {
  /// What will play if the card is left alone.
  final String title;

  /// One quiet line under the title — size and format, in practice.
  final String subtitle;

  /// How long the card waits before advancing on its own.
  final Duration countdown;

  /// Advance now, or when the countdown runs out. Both are "yes".
  final VoidCallback onAdvance;

  /// Stay on the frame the video ended on. The card is then gone, and nothing
  /// plays until the user asks for something.
  final VoidCallback onDismiss;

  const PlayerUpNextCard({
    super.key,
    required this.title,
    required this.subtitle,
    required this.countdown,
    required this.onAdvance,
    required this.onDismiss,
  });

  @override
  State<PlayerUpNextCard> createState() => _PlayerUpNextCardState();
}

class _PlayerUpNextCardState extends State<PlayerUpNextCard>
    with SingleTickerProviderStateMixin {
  late final AnimationController _count = AnimationController(
    vsync: this,
    duration: widget.countdown,
  );

  @override
  void initState() {
    super.initState();
    _count.addStatusListener(_onStatus);
    _count.forward();
  }

  void _onStatus(AnimationStatus s) {
    if (s != AnimationStatus.completed) return;
    // The controller finishes inside a frame; the screen is about to replace
    // this whole screen's media, so hand it over once the frame is done rather
    // than during it.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) widget.onAdvance();
    });
  }

  @override
  void dispose() {
    _count.removeStatusListener(_onStatus);
    _count.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final instant = MediaQuery.disableAnimationsOf(context);
    return Align(
      // The screen places this clear of the transport bar; bottom-end is what
      // it is aligned to there.
      alignment: Alignment.bottomRight,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: _entrance(
          instant,
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 360),
            child: DecoratedBox(
              decoration: BoxDecoration(
                color: RCrmColors.ash.withValues(alpha: 0.96),
                borderRadius: BorderRadius.circular(RCrmRadii.md),
                // Allowed where a surface is not at rest: this one appears
                // over a frame of unknown brightness, and has to be a card
                // rather than a patch of it.
                boxShadow: const [
                  BoxShadow(
                    color: Color(0x59000000),
                    blurRadius: 16,
                    offset: Offset(0, 4),
                  ),
                ],
              ),
              child: Padding(
                padding: const EdgeInsets.fromLTRB(12, 10, 8, 10),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    _ring(),
                    const SizedBox(width: 12),
                    Flexible(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'Up next',
                            style: TextStyle(
                              color: RCrmColors.silver,
                              fontSize: 11,
                              fontWeight: FontWeight.w600,
                              letterSpacing: 0.02,
                            ),
                          ),
                          const SizedBox(height: 3),
                          Text(
                            widget.title,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          if (widget.subtitle.isNotEmpty) ...[
                            const SizedBox(height: 2),
                            Text(
                              widget.subtitle,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                // The card's one line of context — size,
                                // format, and now "Random pick". White38 read
                                // at 3.6:1 on the card's dark surface; the
                                // system's secondary token is Silver.
                                color: RCrmColors.silver,
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                    const SizedBox(width: 8),
                    TextButton(
                      onPressed: widget.onAdvance,
                      style: TextButton.styleFrom(
                        foregroundColor: RCrmColors.primary,
                        padding: const EdgeInsets.symmetric(horizontal: 10),
                        minimumSize: const Size(0, 34),
                        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                      ),
                      child: const Text(
                        'Play now',
                        style: TextStyle(
                          fontSize: 12.5,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    IconButton(
                      icon: const Icon(
                        Icons.close,
                        size: 16,
                        color: Colors.white54,
                      ),
                      onPressed: widget.onDismiss,
                      tooltip: 'Stay on this video',
                      padding: EdgeInsets.zero,
                      visualDensity: VisualDensity.compact,
                      constraints: const BoxConstraints.tightFor(
                        width: 32,
                        height: 32,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// The countdown, as the shape of the time left rather than a number that
  /// ticks — a figure counting down next to a video is noise, a closing ring is
  /// a glance.
  Widget _ring() {
    return SizedBox(
      width: 34,
      height: 34,
      child: AnimatedBuilder(
        animation: _count,
        builder: (_, _) => Stack(
          alignment: Alignment.center,
          children: [
            SizedBox(
              width: 34,
              height: 34,
              child: CircularProgressIndicator(
                // Drains: full at the moment the card appeared.
                value: 1 - _count.value,
                strokeWidth: 2.5,
                valueColor: const AlwaysStoppedAnimation(RCrmColors.primary),
                backgroundColor: Colors.white.withValues(alpha: 0.12),
              ),
            ),
            const Icon(Icons.skip_next, size: 15, color: Colors.white70),
          ],
        ),
      ),
    );
  }

  /// Rises the last few pixels into place. Once: the card is a moment, not a
  /// place.
  Widget _entrance(bool instant, Widget child) {
    if (instant) return child;
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: 1),
      duration: const Duration(milliseconds: 200),
      curve: Curves.easeOutCubic,
      builder: (_, t, inner) => Opacity(
        opacity: t,
        child: Transform.translate(
          offset: Offset(0, 8 * (1 - t)),
          child: inner,
        ),
      ),
      child: child,
    );
  }
}
