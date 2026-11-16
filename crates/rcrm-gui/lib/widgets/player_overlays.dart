// widgets/player_overlays.dart
// The two things the player paints OVER the picture while something is being
// waited for — or has failed: the buffering spinner and the playback-error
// card.
//
// Both are pure presentation. Whether the spinner is up and what failed are the
// screen's business (`screens/video_player_screen.dart`) — so neither widget
// touches a `Player`. The end-of-playback surface is a PLACE rather than a
// wait, and lives in `widgets/player_end_card.dart`.

import 'package:material_ui/material_ui.dart';

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
                  valueColor: AlwaysStoppedAnimation(RCrmColors.playerAccent),
                  backgroundColor: RCrmColors.playerText.withValues(
                    alpha: 0.14,
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ── Playback error ─────────────────────────────────────────────────

/// The overlay for a file the player could not open.
///
/// This is not a wait, so it does not use the spinner's fade-in: it has to say
/// what failed (the player's own message, shortened) and offer the two exits
/// that make sense — retry the same open, or leave the player. There is no
/// frame to preserve on a failed open.
class PlayerPlaybackError extends StatelessWidget {
  /// The player's own error, already cleaned and bounded by the screen.
  final String message;
  final VoidCallback onRetry;
  final VoidCallback onBack;

  const PlayerPlaybackError({
    super.key,
    required this.message,
    required this.onRetry,
    required this.onBack,
  });

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return GestureDetector(
      // The overlay covers the gesture map (tap = chrome, swipes = seek/volume).
      // A tap on the card's background is not a player gesture; the buttons
      // still receive their own taps.
      behavior: HitTestBehavior.opaque,
      onTap: () {},
      child: ColoredBox(
        color: Colors.black.withValues(alpha: 0.78),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.error_outline,
                    color: RCrmColors.playerTextSecondary,
                    size: 36,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    "Can't play this video",
                    textAlign: TextAlign.center,
                    style: text.titleMedium?.copyWith(
                      color: RCrmColors.playerText,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    message,
                    textAlign: TextAlign.center,
                    maxLines: 4,
                    overflow: TextOverflow.ellipsis,
                    style: text.bodySmall?.copyWith(
                      color: RCrmColors.playerTextSecondary,
                    ),
                  ),
                  const SizedBox(height: 18),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      TextButton(
                        onPressed: onBack,
                        style: TextButton.styleFrom(
                          foregroundColor: RCrmColors.playerTextSecondary,
                        ),
                        child: const Text('Back'),
                      ),
                      const SizedBox(width: 8),
                      FilledButton.tonal(
                        onPressed: onRetry,
                        child: const Text('Try again'),
                      ),
                    ],
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
