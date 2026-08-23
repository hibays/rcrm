// widgets/cast_auto_next_panel.dart
// Bilibili-web-style "up next" strip for casting: when the TV sits idle
// (video ended, or a picked video never started), the upcoming videos are
// laid out with the first one carrying a countdown ring — untouched for the
// window, the first plays by itself; any tap (pick or cancel) stops the
// countdown.

import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../models/media_item.dart';
import '../widgets/video_card.dart';

class CastAutoNextPanel extends StatelessWidget {
  final List<MediaItem> candidates;

  /// Whole-second countdown shown in the ring; reaches 1 before firing.
  final int secondsLeft;
  final int totalSeconds;

  /// False = manual-pick-only offer (no countdown fire): the ring becomes a
  /// plain play badge and the header drops the auto-play wording.
  final bool autoFire;
  final ValueChanged<MediaItem> onPick;
  final VoidCallback onCancel;

  const CastAutoNextPanel({
    super.key,
    required this.candidates,
    required this.secondsLeft,
    required this.totalSeconds,
    this.autoFire = true,
    required this.onPick,
    required this.onCancel,
  });

  /// Bilibili brand pink — countdown ring / auto-play accent.
  static const _biliPink = Color(0xFFFB7299);

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final maxW = constraints.maxWidth.isFinite
            ? constraints.maxWidth
            : 520.0;
        final width = maxW < 520 ? maxW : 520.0;
        return TweenAnimationBuilder<double>(
          // Entrance: slide up + fade, like the web end-card.
          tween: Tween(begin: 0, end: 1),
          duration: const Duration(milliseconds: 220),
          curve: Curves.easeOutCubic,
          builder: (context, v, child) => Transform.translate(
            offset: Offset(0, 20 * (1 - v)),
            child: Opacity(opacity: v, child: child),
          ),
          child: Material(
            color: const Color(0xFF1F1F22),
            elevation: 10,
            shadowColor: Colors.black54,
            borderRadius: BorderRadius.circular(12),
            clipBehavior: Clip.antiAlias,
            child: SizedBox(
              width: width,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(12, 8, 4, 8),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(
                          Icons.play_circle_outline,
                          size: 16,
                          color: _biliPink,
                        ),
                        const SizedBox(width: 6),
                        const Text(
                          'Up next',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          autoFire
                              ? 'Auto-play in ${secondsLeft}s'
                              : 'Pick next',
                          style: const TextStyle(
                            color: _biliPink,
                            fontSize: 12,
                          ),
                        ),
                        const Spacer(),
                        TextButton(
                          onPressed: onCancel,
                          style: TextButton.styleFrom(
                            foregroundColor: Colors.white54,
                            visualDensity: VisualDensity.compact,
                            padding: const EdgeInsets.symmetric(horizontal: 10),
                            minimumSize: const Size(0, 32),
                          ),
                          child: const Text(
                            'Cancel',
                            style: TextStyle(fontSize: 12),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    SizedBox(
                      height: 108,
                      child: ListView.separated(
                        scrollDirection: Axis.horizontal,
                        itemCount: candidates.length,
                        separatorBuilder: (_, _) => const SizedBox(width: 8),
                        itemBuilder: (_, i) =>
                            _candidate(candidates[i], isNext: i == 0),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _candidate(MediaItem item, {required bool isNext}) {
    return InkWell(
      onTap: () => onPick(item),
      borderRadius: BorderRadius.circular(6),
      child: SizedBox(
        width: 128,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 128,
              height: 72,
              child: Stack(
                fit: StackFit.expand,
                children: [
                  ClipRRect(
                    borderRadius: BorderRadius.circular(6),
                    child: VideoCard(item: item, compact: true),
                  ),
                  if (isNext)
                    Container(
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: _biliPink, width: 1.5),
                      ),
                    ),
                  if (isNext)
                    Center(child: autoFire ? _countdownBadge() : _pickBadge()),
                ],
              ),
            ),
            const SizedBox(height: 4),
            Text(
              item.name,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                color: Colors.white70,
                fontSize: 11,
                height: 1.2,
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Manual-pick-only variant of the badge: a plain play icon, no ring.
  Widget _pickBadge() => Container(
    width: 38,
    height: 38,
    decoration: BoxDecoration(
      color: Colors.black.withValues(alpha: 0.65),
      shape: BoxShape.circle,
    ),
    child: const Icon(Icons.play_arrow, color: Colors.white, size: 26),
  );

  Widget _countdownBadge() {
    final frac = totalSeconds <= 0
        ? 0.0
        : (secondsLeft / totalSeconds).clamp(0.0, 1.0);
    return Container(
      width: 38,
      height: 38,
      decoration: BoxDecoration(
        color: Colors.black.withValues(alpha: 0.65),
        shape: BoxShape.circle,
      ),
      child: CustomPaint(
        painter: _RingPainter(progress: frac, color: _biliPink),
        child: Center(
          child: Text(
            '$secondsLeft',
            style: const TextStyle(
              color: Colors.white,
              fontSize: 15,
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
      ),
    );
  }
}

/// Circular countdown ring, depleting clockwise from 12 o'clock.
class _RingPainter extends CustomPainter {
  final double progress;
  final Color color;
  const _RingPainter({required this.progress, required this.color});

  @override
  void paint(Canvas canvas, Size size) {
    const stroke = 3.0;
    final rect = (Offset.zero & size).deflate(stroke / 2 + 1);
    canvas.drawArc(
      rect,
      -math.pi / 2,
      2 * math.pi * progress,
      false,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = stroke
        ..strokeCap = StrokeCap.round
        ..color = color,
    );
  }

  @override
  bool shouldRepaint(_RingPainter oldDelegate) =>
      oldDelegate.progress != progress || oldDelegate.color != color;
}
