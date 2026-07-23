// widgets/player_settings_panel.dart
// Settings overlay for video player: playback mode, auto-rotate.
// Rendered as a floating panel in the video player's Stack.

import 'package:flutter/material.dart';

/// Playback mode enum for video end-of-stream behavior.
enum PlaybackMode {
  /// Auto-play the next video in the related list.
  loopAll,

  /// Repeat the current video.
  loopOne,

  /// Pause when the current video finishes.
  pauseAfter;

  String get label => switch (this) {
    PlaybackMode.loopAll => 'Loop All',
    PlaybackMode.loopOne => 'Loop One',
    PlaybackMode.pauseAfter => 'Pause After',
  };

  static PlaybackMode fromString(String s) {
    switch (s) {
      case 'loopAll':
        return PlaybackMode.loopAll;
      case 'loopOne':
        return PlaybackMode.loopOne;
      default:
        return PlaybackMode.pauseAfter;
    }
  }

  String get key => switch (this) {
    PlaybackMode.loopAll => 'loopAll',
    PlaybackMode.loopOne => 'loopOne',
    PlaybackMode.pauseAfter => 'pauseAfter',
  };
}

class PlayerSettingsPanel extends StatelessWidget {
  final PlaybackMode mode;
  final ValueChanged<PlaybackMode> onModeChanged;
  final bool autoRotate;
  final ValueChanged<bool> onAutoRotateChanged;
  final VoidCallback onDismiss;

  const PlayerSettingsPanel({
    super.key,
    required this.mode,
    required this.onModeChanged,
    required this.autoRotate,
    required this.onAutoRotateChanged,
    required this.onDismiss,
  });

  static const _accent = Color(0xFFFF6B00);

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onDismiss,
      behavior: HitTestBehavior.opaque,
      child: Container(
        color: Colors.black.withValues(alpha: 0.45),
        child: Center(
          child: GestureDetector(
            onTap: () {}, // absorb taps inside the panel
            child: Container(
              width: 400,
              margin: const EdgeInsets.symmetric(horizontal: 24),
              padding: const EdgeInsets.all(28),
              decoration: BoxDecoration(
                color: const Color(0xFF1A1A1A),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Header
                  Row(
                    children: [
                      const Icon(
                        Icons.settings,
                        color: Colors.white54,
                        size: 18,
                      ),
                      const SizedBox(width: 8),
                      const Text(
                        'Playback Settings',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const Spacer(),
                      IconButton(
                        icon: const Icon(
                          Icons.close,
                          color: Colors.white38,
                          size: 18,
                        ),
                        onPressed: onDismiss,
                        visualDensity: VisualDensity.compact,
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(),
                      ),
                    ],
                  ),
                  const SizedBox(height: 24),

                  // ── Playback Mode ─────────────────────────
                  const Text(
                    'Playback Mode',
                    style: TextStyle(
                      color: Colors.white54,
                      fontSize: 12,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: SegmentedButton<PlaybackMode>(
                      segments: PlaybackMode.values
                          .map(
                            (m) => ButtonSegment<PlaybackMode>(
                              value: m,
                              label: Text(
                                m.label,
                                style: TextStyle(
                                  fontSize: 12,
                                  fontWeight: FontWeight.w600,
                                  color: mode == m
                                      ? Colors.black
                                      : Colors.white54,
                                ),
                              ),
                            ),
                          )
                          .toList(),
                      selected: {mode},
                      onSelectionChanged: (sel) {
                        if (sel.isNotEmpty) onModeChanged(sel.first);
                      },
                      style: ButtonStyle(
                        backgroundColor: WidgetStateProperty.resolveWith(
                          (states) => states.contains(WidgetState.selected)
                              ? _accent
                              : Colors.white.withValues(alpha: 0.06),
                        ),
                        foregroundColor: WidgetStateProperty.resolveWith(
                          (states) => states.contains(WidgetState.selected)
                              ? Colors.black
                              : Colors.white54,
                        ),
                        visualDensity: VisualDensity.compact,
                        padding: WidgetStateProperty.all(
                          const EdgeInsets.symmetric(vertical: 8),
                        ),
                        shape: WidgetStateProperty.all(
                          RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(8),
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),

                  // ── Auto-Rotate ───────────────────────────
                  Row(
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'Auto-Rotate',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 13,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              'Ignore system rotation lock; follow device orientation',
                              style: TextStyle(
                                color: Colors.white.withValues(alpha: 0.35),
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 12),
                      SizedBox(
                        height: 28,
                        child: Switch(
                          value: autoRotate,
                          onChanged: onAutoRotateChanged,
                          activeThumbColor: _accent,
                          activeTrackColor: _accent.withValues(alpha: 0.4),
                          inactiveThumbColor: Colors.white38,
                          inactiveTrackColor: Colors.white.withValues(
                            alpha: 0.08,
                          ),
                        ),
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
