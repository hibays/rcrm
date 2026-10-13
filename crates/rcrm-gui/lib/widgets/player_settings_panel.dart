// widgets/player_settings_panel.dart
// Settings overlay for video player: playback mode, auto-rotate, and what the
// player can honestly say about the file it is playing.
// Rendered as a floating panel in the video player's Stack.

import 'package:flutter/material.dart';

import '../config/theme.dart';
import '../utils/player_orientation.dart';

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

  /// What the mode actually does when a file ends. Printed under the choice,
  /// because "Loop All" and "Loop One" are one letter apart and describe
  /// opposite behaviour — and because Loop All's next video now arrives through
  /// a countdown the viewer can refuse, which is not something a two-word
  /// segment can say.
  String get note => switch (this) {
    PlaybackMode.loopAll =>
      'When this one ends, offer the next video in Related — eight seconds to '
          'play it now or stay put',
    PlaybackMode.loopOne => 'Start this video again from the beginning',
    PlaybackMode.pauseAfter => 'Stop on the last frame and wait',
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

/// One read-only fact about the media that is playing, as the player itself
/// reported it. A value the player never reported is simply absent — this list
/// is a report, not a form.
@immutable
class PlayerMediaFact {
  final String label;
  final String value;
  const PlayerMediaFact(this.label, this.value);
}

class PlayerSettingsPanel extends StatelessWidget {
  final PlaybackMode mode;
  final ValueChanged<PlaybackMode> onModeChanged;

  /// How the fullscreen player chooses which way up it is
  /// (`utils/player_orientation.dart`).
  final PlayerOrientation orientation;
  final ValueChanged<PlayerOrientation> onOrientationChanged;

  final VoidCallback onDismiss;

  /// Whether the orientation row belongs on this screen at all.
  ///
  /// Rotation is a mobile concern and only mobile code acts on it, so on
  /// desktop the row would be a control that cannot do anything — the one
  /// kind of control this app does not ship.
  final bool showOrientation;

  /// What is playing, from `PlayerState`. Empty is a normal answer: it means
  /// the player has not reported anything yet, not that the file is unusual.
  final List<PlayerMediaFact> facts;

  /// Whether to print the keyboard map. Desktop only, for the same reason.
  final bool showShortcuts;

  const PlayerSettingsPanel({
    super.key,
    required this.mode,
    required this.onModeChanged,
    required this.orientation,
    required this.onOrientationChanged,
    required this.onDismiss,
    this.showOrientation = false,
    this.facts = const [],
    this.showShortcuts = false,
  });

  static const _accent = RCrmColors.primary;

  /// The keys `widgets/media_player_keys.dart` answers to. Kept as one line of
  /// text rather than a table: it is a reminder for someone who already knows
  /// players, not documentation.
  ///
  /// Directions are spelled OUT, not drawn as `←`/`→`/`↑`/`↓`: those code
  /// points are not in Roboto (measured — they render as tofu boxes against the
  /// engine's own font set), so the arrow glyphs would be the one broken thing
  /// in the panel on Android.
  static const _shortcutLine =
      'Space or K  play/pause  ·  J or L, Left or Right  skip 10s  ·  '
      'Up or Down  volume  ·  M  mute  ·  comma or period  speed  ·  '
      'F  fullscreen  ·  Esc  close or leave';

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
            child: _entrance(
              context,
              Container(
                width: 400,
                margin: const EdgeInsets.symmetric(horizontal: 24),
                padding: const EdgeInsets.fromLTRB(24, 20, 24, 24),
                decoration: BoxDecoration(
                  color: RCrmColors.ash,
                  borderRadius: BorderRadius.circular(RCrmRadii.md + 4),
                ),
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _header(),
                      const SizedBox(height: 20),
                      _label('Playback Mode'),
                      const SizedBox(height: 10),
                      _modeSegments(context),
                      const SizedBox(height: 8),
                      Text(
                        mode.note,
                        style: const TextStyle(
                          color: Colors.white38,
                          fontSize: 11,
                          height: 1.4,
                        ),
                      ),
                      if (showOrientation) ...[
                        const SizedBox(height: 20),
                        _label('Fullscreen Orientation'),
                        const SizedBox(height: 10),
                        _orientationSegments(context),
                        const SizedBox(height: 8),
                        Text(
                          orientationNote(orientation.policy),
                          style: const TextStyle(
                            color: Colors.white38,
                            fontSize: 11,
                            height: 1.4,
                          ),
                        ),
                        if (orientation.isLock) ...[
                          const SizedBox(height: 10),
                          _lockSegments(context),
                        ],
                      ],
                      if (facts.isNotEmpty) ...[
                        const SizedBox(height: 22),
                        _label('This Video'),
                        const SizedBox(height: 10),
                        _facts(),
                      ],
                      if (showShortcuts) ...[
                        const SizedBox(height: 22),
                        _label('Keyboard'),
                        const SizedBox(height: 8),
                        const Text(
                          _shortcutLine,
                          style: TextStyle(
                            color: Colors.white38,
                            fontSize: 11,
                            height: 1.6,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _header() {
    return Row(
      children: [
        const Icon(Icons.settings, color: Colors.white54, size: 18),
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
          icon: const Icon(Icons.close, color: Colors.white38, size: 18),
          onPressed: onDismiss,
          tooltip: 'Close',
          visualDensity: VisualDensity.compact,
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(),
        ),
      ],
    );
  }

  Widget _label(String t) => Text(
    t,
    style: const TextStyle(
      color: RCrmColors.silver,
      fontSize: 12,
      fontWeight: FontWeight.w600,
      letterSpacing: 0.02,
    ),
  );

  Widget _modeSegments(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      child: SegmentedButton<PlaybackMode>(
        segments: PlaybackMode.values
            .map(
              (m) => ButtonSegment<PlaybackMode>(
                value: m,
                label: Text(m.label),
              ),
            )
            .toList(),
        selected: {mode},
        // No check on the chosen segment, here or on the orientation rows: the
        // accent fill already says which one it is, and the icon is what made
        // this row wrap onto three lines ("Loo / p / All") on a 320dp phone —
        // measured at 320x640, where the three labels plus the icon need more
        // than the panel can give.
        showSelectedIcon: false,
        onSelectionChanged: (sel) {
          if (sel.isNotEmpty) onModeChanged(sel.first);
        },
        style: _segmentStyle(context),
      ),
    );
  }

  Widget _orientationSegments(BuildContext context) {
    final policies = orientationPolicies();
    return SizedBox(
      width: double.infinity,
      child: SegmentedButton<OrientationPolicy>(
        segments: policies
            .map(
              (p) => ButtonSegment<OrientationPolicy>(
                value: p,
                label: Text(p.label),
              ),
            )
            .toList(),
        selected: {orientation.policy},
        // See `_modeSegments`: the fill says which one is chosen, and four
        // segments plus a check icon do not fit a narrow phone.
        showSelectedIcon: false,
        onSelectionChanged: (sel) {
          if (sel.isEmpty) return;
          // No "already selected" case to handle: the framework does not call
          // back for the segment that is already chosen, so re-tapping the
          // locked policy leaves the direction the viewer picked exactly where it
          // was, and picking a lock that is NOT in force enters it at its own
          // default -- landscape, because this is a video player.
          onOrientationChanged(sel.first.entry);
        },
        style: _segmentStyle(context),
      ),
    );
  }

  /// The direction the lock means, shown only while the lock is the policy.
  Widget _lockSegments(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      child: SegmentedButton<PlayerOrientation>(
        segments: <ButtonSegment<PlayerOrientation>>[
          for (final o in <PlayerOrientation>[
            PlayerOrientation.portrait,
            PlayerOrientation.landscape,
          ])
            ButtonSegment<PlayerOrientation>(
              value: o,
              label: Text(
                o == PlayerOrientation.portrait ? 'Portrait' : 'Landscape',
              ),
            ),
        ],
        selected: {orientation},
        showSelectedIcon: false,
        onSelectionChanged: (sel) {
          if (sel.isNotEmpty) onOrientationChanged(sel.first);
        },
        style: _segmentStyle(context),
      ),
    );
  }

  /// The one style all three segmented rows share (playback mode, the
  /// orientation policy, and the lock's direction).
  ///
  /// The label's colour comes from `foregroundColor` rather than from each
  /// `Text`, so the selected segment cannot end up with two colours fighting.
  /// The `textStyle` is built FROM the theme's own label style, and that is not
  /// cosmetic: a `ButtonStyle.textStyle` is what the labels are rendered with,
  /// so a bare `TextStyle` here replaces the inherited one and takes the font
  /// family with it — the panel then drew its segment labels in the engine's
  /// fallback face instead of the app's.
  ButtonStyle _segmentStyle(BuildContext context) => ButtonStyle(
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
    textStyle: WidgetStateProperty.all(
      (Theme.of(context).textTheme.labelLarge ??
              const TextStyle())
          .copyWith(fontSize: 12, fontWeight: FontWeight.w600),
    ),
    visualDensity: VisualDensity.compact,
    padding: WidgetStateProperty.all(const EdgeInsets.symmetric(vertical: 8)),
    shape: WidgetStateProperty.all(
      RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(RCrmRadii.md),
      ),
    ),
  );

  /// Two columns of label/value pairs, separated by tone rather than rules:
  /// the value is white and the label silver, and the rows breathe.
  Widget _facts() {
    return Column(
      children: [
        for (final f in facts)
          Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(
                  width: 116,
                  child: Text(
                    f.label,
                    style: const TextStyle(
                      color: RCrmColors.silver,
                      fontSize: 12,
                    ),
                  ),
                ),
                Expanded(
                  child: Text(
                    f.value,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 12,
                      // Numbers that do not shuffle as the row updates.
                      fontFeatures: [FontFeature.tabularFigures()],
                    ),
                  ),
                ),
              ],
            ),
          ),
      ],
    );
  }

  /// Grows the last few percent into place. The panel is a place the user asked
  /// to go, so it settles rather than appearing.
  Widget _entrance(BuildContext context, Widget child) {
    if (MediaQuery.disableAnimationsOf(context)) return child;
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: 1),
      duration: const Duration(milliseconds: 160),
      curve: Curves.easeOutCubic,
      builder: (_, t, inner) => Opacity(
        opacity: t,
        child: Transform.scale(scale: 0.98 + 0.02 * t, child: inner),
      ),
      child: child,
    );
  }
}
