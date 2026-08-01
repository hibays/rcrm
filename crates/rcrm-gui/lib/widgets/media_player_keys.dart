// widgets/media_player_keys.dart
// Shared desktop keyboard handling for media playback surfaces
// (video player screen + cast receiver playing page).
//
// Uses HardwareKeyboard (global, focus-independent) instead of
// CallbackShortcuts/Focus: on desktop the Flutter focus can land anywhere
// (autofocus only fires on first mount, sliders/buttons steal focus), which
// made arrows/space/ESC silently dead. A global handler works as long as the
// window has keyboard focus — the reliable path for media players.
//
// Callbacks are optional so each surface wires only what it needs. While a
// text field or slider holds focus, arrows are left to that widget.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// What a surface wants the media keys to do.
class MediaPlayerKeyActions {
  /// Toggle play/pause. Null = space does nothing.
  final VoidCallback? onTogglePlay;

  /// Seek by a relative delta (negative = backward). Null = arrows inert.
  final void Function(Duration delta)? onSeek;

  /// Change volume by a relative step (0..1 scale for media_kit).
  final void Function(double delta)? onVolume;

  /// ESC action (e.g. exit fullscreen, stop playback). Null = ESC ignored.
  final VoidCallback? onEscape;

  /// F key action (e.g. toggle fullscreen). Null = F ignored.
  final VoidCallback? onToggleFullscreen;

  const MediaPlayerKeyActions({
    this.onTogglePlay,
    this.onSeek,
    this.onVolume,
    this.onEscape,
    this.onToggleFullscreen,
  });
}

/// Registers a global key handler for the lifetime of the widget.
/// Wrap your media surface (or place it anywhere in the tree).
class MediaPlayerKeys extends StatefulWidget {
  final MediaPlayerKeyActions actions;
  final Widget child;

  const MediaPlayerKeys({
    super.key,
    required this.actions,
    required this.child,
  });

  @override
  State<MediaPlayerKeys> createState() => _MediaPlayerKeysState();
}

class _MediaPlayerKeysState extends State<MediaPlayerKeys> {
  KeyEventCallback? _handler;

  @override
  void initState() {
    super.initState();
    _handler = _onKey;
    HardwareKeyboard.instance.addHandler(_handler!);
  }

  @override
  void dispose() {
    if (_handler != null) {
      HardwareKeyboard.instance.removeHandler(_handler!);
      _handler = null;
    }
    super.dispose();
  }

  bool _onKey(KeyEvent event) {
    if (event is! KeyDownEvent && event is! KeyRepeatEvent) return false;
    final a = widget.actions;
    final key = event.logicalKey;
    final focus = FocusManager.instance.primaryFocus;
    final editing =
        focus?.context?.widget is TextField ||
        focus?.context?.widget is TextFormField ||
        focus?.context?.widget is SelectableText;
    // Sliders consume left/right; let them have it while focused.
    final onSlider = focus?.context?.widget is Slider;

    if (key == LogicalKeyboardKey.space && a.onTogglePlay != null) {
      a.onTogglePlay!();
      return true;
    }
    if (!editing) {
      if (key == LogicalKeyboardKey.arrowLeft &&
          !onSlider &&
          a.onSeek != null) {
        a.onSeek!(const Duration(seconds: -10));
        return true;
      }
      if (key == LogicalKeyboardKey.arrowRight &&
          !onSlider &&
          a.onSeek != null) {
        a.onSeek!(const Duration(seconds: 10));
        return true;
      }
      if (key == LogicalKeyboardKey.arrowUp && a.onVolume != null) {
        a.onVolume!(0.05);
        return true;
      }
      if (key == LogicalKeyboardKey.arrowDown && a.onVolume != null) {
        a.onVolume!(-0.05);
        return true;
      }
    }
    if (key == LogicalKeyboardKey.escape && a.onEscape != null) {
      a.onEscape!();
      return true;
    }
    if (key == LogicalKeyboardKey.keyF && a.onToggleFullscreen != null) {
      a.onToggleFullscreen!();
      return true;
    }
    return false;
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
