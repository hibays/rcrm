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
// The map: Space/K play-pause, J/L and ←/→ skip 10s, ↑/↓ volume, M mute,
// `,`/`.` rate, F fullscreen, Esc back. K and M are video.js's own hotkeys;
// J/L and `,`/`.` are the pair every other player taught the same users.
//
// Callbacks are optional so each surface wires only what it needs — a key whose
// callback is null does nothing AND does not swallow the event. While a text
// field or slider holds focus, the keys a typist needs are left to it.

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

  /// M key. Null = M ignored.
  final VoidCallback? onToggleMute;

  /// `,` and `.`, as a relative rate step (negative = slower). Null = inert.
  final void Function(double delta)? onSpeed;

  const MediaPlayerKeyActions({
    this.onTogglePlay,
    this.onSeek,
    this.onVolume,
    this.onEscape,
    this.onToggleFullscreen,
    this.onToggleMute,
    this.onSpeed,
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

  /// Whether the keyboard belongs to a text field right now.
  ///
  /// The node that holds a text field's keys is the `EditableText` INSIDE it,
  /// never the `TextField` the caller wrote — so testing only the focus node's
  /// own widget (which is what this used to do) left every letter key armed
  /// while the user was typing, and `m` muted the video instead of typing an
  /// `m`. The ancestor walk is what actually finds the field.
  static bool _isEditing(FocusNode? focus) {
    final ctx = focus?.context;
    if (ctx == null) return false;
    final w = ctx.widget;
    if (w is TextField ||
        w is TextFormField ||
        w is EditableText ||
        w is SelectableText) {
      return true;
    }
    return ctx.findAncestorWidgetOfExactType<EditableText>() != null;
  }

  bool _onKey(KeyEvent event) {
    if (event is! KeyDownEvent && event is! KeyRepeatEvent) return false;
    final a = widget.actions;
    final key = event.logicalKey;
    final focus = FocusManager.instance.primaryFocus;
    final editing = _isEditing(focus);
    // Sliders consume left/right; let them have it while focused. Found by
    // ANCESTRY for the same reason as the text field above: the node a Slider
    // focuses belongs to a `Focus` widget built INSIDE it, never to the Slider
    // itself, so the old `context.widget is Slider` test never once matched and
    // a focused seek bar moved twice per arrow press.
    final onSlider =
        focus?.context?.findAncestorWidgetOfExactType<Slider>() != null;

    // Every key below is the PLAYER's only while nobody is typing. Space is
    // last in that queue, not first: a space is a space.
    if (editing) return false;

    if (key == LogicalKeyboardKey.space && a.onTogglePlay != null) {
      a.onTogglePlay!();
      return true;
    }
    // K is play/pause and M is mute because those are video.js's own two
    // hotkeys — the same letters a viewer already has in their fingers from
    // every other player. J/L (the YouTube pair) join the arrow keys, and
    // `,`/`.` step the rate.
    if (key == LogicalKeyboardKey.keyK && a.onTogglePlay != null) {
      a.onTogglePlay!();
      return true;
    }
    if (key == LogicalKeyboardKey.keyM && a.onToggleMute != null) {
      a.onToggleMute!();
      return true;
    }
    if (key == LogicalKeyboardKey.arrowLeft && !onSlider && a.onSeek != null) {
      a.onSeek!(const Duration(seconds: -10));
      return true;
    }
    if (key == LogicalKeyboardKey.arrowRight && !onSlider && a.onSeek != null) {
      a.onSeek!(const Duration(seconds: 10));
      return true;
    }
    if (key == LogicalKeyboardKey.keyJ && a.onSeek != null) {
      a.onSeek!(const Duration(seconds: -10));
      return true;
    }
    if (key == LogicalKeyboardKey.keyL && a.onSeek != null) {
      a.onSeek!(const Duration(seconds: 10));
      return true;
    }
    if (key == LogicalKeyboardKey.comma && a.onSpeed != null) {
      a.onSpeed!(-0.25);
      return true;
    }
    if (key == LogicalKeyboardKey.period && a.onSpeed != null) {
      a.onSpeed!(0.25);
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
