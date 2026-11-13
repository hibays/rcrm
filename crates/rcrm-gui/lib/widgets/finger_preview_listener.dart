// widgets/finger_preview_listener.dart
// Mobile: detects which VideoCard is under the INITIAL touch point and
// makes that card preview. "Sticky": once a card starts previewing it
// keeps playing after the finger lifts — only a new touch-down whose
// first contact lands on a DIFFERENT card switches the preview.

import 'dart:io';
import 'package:material_ui/material_ui.dart';

/// One surface's cards: a list, a grid, a sheet, the end card.
///
/// A GlobalKey may be mounted only ONCE in a widget tree, and two surfaces
/// can show the SAME file at the same time — the player's Related list beside
/// the picture and the end card floating over it. One key per path would
/// hand both the same key, and the framework would move the first card's
/// element into the second card's slot: the surface that lost it renders
/// BLANK.
///
/// So a key lives in a surface, and each surface answers "is MY card the one
/// previewing?" on its own. Two surfaces never share a name: the name is the
/// namespace the keys live in, and a repeated name is the bug this class
/// exists to prevent.
class FingerPreviewSurface {
  FingerPreviewSurface(this._state, this.name);

  final FingerPreviewState _state;

  /// The surface's name — the namespace its keys live in.
  final String name;

  /// The key for [path] on THIS surface.
  GlobalKey keyFor(String path) => _state._keyFor(name, path);

  /// Whether the card for [path] on THIS surface is the one previewing.
  bool isActive(String path) => _state._isActive(name, path);
}

/// Tracks the initial touch point to decide which card's [activePath] previews.
class FingerPreviewState {
  static final isMobile = Platform.isAndroid || Platform.isIOS;
  String? activePath;
  final Map<String, GlobalKey> keys = {};

  /// A named surface: its own key namespace, and its own answer to "is this
  /// the card being previewed". Two surfaces on screen at the same time MUST
  /// be two surfaces — see [FingerPreviewSurface].
  FingerPreviewSurface surface(String name) => FingerPreviewSurface(this, name);

  /// The key for [path] on the surface called [surface]. The surface name is
  /// part of the key, so the same file on two surfaces is two keys.
  GlobalKey _keyFor(String surface, String path) =>
      keys.putIfAbsent('$surface\u0000$path', () => GlobalKey());

  bool _isActive(String surface, String path) =>
      isMobile && activePath == '$surface\u0000$path';

  /// On the first contact of a touch: if it lands on a card, switch the
  /// preview to it. If it lands on empty space, do nothing (keep current).
  void onPointerDown(
    PointerDownEvent e,
    void Function(void Function()) setState,
  ) {
    if (!isMobile) return;
    for (final entry in keys.entries) {
      final ctx = entry.value.currentContext;
      if (ctx == null) continue;
      final box = ctx.findRenderObject() as RenderBox?;
      if (box == null) continue;
      try {
        final local = box.globalToLocal(e.position);
        if (local.dx >= 0 &&
            local.dy >= 0 &&
            local.dx < box.size.width &&
            local.dy < box.size.height) {
          if (entry.key != activePath) setState(() => activePath = entry.key);
          return;
        }
      } catch (_) {}
    }
    // No card under the first touch → keep whatever is currently playing.
  }
}
