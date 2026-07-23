// widgets/finger_preview_listener.dart
// Mobile: detects which VideoCard is under the INITIAL touch point and
// makes that card preview. "Sticky": once a card starts previewing it
// keeps playing after the finger lifts — only a new touch-down whose
// first contact lands on a DIFFERENT card switches the preview.

import 'dart:io';
import 'package:flutter/material.dart';

/// Tracks the initial touch point to decide which card's [activePath] previews.
class FingerPreviewState {
  static final isMobile = Platform.isAndroid || Platform.isIOS;
  String? activePath;
  final Map<String, GlobalKey> keys = {};

  GlobalKey keyFor(String path) => keys.putIfAbsent(path, () => GlobalKey());

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

  bool isActive(String path) => isMobile && activePath == path;
}
