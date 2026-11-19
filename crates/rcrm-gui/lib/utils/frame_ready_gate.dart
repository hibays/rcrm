// utils/frame_ready_gate.dart
// Event-driven "the new video has a frame" gate for the inline preview.
//
// The preview reveals the Video layer only after the freshly-opened video has
// real dimensions. A positive `stream.width` event is published by media_kit
// after `open()` resets width=null and the new video's videoParams arrive — so
// it belongs to the NEW video and cannot be a stale frame from the previous one
// that was still on the shared player when the hover began.
//
// An FFI property probe (screenshot / video-frame-info) reads the player's
// CURRENT frame, which on a shared player is still the previous video's during
// `open()` — that made the gate open instantly and flash the old frame. This
// gate deliberately uses no such probe. A deadline is the only fallback, so a
// stalled open still reveals eventually.
//
// Generation-guarded: a fast hover across cards cannot let a superseded open
// reveal a stale preview.

import 'dart:async';

class FrameReadyGate {
  FrameReadyGate(
    this._onReady, {
    this.deadline = const Duration(milliseconds: 1200),
  });

  final void Function() _onReady;
  final Duration deadline;

  Timer? _timer;
  int _gen = 0;
  bool _ready = false;
  bool _armed = false;

  bool get ready => _ready;

  /// Start a new generation. [onWidth] calls after this decide when to open.
  void arm() {
    _gen++;
    _ready = false;
    _armed = true;
    _timer?.cancel();
    final gen = _gen;
    _timer = Timer(deadline, () {
      if (gen == _gen && !_ready) _finish();
    });
  }

  /// Feed a width event from `player.stream.width`. Only a positive value opens
  /// the gate; null/zero (the reset) are ignored.
  void onWidth(int? width) {
    if (_ready || !_armed) return;
    if ((width ?? 0) > 0) _finish();
  }

  void _finish() {
    if (_ready || !_armed) return;
    _armed = false;
    _timer?.cancel();
    _timer = null;
    _ready = true;
    _onReady();
  }

  /// Abandon this generation. [_onReady] will not fire for it.
  void cancel() {
    _gen++;
    _armed = false;
    _timer?.cancel();
    _timer = null;
    _ready = false;
  }
}
