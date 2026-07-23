// services/preview_player.dart
// A single shared Player + VideoController for inline hover/touch previews.
//
// Only one card previews at a time (hover and mobile sticky-preview are
// mutually exclusive), so reusing one Player avoids paying mpv's context
// creation cost on every hover — which caused the first-hover UI stutter.

import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import '../services/net.dart';

class PreviewClaim {
  final VideoController controller;
  final Player player;
  final int token;
  const PreviewClaim(this.controller, this.player, this.token);
}

class PreviewPlayer {
  PreviewPlayer._();
  static final PreviewPlayer instance = PreviewPlayer._();

  /// Runtime gate mirrored from the "Video Hover Preview" setting. When false,
  /// cards skip starting any inline preview (hover or finger).
  static bool enabled = true;

  Player? _player;
  VideoController? _controller;
  int _token = 0;

  VideoController? _ensure() {
    if (_player != null) return _controller;
    try {
      _player = Player();
      _player!.setVolume(0);
      _controller = VideoController(_player!);
    } catch (_) {
      // MediaKit unavailable — preview gracefully degrades.
      _player = null;
      _controller = null;
      return null;
    }
    return _controller;
  }

  /// Eagerly create the Player+VideoController so the first hover/preview
  /// doesn't pay mpv's context-creation cost (the first-hover stutter).
  void warmUp() {
    _ensure();
  }

  /// Claim the shared player for [url]; supersedes any prior claim.
  /// Returns null if MediaKit is unavailable.
  /// The caller renders Video(controller: claim.controller).
  PreviewClaim? claim(String url) {
    final c = _ensure();
    if (c == null) return null;
    _token++;
    final myToken = _token;
    _player!.open(Media(url, httpHeaders: sharedAuthHeader), play: true);
    return PreviewClaim(c, _player!, myToken);
  }

  /// True if [token] still owns the shared player.
  bool owns(int token) => token == _token;

  /// Stop playback if [token] still owns the player (pause, keep last frame).
  void release(int token) {
    if (token == _token) {
      _player?.pause();
    }
  }
}
