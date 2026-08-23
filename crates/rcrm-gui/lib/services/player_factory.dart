// services/player_factory.dart
// Single place where media_kit Players are created, so the mpv tuning that
// keeps low-RAM devices (ARMv7 phones/TVs) stable applies everywhere.
//
// What we override and why (media_kit 1.2.6 defaults):
// * `demuxer-max-bytes` / `demuxer-max-back-bytes` both follow
//   [PlayerConfiguration.bufferSize], whose default is 32 MiB — up to 64 MiB
//   of demux cache per player. On a ≤1 GB ARMv7 TV that alone competes with
//   the Flutter engine and decoded frames, pushing the device into
//   low-memory thrash (stuttering playback AND slow control responses).
// * media_kit hardcodes `cache-on-disk: yes`; mpv then writes the stream
//   cache to disk. This project guarantees zero plaintext disk writes, so it
//   is turned off for every player.

import 'dart:io' show Platform;

import 'package:media_kit/media_kit.dart';

class PlayerFactory {
  PlayerFactory._();

  /// Demux-cache budget for main playback (video player screen, cast
  /// receiver, hover previews). Desktop keeps media_kit's default.
  static final int _playbackBufferSize = Platform.isAndroid || Platform.isIOS
      ? 16 << 20
      : 32 << 20;

  /// Demux-cache budget for poster/screenshot players: they seek and grab a
  /// frame within seconds of opening, so a small window is plenty. The
  /// desktop pool runs up to ItemCacheLimit.videoPosterConcurrency players
  /// at once, which multiplies this budget.
  static final int _posterBufferSize = Platform.isAndroid || Platform.isIOS
      ? 4 << 20
      : 8 << 20;

  /// Create a [Player] for media playback with the app-wide tuning applied.
  static Player playback() => _create(_playbackBufferSize);

  /// Create a [Player] for poster generation (screenshot pipeline).
  static Player poster() => _create(_posterBufferSize);

  static Player _create(int bufferSize) {
    final player = Player(
      configuration: PlayerConfiguration(bufferSize: bufferSize),
    );
    // setProperty waits for the player's async initialization before writing,
    // so this safely overrides media_kit's own init-time `cache-on-disk: yes`.
    final platform = player.platform;
    if (platform is NativePlayer) {
      platform.setProperty('cache-on-disk', 'no').catchError((_) {});
    }
    return player;
  }
}
