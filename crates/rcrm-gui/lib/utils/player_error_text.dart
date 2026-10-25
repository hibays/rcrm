// utils/player_error_text.dart
//
// The two pure pieces of the player's error path: which libmpv log lines are
// fatal to an OPEN, and how an exception/log is shown in the error overlay.
// Both are here because `video_player_screen.dart` cannot be mounted in a test
// (it creates a native media_kit Player).

import 'package:media_kit/media_kit.dart';

/// True for the ffmpeg HTTP failures that media_kit's `stream.error` drops.
///
/// media_kit forwards only ffmpeg errors whose text starts with `tcp:` (see
/// `real.dart`), so an HTTP 404 arrives solely on the log stream. The screen
/// only uses this while the open is still waiting for its first frame; an HTTP
/// error during playback must not cover a file that is still working.
bool isFatalHttpLog(PlayerLog log) {
  if (log.level != 'error' || log.prefix != 'ffmpeg') return false;
  return log.text.trim().toLowerCase().startsWith('http:');
}

/// A player error as one bounded line, safe to paint in the overlay.
String describePlaybackError(Object error) {
  var text = error.toString().replaceAll(RegExp(r'\s+'), ' ').trim();
  if (text.isEmpty) return 'The player could not open this video.';
  if (text.length > 180) text = '${text.substring(0, 177)}...';
  return text;
}
