// utils/player_eof.dart
// Where a finished file is, and the one question the position stream asks while
// the player is sitting there.
//
// This is a VALUE, not a set of loose predicates, and it is the only place the
// app is allowed to keep the ending. It has to: media_kit reports
// `playing: false` when `eof-reached` goes to 1 and NOTHING ever undoes it. There
// is no handler for `eof-reached` returning to 0, `seek` does not touch `playing`,
// and the only other writers are `stop()` and `play()`. So after the viewer drags
// the bar back from the last frame the SCREEN still believes the file is paused,
// whatever mpv is doing -- and the offer to play the next video counts down over a
// video the viewer is watching again. The position is the only signal in the
// whole player that can report any of it, and reading it is arithmetic.
//
// (What the picture is doing afterwards is NOT this file's business and used to
// be assumed wrongly: media_kit runs mpv with `--keep-open=yes`, so a finished
// file is left PAUSED on its last frame and dragging the bar back moves
// `time-pos` without waking anything up. `video_player_screen._resumeAfterTakeBack`
// is what actually starts it, because `p.play()` would restart the file at 0
// instead — see there.)
//
// Immutable on purpose, like every other value this screen reduces over: each
// event answers with the next value, a test asserts on the pairs without a
// widget, and two equal states really are the same state (`==`), which is what
// lets the screen ask "did that change anything?" instead of keeping a second
// copy of the truth to compare against.

import 'package:flutter/foundation.dart';

/// The end of a file, as far as this app is concerned.
@immutable
class PlayerEof {
  /// True from the moment the file finished until the viewer takes it back, a new
  /// file starts, or `loopOne` restarts this one in place.
  ///
  /// The app's own memory of the ending, because media_kit cannot report it as a
  /// fact that comes and goes (see the file header). Three things read it, and
  /// each was wrong without it:
  ///
  ///  * the completion handler, as a LATCH -- one end-of-playback decision per
  ///    ending. mpv reports the end again after every take-back, and `loopOne`
  ///    re-enters this same file immediately, so a second pass would seek a video
  ///    the viewer had just dragged back to 0.
  ///  * the stall timer: nothing is loading on a finished file, so a spinner over
  ///    the last frame claims "working on it" about nothing.
  ///  * the position stream, which is the only thing that reports a take-back.
  final bool finished;

  /// Where the position stood when the file finished, in milliseconds. Meaningful
  /// only while [finished]; the baseline [onPosition] measures against.
  ///
  /// Fixed rather than re-tracked on every report: the reports wobble a frame or
  /// two around the duration at the end of a file, and a wobble is already inside
  /// [takeBackEpsilonMs], so following it would buy nothing and would make "did
  /// anything change?" mean two different things.
  final int endPositionMs;

  const PlayerEof({this.finished = false, this.endPositionMs = 0});

  /// How far the position must move BACKWARDS before it counts as the viewer
  /// taking the video back, rather than the last frame being reported.
  ///
  /// Not zero, because at the end of a file the reported position sits within a
  /// frame or two of the duration and wobbles there -- a dropped frame, a
  /// container whose last timestamp rounds down, `demuxer-cache-time` settling.
  /// A viewer dragging backwards moves hundreds of milliseconds at a time (a
  /// full-width bar for a ten-minute video is ~0.6ms per pixel), so anything
  /// inside this window is noise and anything outside it is a deliberate move.
  static const int takeBackEpsilonMs = 200;

  /// The state of a file that has not finished: a new one, a restarted one, or
  /// one the viewer took back.
  static const PlayerEof idle = PlayerEof();

  /// The file has ended, having stopped at [positionMs].
  ///
  /// The baseline is the position at that instant, which is what the next
  /// position report is measured against. `completed: true` is the only way in:
  /// media_kit also publishes `completed: false` every time a file STARTS
  /// (`stop()`, which `open()` calls internally), and treating that as an ending
  /// offers the next video over one that has only just begun.
  PlayerEof endedAt(int positionMs) =>
      PlayerEof(finished: true, endPositionMs: positionMs);

  /// A position report, which is either this state or the evidence that the
  /// viewer has taken the video back.
  ///
  /// Backwards only, and by more than [takeBackEpsilonMs]: a finished file has
  /// nothing ahead of where it stopped, so a forward report is not a take-back,
  /// and a millimetre of jitter is not an intent. Returns `this` unchanged when
  /// nothing happened, so the caller can ask `next != _eof` and be right.
  PlayerEof onPosition(int positionMs) =>
      finished && positionMs < endPositionMs - takeBackEpsilonMs ? idle : this;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PlayerEof &&
          other.finished == finished &&
          other.endPositionMs == endPositionMs;

  @override
  int get hashCode => Object.hash(finished, endPositionMs);

  @override
  String toString() =>
      'PlayerEof(finished: $finished, at: ${endPositionMs}ms)';
}