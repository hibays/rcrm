// utils/player_eof.dart
// Where a finished file is, and what a seek does to that.
//
// This is a VALUE, not a set of loose predicates, and it is the only place the
// app is allowed to keep the ending. It has to: media_kit reports
// `playing: false` when `eof-reached` goes to 1 and NOTHING ever undoes it. There
// is no handler for `eof-reached` returning to 0, `seek` does not touch `playing`,
// and the only other writers are `stop()` and `play()`. So the app cannot learn
// from the player that a file has become live again, and cannot learn from it
// that one is still the finished file it was.
//
// WHY THE SEEK, AND NOT THE POSITION STREAM — this is the second version of this
// rule and the first one shipped frozen. The first inferred a take-back from the
// position reports, reasoning that the position was "the only signal that can
// report it". It is not: the four seeks this screen issues (bar scrub, the mobile
// horizontal swipe, the PiP drag, the arrow keys) are OUR calls, so the
// direction is known exactly instead of reconstructed. mpv's position reports
// cannot be trusted to mean "the viewer went back", because seeking PAST the end
// — which is exactly what holding the right arrow key does, since the cached
// `state.position` is stale once the file is paused at its last frame — clamps,
// and the clamped result reads as a backwards move. That cost two bugs at once:
// the up-next offer was withdrawn by a forward gesture, and an un-pause was
// issued on a file that immediately reached eof again, so the picture froze with
// the transport claiming "playing".
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
  /// fact that comes and goes (see the file header). Two things read it:
  ///
  ///  * the completion handler, as a LATCH -- one end-of-playback decision per
  ///    ending. mpv reports the end again after every take-back, and `loopOne`
  ///    re-enters this same file immediately, so a second pass would seek a video
  ///    the viewer had just dragged back to 0.
  ///  * the stall timer: nothing is loading on a finished file, so a spinner over
  ///    the last frame claims "working on it" about nothing.
  ///
  /// The position stream is deliberately NOT a reader: see the header.
  final bool finished;

  const PlayerEof({this.finished = false});

  /// How far a seek must go BACKWARDS before it counts as the viewer taking the
  /// video back, rather than a nudge inside the frame they are already on.
  ///
  /// Not zero, because the scrub bar re-seeks continuously while a pointer or
  /// finger is down, and a target that sits a few milliseconds behind the
  /// reported position is a hand settling rather than a decision. A deliberate
  /// move is orders of magnitude larger: the arrow keys jump 10s, and a
  /// full-width bar on a ten-minute video is ~0.6ms per pixel.
  static const Duration takeBackEpsilon = Duration(milliseconds: 200);

  /// The state of a file that has not finished: a new one, a restarted one, or
  /// one the viewer took back.
  static const PlayerEof idle = PlayerEof();

  /// The file has ended. `completed: true` is the only way in: media_kit also
  /// publishes `completed: false` every time a file STARTS (`stop()`, which
  /// `open()` calls internally), and treating that as an ending would offer the
  /// next video over one that has only just begun.
  PlayerEof ended() => const PlayerEof(finished: true);

  /// The state after a seek to [target] from [current].
  ///
  /// Backwards by more than [takeBackEpsilon], and only while the file is
  /// finished: that is the viewer taking it back, and the caller withdraws the
  /// offer and un-pauses (mpv leaves a finished file paused on its last frame, so
  /// the seek alone moves `time-pos` and wakes nothing).
  ///
  /// Forwards, or by less than the epsilon, this state comes back unchanged --
  /// including a forward seek past the end, which is what holding the right
  /// arrow key does and which must stay a forward seek.
  PlayerEof seeked({
    required Duration target,
    required Duration current,
  }) => finished && target < current - takeBackEpsilon ? idle : this;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PlayerEof && other.finished == finished;

  @override
  int get hashCode => finished.hashCode;

  @override
  String toString() => 'PlayerEof(finished: $finished)';
}