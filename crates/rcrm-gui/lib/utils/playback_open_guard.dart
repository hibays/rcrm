// utils/playback_open_guard.dart
//
// The state of ONE media open, split out of `video_player_screen.dart` so it
// can be tested: the screen itself cannot be mounted in a test process (it
// creates a native media_kit Player).
//
// The guard owns only the facts that must agree:
// * which open attempt is current (a generation),
// * whether its first frame/duration/shape has arrived,
// * why it failed, and whether that failure was the timeout watchdog.
//
// The screen owns the `Timer` and the UI; this class owns the transitions. That
// keeps every "stale generation" or "timeout withdraws when the file finally
// loads" rule in a pure value object, the same way `PlayerEof` and
// `PlayerVolume` keep their rules out of the un-mountable screen.

/// One failed open. [watchdog] says the failure came from the deadline rather
/// than from the player, because a late file load may withdraw a timeout but
/// must never hide a decode/HTTP error.
class PlaybackOpenFailure {
  final String message;
  final bool watchdog;

  const PlaybackOpenFailure(this.message, {this.watchdog = false});
}

class PlaybackOpenGuard {
  int _generation = 0;
  bool _opened = false;
  PlaybackOpenFailure? _failure;

  int get generation => _generation;
  bool get opened => _opened;
  PlaybackOpenFailure? get failure => _failure;
  bool get hasFailure => _failure != null;

  /// True while this attempt may still produce a first frame (no success and no
  /// failure). The HTTP-log fallback uses this so a log arriving after playback
  /// started cannot cover a working file.
  bool get waitingForFirstFrame => !_opened && _failure == null;

  /// Start a new attempt and drop the previous attempt's outcome.
  int begin() {
    _generation++;
    _opened = false;
    _failure = null;
    return _generation;
  }

  bool isCurrent(int generation) => generation == _generation;

  /// The watchdog may only fire for the attempt it was armed for, before either
  /// a first frame or a failure.
  bool shouldTimeout(int generation) =>
      generation == _generation && !_opened && _failure == null;

  /// Record a first-frame proof for the CURRENT attempt.
  ///
  /// Returns true when the screen should withdraw a timeout error (including
  /// the case where this attempt had already opened). Returns false when a
  /// player/decode error is in force: such an error must stay visible even if a
  /// late duration/shape report arrives.
  bool markOpened() {
    final current = _failure;
    if (current != null) {
      if (!current.watchdog) return false;
      // The server finally answered: the timeout was a false alarm.
      _failure = null;
    }
    _opened = true;
    return true;
  }

  /// Record [message] against [generation]. A stale generation is ignored.
  ///
  /// A player/decode error may replace a timeout (it is the more specific
  /// answer); a timeout may not replace a real player error. Returns true when
  /// the screen should show [message].
  bool fail(int generation, String message, {bool watchdog = false}) {
    if (generation != _generation) return false;
    final current = _failure;
    if (current != null) {
      if (current.watchdog && !watchdog) {
        _failure = PlaybackOpenFailure(message);
        return true;
      }
      return false;
    }
    _failure = PlaybackOpenFailure(message, watchdog: watchdog);
    return true;
  }

  /// Clear the outcome for a Retry that has not begun its new open yet (the
  /// caller may need to create the Player first). The generation is unchanged;
  /// the following [begin] advances it.
  void clearFailure() {
    _failure = null;
  }
}
