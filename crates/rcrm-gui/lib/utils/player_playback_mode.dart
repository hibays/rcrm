// utils/player_playback_mode.dart
// What happens when a video ends — four modes, decided here rather than in the
// settings panel that used to own them.
//
// The panel lost this row when the mode moved to the transport bar. A mode is
// something a viewer changes WHILE watching — and changes their mind about,
// which is what the ending is for — and a control reached by leaving the
// picture to open a panel is a control reached at the wrong moment. The
// sentence that used to sit under the segmented row travels with each mode now
// (see [PlaybackMode.note]), because it was never really about the mode that
// happened to be selected: it was about the choice being made, and four choices
// need four sentences rather than one.
//
// The sentences are SHORT on purpose. They were a paragraph each for a while,
// and four paragraphs turned a four-choice menu into a settings page: 2 lines
// per row at 11dp, 350dp of menu on a 640dp phone, a wall of text over the
// picture the mode exists to leave alone. They still say what each mode does —
// the pair that is one letter apart still differs in exactly one phrase — but
// they say it in a line, because a menu is scanned, not read.
//
// All four are END-OF-STREAM behaviour, and that is what makes them one family
// rather than two settings. None of them changes what the transport bar's Next
// button does: that button still walks the Related list the viewer is looking
// at, and its promise — pressing Next plays a video you can see in that list —
// would be broken by a mode that quietly made the button draw from somewhere
// else. The mode decides what an ENDING offers, and nothing else.

/// What the player does when a file ends.
///
/// Ordered as the menu reads: the two modes that lead to a DIFFERENT video
/// (in Related order, then at random), then the one that keeps this video, then
/// the one that stops.
enum PlaybackMode {
  /// Offer the next video in Related through the card: the same list the Next
  /// button walks, same directory first.
  loopAll,

  /// Offer a random video from the Related list through the same card — a
  /// uniform draw over the rows the viewer can see, not the top of the list
  /// (`utils/shuffle_next.dart`).
  shuffle,

  /// Start this video again from the beginning.
  loopOne,

  /// Stop on the last frame and wait.
  pauseAfter;

  String get label => switch (this) {
    PlaybackMode.loopAll => 'Loop All',
    PlaybackMode.shuffle => 'Shuffle',
    PlaybackMode.loopOne => 'Loop One',
    PlaybackMode.pauseAfter => 'Pause After',
  };

  /// What the mode really does when a file ends, printed under the choice in
  /// the mode menu (and nowhere else — one home, like the control).
  ///
  /// It exists because the labels cannot carry it: "Loop All" and "Loop One" are
  /// one letter apart and describe opposite behaviour, and neither says where
  /// the next video comes from. Shuffle's sentence differs from Loop All's in
  /// exactly one word — where the video comes from — because that is the whole
  /// of the difference.
  ///
  /// The "8s" is the up-next card's own window. The card is where the viewer
  /// meets the countdown and where they can refuse it ("Play now", or the ✕);
  /// the menu only has to say that an ending leads to one, in the one line a
  /// menu row is read in.
  String get note => switch (this) {
    PlaybackMode.loopAll => 'Next video in Related, 8s',
    PlaybackMode.shuffle => 'Random video in Related, 8s',
    PlaybackMode.loopOne => 'Replay this video',
    PlaybackMode.pauseAfter => 'Stop on the last frame',
  };

  /// Whether an ending leads anywhere: the two modes whose answer is a video
  /// rather than this frame again or a full stop. The countdown card belongs to
  /// these and to no others.
  bool get offersNextVideo =>
      this == PlaybackMode.loopAll || this == PlaybackMode.shuffle;

  /// The stored form, as `settings_service` keeps it. Anything unrecognised
  /// (an older build's value, a hand-edited preference file) reads as the
  /// default rather than as an error: this is a preference, not data.
  String get key => switch (this) {
    PlaybackMode.loopAll => 'loopAll',
    PlaybackMode.shuffle => 'shuffle',
    PlaybackMode.loopOne => 'loopOne',
    PlaybackMode.pauseAfter => 'pauseAfter',
  };

  static PlaybackMode fromString(String s) {
    for (final m in PlaybackMode.values) {
      if (m.key == s) return m;
    }
    return PlaybackMode.pauseAfter;
  }
}
