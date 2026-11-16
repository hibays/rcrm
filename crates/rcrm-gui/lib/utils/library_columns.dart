// utils/library_columns.dart
//
// The arithmetic of the library's column choices — one owner for every rule
// that turns a pinch, a window width or a stored preference into a number of
// columns. It lives here rather than in the widgets because a widget test can
// only measure the outcome; these rules are easiest to pin where they run on
// numbers (the same reason `utils/thumb_cache_policy.dart` and
// `utils/player_orientation.dart` exist).
//
// Two gestures share the file on purpose: the grid's two-finger pinch and the
// list's, and they are NOT the same rule. A grid pinch changes the count
// continuously (the cell is the unit); a list pinch only has two honest answers
// (a row per line, or two), because a "3-column list" is a grid with worse
// metadata.

/// The grid's column count for a pinch whose cumulative scale is [scale].
///
/// [startColumns] is the count the gesture STARTED on, not the current one: a
/// live-changing count fed back into its own input would compound (the first
/// step would move the rest of the gesture's reference point, so every later
/// frame would step again) and the grid would run to the end of its range under
/// a still finger.
///
/// Spreading two fingers ([scale] > 1) makes cells bigger, so it asks for FEWER
/// columns — the direction every gallery app uses. The result is rounded and
/// clamped: a pinch is an analogue gesture aiming at a discrete number.
int pinchColumnCount({
  required int startColumns,
  required double scale,
  required int min,
  required int max,
}) {
  final lo = min < 1 ? 1 : min;
  final hi = max < lo ? lo : max;
  if (!scale.isFinite || scale <= 0) return startColumns.clamp(lo, hi);
  final raw = startColumns / scale;
  if (!raw.isFinite) return startColumns.clamp(lo, hi);
  return raw.round().clamp(lo, hi);
}

/// How far a pinch must travel before the video LIST changes its answer.
///
/// A list has two states, so a threshold is the whole gesture: without one, a
/// two-finger scroll (which barely changes the span) would flip the layout, and
/// a wobble around 1.0 would flicker between one and two columns. 20% of span
/// change is about the point a viewer would call the pinch deliberate.
const double kPinchListStep = 1.2;

/// The video list's column count for a pinch, or null while the pinch has not
/// travelled far enough to mean anything.
///
/// Spreading the fingers asks for BIGGER rows, which is one column; pinching in
/// asks for more of them per line.
int? pinchListColumns({required double scale}) {
  if (!scale.isFinite || scale <= 0) return null;
  if (scale >= kPinchListStep) return 1;
  if (scale <= 1 / kPinchListStep) return 2;
  return null;
}

/// Where an AUTOMATIC two-column video list starts.
///
/// 840dp is Material's "expanded" window class — the same breakpoint Flutter's
/// adaptive guidance uses for a layout that stops being a single column. Below
/// it a row's title and metadata need the full width; above it a single row is a
/// very long line of text with a thumbnail at one end.
const double kTwoColumnListAutoWidth = 840;

/// The narrowest window in which an EXPLICIT two-column list is honoured.
///
/// 600dp is Material's "medium" class. The floor is not arbitrary: a
/// `VideoListTile` is a 100dp row whose thumbnail takes up to 42% of its width,
/// so at half a phone (≈180dp per column) the text column is <100dp — a title
/// that has to wrap twice and metadata that has to wrap, inside a row that
/// cannot grow. That is an overflow, not a layout. Below this width the list
/// stays one column whatever the stored preference says; the GRID is where a
/// phone changes its columns, and a wide (landscape/desktop) window gets the
/// two-column list the setting names.
const double kTwoColumnListMinWidth = 600;

/// The video list's column count: the stored mode when it names one, otherwise
/// the responsive answer for [width].
///
/// The stored vocabulary is 'auto' | 'one' | 'two' and an unknown value reads as
/// 'auto' — a preference file this build did not write must not invent a layout.
int videoListColumnCount({required String mode, required double width}) {
  final twoAllowed = width >= kTwoColumnListMinWidth;
  return switch (mode) {
    'one' => 1,
    'two' => twoAllowed ? 2 : 1,
    _ => twoAllowed && width >= kTwoColumnListAutoWidth ? 2 : 1,
  };
}

/// The height a video-list ROW needs, for [columns] rows on one line.
///
/// The row's content is a title of up to two lines, the duration and the
/// `size • extension` line — about 114dp at 1.0x. A full-width row gives the
/// text column enough room that the last line never wraps, so the established
/// 100dp row still fits; a two-column cell halves the width, the size line
/// wraps, and 100dp is 14dp short (measured at 600-620dp, the exact widths
/// `kTwoColumnListMinWidth` declares legal). The row height therefore follows
/// the cell width AND the reader's text scale, and `VideoListTile` derives its
/// 16:9 thumbnail from the same number so the poster never gets letterboxed
/// into a 100dp band under a taller row.
///
/// Capped at 1.5x for the same reason `estimatedMenuHeight` caps: past that the
/// row's own padding takes over, and an unbounded multiple would push a phone
/// list into one row per screen.
double videoListRowHeight({
  required int columns,
  required double textScale,
}) {
  final scale = textScale.isFinite ? textScale.clamp(1.0, 1.5) : 1.0;
  return (columns > 1 ? 116.0 : 100.0) * scale;
}

/// The video grid's allowed column range at [width].
///
/// Extracted so the screen that DRAWS the grid and the gesture that CHANGES it
/// clamp to the same numbers: a pinch that asks for a column the build would
/// refuse is a column that silently does not appear.
class VideoGridBounds {
  final int min;
  final int max;
  const VideoGridBounds(this.min, this.max);

  /// The stored choice as this width can actually show it.
  int resolve(int stored) => stored.clamp(min, max);

  @override
  bool operator ==(Object other) =>
      other is VideoGridBounds && other.min == min && other.max == max;

  @override
  int get hashCode => Object.hash(min, max);
}

/// One card is at least 160dp wide, so a window shows as many columns as fit in
/// that budget, never fewer than one and never more than six.
///
/// A phone may go down to a single column (its cards are the viewport, which is
/// what one-handed browsing wants); a desktop window keeps at least two, because
/// one column of 160dp-wide cards on a 1920px screen is a list pretending to be
/// a grid.
VideoGridBounds videoGridBounds({
  required double width,
  required bool mobile,
}) {
  const minCardWidth = 160.0;
  final maxByWidth = (width / minCardWidth).floor().clamp(1, 6);
  final min = mobile ? 1 : (maxByWidth < 2 ? 1 : 2);
  return VideoGridBounds(min, maxByWidth);
}

/// The image grid's upper bound at [width]: at least two columns, at most eight,
/// and never a cell narrower than 100dp.
int imageGridMaxColumns(double width) => (width / 100).floor().clamp(2, 8);