// utils/menu_placement.dart
//
// Where an item menu opens, decided before it is laid out.
//
// The native popup flips because it measures itself and then repositions. A
// SmartDialog anchor is given an ALIGNMENT up front, so the direction has to be
// chosen from an estimate — and the estimate is exact enough to be useful: the
// panel is 8dp of padding around rows that are 48dp at 1.0x text (and grow with
// the reader's text scale). Being one row out only matters when the menu exactly
// fills the space below, and then the roomier side is still the better answer.

/// The height a menu of [rows] rows asks for, at [textScale].
///
/// 48dp is Material's minimum interactive row and the floor the shared menu
/// gives every row; past 1.0x a row grows, and the estimate follows it so a
/// large-text reader is not handed a menu twice the size the maths assumed.
/// Capped at 1.6x because that is where the row's own air (6dp above and below)
/// takes over from the text.
double estimatedMenuHeight(int rows, {double textScale = 1}) {
  final scale = textScale.isFinite ? textScale.clamp(1.0, 1.6) : 1.0;
  return rows * 48.0 * scale + 16;
}

/// Whether a menu anchored at [anchorY] should open ABOVE that line.
///
/// Opens downward whenever it fits, because that is the direction a menu is read
/// in and the direction the pointer's own movement implies. Only when the space
/// below cannot hold it does it flip — and if neither side fits, it takes the
/// roomier one: the menu is clamped to the screen either way, and covering the
/// item from the side with more room is the least bad answer.
bool menuOpensUpward({
  required double anchorY,
  required double screenHeight,
  required int rows,
  double textScale = 1,
  double margin = 8,
}) {
  final height = estimatedMenuHeight(rows, textScale: textScale);
  final below = screenHeight - anchorY - margin;
  final above = anchorY - margin;
  if (below >= height) return false;
  if (above >= height) return true;
  return above > below;
}
