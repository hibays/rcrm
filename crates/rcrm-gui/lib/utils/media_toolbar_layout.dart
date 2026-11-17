// utils/media_toolbar_layout.dart
//
// The width → controls ladder for the library toolbar.
//
// This lives here, not in `widgets/media_toolbar.dart`, for the same reason
// `library_columns.dart` lives outside the grids: a widget test can only see
// the rendered result, while these are numbers with boundaries that need to be
// pinned directly. The toolbar reads the width `LayoutBuilder` gives IT — a
// wide window can still hand it a narrow column — and this file is the only
// owner of what that width means.

/// The toolbar's own width at which the third (tag) chip keeps its label.
///
/// A labeled chip measures ~110dp and the icon-only one ~40dp; at 414dp three
/// labeled chips plus the right-side icons overflow the row by ~60dp. 600dp is
/// where that third chip still has slack beside its two neighbours.
const double kToolbarTagLabelMinWidth = 600;

/// The narrow-width ladder for the optional RIGHT-side controls.
///
/// Same rule as `planPlayerControlBar`: a control with another door leaves
/// before one that would otherwise be unreachable. The sort arrow goes first
/// (re-picking the active sort chip reverses — its tooltip says so), then the
/// Organize trigger and the grid/list switch (both have a Settings row), and
/// only then the column button: on a narrow desktop window there is no pinch
/// gesture, so that button is the last way to change the grid.
///
/// Measured at compact size: the row wants 452dp at 414dp available; dropping
/// the 40dp arrow leaves 412dp, dropping the 16dp Organize trigger and the 40dp
/// layout toggle leaves 356dp, and dropping the 49dp column button too leaves
/// 307dp.
const double kToolbarSortArrowMinWidth = 460;
const double kToolbarRightIconsMinWidth = 400;
const double kToolbarColumnButtonMinWidth = 350;

/// What a toolbar of a given width may render.
class MediaToolbarLayout {
  /// Whether the tag chip drops its "Tags" label AND its label padding.
  final bool compactTagLabel;

  /// The sort-direction arrow; re-picking the active sort chip replaces it.
  final bool showSortArrow;

  /// The column-count button; a grid pinch reaches it on touch, and Settings
  /// reaches it everywhere, so this is the last optional control to leave.
  final bool showColumnButton;

  /// Organize and the grid/list switch; both have a Settings row.
  final bool showRightIcons;

  /// 8dp when the tag label is gone, 12dp otherwise.
  final double horizontalPadding;

  const MediaToolbarLayout({
    required this.compactTagLabel,
    required this.showSortArrow,
    required this.showColumnButton,
    required this.showRightIcons,
    required this.horizontalPadding,
  });

  @override
  bool operator ==(Object other) =>
      other is MediaToolbarLayout &&
      other.compactTagLabel == compactTagLabel &&
      other.showSortArrow == showSortArrow &&
      other.showColumnButton == showColumnButton &&
      other.showRightIcons == showRightIcons &&
      other.horizontalPadding == horizontalPadding;

  @override
  int get hashCode => Object.hash(
    compactTagLabel,
    showSortArrow,
    showColumnButton,
    showRightIcons,
    horizontalPadding,
  );
}

const MediaToolbarLayout _full = MediaToolbarLayout(
  compactTagLabel: false,
  showSortArrow: true,
  showColumnButton: true,
  showRightIcons: true,
  horizontalPadding: 12,
);

const MediaToolbarLayout _collapsed = MediaToolbarLayout(
  compactTagLabel: true,
  showSortArrow: false,
  showColumnButton: false,
  showRightIcons: false,
  horizontalPadding: 8,
);

/// The toolbar layout for the width it was actually given.
///
/// `double.infinity` means an unconstrained horizontal run, which gets the
/// full layout. NaN and negative widths are treated as collapsed: a layout
/// decision must never guess "wide" from a number that carries no width.
MediaToolbarLayout mediaToolbarLayout(double width) {
  if (width.isNaN) return _collapsed;
  if (width == double.infinity) return _full;
  return MediaToolbarLayout(
    compactTagLabel: width < kToolbarTagLabelMinWidth,
    showSortArrow: width >= kToolbarSortArrowMinWidth,
    showColumnButton: width >= kToolbarColumnButtonMinWidth,
    showRightIcons: width >= kToolbarRightIconsMinWidth,
    horizontalPadding: width < kToolbarTagLabelMinWidth ? 8 : 12,
  );
}
