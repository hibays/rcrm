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

/// Below this the row cannot hold every control — even with the compact tag —
/// so every right-side control folds into ONE overflow button on the right.
/// That button costs the ~40dp the bare `#` chip used to take, so it is a SWAP,
/// not an addition: the row never gets wider. The measured full row wants
/// ~508dp with the longest sort label ("Duration ↑", ~195dp against ~139dp for
/// the short ones), so 520dp keeps the full layout clear of an overflow stripe
/// at every sort field.
const double kToolbarOverflowMinWidth = 520;

/// Below this the extension-filter chip joins the overflow too. With the long
/// sort label inline, the ~96dp filter chip plus a 40dp overflow button cannot
/// share a 320dp row; folding the filter in leaves ~195 + 40 + gaps + padding,
/// which fits every width down to 320dp.
const double kToolbarFormatChipMinWidth = 380;

/// What a toolbar of a given width may render.
class MediaToolbarLayout {
  /// Whether the tag chip drops its "Tags" label AND its label padding.
  /// Only relevant while the chip is inline (at or above the overflow width).
  final bool compactTagLabel;

  /// When any control stops fitting, ONE overflow button on the right carries
  /// every right-side control — including the tag toggle, whose compact bare
  /// `#` is the least self-explanatory thing on the bar. The button replaces
  /// that chip, so the row is no wider than before and keeps a control at each
  /// end instead of a bare `#` and an empty gap.
  final bool showOverflow;

  /// The extension-filter chip stays inline while it fits. Below
  /// [kToolbarFormatChipMinWidth] it moves into the overflow instead.
  final bool showFormatChipInline;

  /// 8dp when the tag label is gone, 12dp otherwise.
  final double horizontalPadding;

  const MediaToolbarLayout({
    required this.compactTagLabel,
    required this.showOverflow,
    required this.showFormatChipInline,
    required this.horizontalPadding,
  });

  @override
  bool operator ==(Object other) =>
      other is MediaToolbarLayout &&
      other.compactTagLabel == compactTagLabel &&
      other.showOverflow == showOverflow &&
      other.showFormatChipInline == showFormatChipInline &&
      other.horizontalPadding == horizontalPadding;

  @override
  int get hashCode => Object.hash(
    compactTagLabel,
    showOverflow,
    showFormatChipInline,
    horizontalPadding,
  );
}

const MediaToolbarLayout _full = MediaToolbarLayout(
  compactTagLabel: false,
  showOverflow: false,
  showFormatChipInline: true,
  horizontalPadding: 12,
);

const MediaToolbarLayout _collapsed = MediaToolbarLayout(
  compactTagLabel: true,
  showOverflow: false,
  showFormatChipInline: false,
  horizontalPadding: 8,
);

/// The toolbar layout for the width it was actually given.
///
/// `double.infinity` means an unconstrained horizontal run, which gets the
/// full layout. NaN and non-positive widths are treated as collapsed: a layout
/// decision must never guess "wide" from a number that carries no width.
MediaToolbarLayout mediaToolbarLayout(double width) {
  if (width.isNaN || width <= 0) return _collapsed;
  if (width == double.infinity) return _full;
  return MediaToolbarLayout(
    compactTagLabel: width < kToolbarTagLabelMinWidth,
    showOverflow: width < kToolbarOverflowMinWidth,
    showFormatChipInline: width >= kToolbarFormatChipMinWidth,
    horizontalPadding: width < kToolbarTagLabelMinWidth ? 8 : 12,
  );
}
