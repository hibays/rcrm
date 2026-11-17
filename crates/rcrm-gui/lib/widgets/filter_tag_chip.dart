// widgets/filter_tag_chip.dart
// The app's ONE selectable chip: a quiet pill that turns Marquee Orange when
// selected, wears a check in the avatar slot, and never touches the chip's
// shape or border between states.
//
// Why this exists as a widget and not as a copied argument list: FilterChip's
// M3 defaults are NOT this app's palette. Its `color` is a WidgetStateProperty
// that resolves to `secondaryContainer` — teal here — and it outranks
// `selectedColor` for the frames where the selection and enable animations
// still overlap. Leaving that one property to the default painted a teal frame
// between the tap and the orange at three call sites (the toolbar's Tags chip,
// the tag filter bar, and search's selected-tag chip) before this file existed.
// The fill is therefore pinned for EVERY ink state, and so are the type, the
// check and the shape, so a call site cannot forget one of them.
//
// A species that must look like something else — the toolbar's Tags chip, which
// has to match the `Chip`s beside it — stays a raw FilterChip and pins `color`
// itself. `test/chip_fill_policy_test.dart` scans `lib/` and fails if any
// FilterChip or ChoiceChip goes back to the default fill.

import 'package:material_ui/material_ui.dart';

import '../config/theme.dart';

class FilterTagChip extends StatelessWidget {
  /// Already phrase-cased by the caller (a tag label, `All tags`, `#tag`).
  /// Chips in a row share one width budget so a long tag cannot push the
  /// others off the strip.
  final String label;

  final bool selected;

  /// What a tap does. Selection is the CALLER's state, not this widget's: the
  /// tag bar toggles multi-select, while search's selected-tag chip is always
  /// on and treats the tap as "remove".
  final VoidCallback onTap;

  /// The label's size. 13 is the tag bar's; search's denser chips ask for 12.5.
  final double labelSize;

  const FilterTagChip({
    super.key,
    required this.label,
    required this.selected,
    required this.onTap,
    this.labelSize = 13,
  });

  @override
  Widget build(BuildContext context) {
    return FilterChip(
      selected: selected,
      onSelected: (_) => onTap(),
      showCheckmark: true,
      // The check sits on an orange fill, so it is drawn in the ink the fill
      // owes, not in the accent.
      checkmarkColor: RCrmColors.onPrimary,
      // See the file header: this single property is the one that leaked teal.
      // Pinned for both states so no default has anything left to paint.
      color: WidgetStateProperty.resolveWith(
        (states) => states.contains(WidgetState.selected)
            ? RCrmColors.primary
            : RCrmColors.char,
      ),
      side: BorderSide.none,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(RCrmRadii.sm),
      ),
      label: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 220),
        child: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
      ),
      labelStyle: TextStyle(
        color: selected ? RCrmColors.onPrimary : RCrmColors.textSecondary,
        fontSize: labelSize,
        fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
      ),
      visualDensity: VisualDensity.compact,
      materialTapTargetSize: MaterialTapTargetSize.padded,
    );
  }
}
