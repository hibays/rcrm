// widgets/keyword_chip.dart
// One CLICKABLE keyword: a quiet hashtag chip that opens that tag's results.
//
// The video tab's KeywordFilterBar uses [FilterTagChip] because it is a filter
// (selected or not). A chip here is an ACTION — the thing under the player's
// title and in search suggestions — so it uses ActionChip and says `#tag`,
// the same way a streaming player links a hashtag to its topic page.
//
// Search ALSO needs the selected state, because tags there are multi-select:
// [SelectedKeywordChip] is the checked, filled chip whose tap removes the tag.

import 'package:material_ui/material_ui.dart';

import '../config/theme.dart';
import '../utils/keywords.dart';
import 'filter_tag_chip.dart';

class KeywordChip extends StatelessWidget {
  final KeywordTag tag;
  final VoidCallback onTap;

  /// True where the chip ADDS a tag to a selection (search suggestions and
  /// Browse by tag), false where it opens a tag (the player title). The small
  /// plus is the difference between "narrow this search" and "go there".
  final bool additive;

  const KeywordChip({
    super.key,
    required this.tag,
    required this.onTap,
    this.additive = false,
  });

  @override
  Widget build(BuildContext context) {
    final label = tag.label.startsWith('#') ? tag.label : '#${tag.label}';
    return ActionChip(
      onPressed: onTap,
      avatar: additive
          ? Icon(Icons.add, size: 14, color: RCrmColors.textFaint)
          : null,
      label: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 220),
        child: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
      ),
      backgroundColor: RCrmColors.char,
      side: BorderSide.none,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(RCrmRadii.sm),
      ),
      labelStyle: TextStyle(
        color: RCrmColors.textSecondary,
        fontSize: 12.5,
        fontWeight: FontWeight.w500,
      ),
      elevation: 0,
      pressElevation: 0,
      visualDensity: VisualDensity.compact,
      materialTapTargetSize: MaterialTapTargetSize.padded,
    );
  }
}

/// A tag that is part of the current multi-select: filled, checked, and tapped
/// to remove. It is not a suggestion — that is [KeywordChip], the neutral one
/// that adds a tag.
class SelectedKeywordChip extends StatelessWidget {
  final KeywordTag tag;
  final VoidCallback onRemove;

  const SelectedKeywordChip({
    super.key,
    required this.tag,
    required this.onRemove,
  });

  @override
  Widget build(BuildContext context) {
    final label = tag.label.startsWith('#') ? tag.label : '#${tag.label}';
    // The selectable chip itself lives in one place; this wrapper only says
    // "always on, and a tap removes it".
    return FilterTagChip(
      label: label,
      selected: true,
      labelSize: 12.5,
      onTap: onRemove,
    );
  }
}
