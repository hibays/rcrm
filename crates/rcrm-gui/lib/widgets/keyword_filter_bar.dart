// widgets/keyword_filter_bar.dart
// The video tab's keyword row: one chip per repeated tag, plus All tags.
//
// This is the visible half of the automatic keywords. The tags themselves are
// derived from the file names (`utils/keywords.dart`); this bar only decides
// which ones the list is filtered by. It sits under the toolbar rather than
// inside it because the toolbar is already dense on a phone, and a filter the
// user reaches by scrolling is not a hidden control.
//
// Multi-select: chips are filters, not radio buttons. Every selected tag adds
// a constraint, so a file must carry ALL of them. The checkmark + fill is the
// selected state; All tags clears the set.

import 'package:material_ui/material_ui.dart';

import '../config/theme.dart';
import '../utils/keywords.dart';
import 'filter_tag_chip.dart';

class KeywordFilterBar extends StatelessWidget {
  final List<KeywordTag> tags;
  final Set<String> selected;
  final ValueChanged<String> onToggle;
  final VoidCallback onClear;

  const KeywordFilterBar({
    super.key,
    required this.tags,
    required this.selected,
    required this.onToggle,
    required this.onClear,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          bottom: BorderSide(color: Theme.of(context).dividerColor),
        ),
      ),
      child: SizedBox(
        height: 56,
        child: Row(
          children: [
            const SizedBox(width: 12),
            Tooltip(
              message: 'Keyword filters',
              child: Icon(Icons.tag, size: 16, color: RCrmColors.textFaint),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: ListView.separated(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(vertical: 4),
                itemCount: tags.length + 1,
                separatorBuilder: (_, _) => const SizedBox(width: 8),
                itemBuilder: (context, index) {
                  if (index == 0) {
                    // `All tags` is the CLEAR action and reads as selected when
                    // nothing is filtered — the same shared chip as the tags.
                    return FilterTagChip(
                      label: 'All tags',
                      selected: selected.isEmpty,
                      onTap: onClear,
                    );
                  }
                  final tag = tags[index - 1];
                  return FilterTagChip(
                    label: tag.label,
                    selected: selected.contains(tag.key),
                    onTap: () => onToggle(tag.key),
                  );
                },
              ),
            ),
            const SizedBox(width: 12),
          ],
        ),
      ),
    );
  }
}
