// widgets/media_toolbar.dart
// RCrm GUI — sort / filter / display options toolbar
//
// Currently the video screen's toolbar: sort field dropdown, sort direction
// toggle, extension filter, column-count cycle button, and grid/list layout
// toggle.

import 'package:flutter/material.dart';
import 'column_button.dart';

/// The icon for each grouping, for the toolbar's button — the one place that has
/// to pick an icon at RUNTIME.
///
/// That is also the whole trouble with it: the release icon tree-shaker keeps a
/// glyph only when the `IconData` is a constant at a use site, which is why
/// `Icons.folder` has always rendered (eight files use it as a `const Icon`)
/// while `Icons.apps` and `Icons.category` — reachable here only through a
/// lookup — shipped as EMPTY GLYPHS. The grouping menu therefore writes its
/// three icons out as literals, and those literals are what keeps all three
/// glyphs in the font; this map is free to choose among them afterwards.
const Map<String, Icon> kGroupingIcons = {
  'none': Icon(Icons.apps, size: 16),
  'folder': Icon(Icons.folder, size: 16),
  'format': Icon(Icons.category, size: 16),
};

/// See [kGroupingIcons].
Icon groupingIcon(String grouping) =>
    kGroupingIcons[grouping] ?? kGroupingIcons['none']!;

/// One row of the grouping menu: the check marking the arrangement in effect,
/// the icon, and the label.
///
/// The check's width is reserved whether or not it is drawn, so the three icons
/// sit in one column. `CheckedPopupMenuItem` would do the checking itself, but it
/// lays its title out through a `ListTile`, which overflows a popup menu's 280dp
/// as soon as the row carries an icon too.
///
/// The labels stay short for the same 280dp: with a check slot, an icon and two
/// gaps beside it, a wordy label overflows the row.
Widget _groupingRow(
  BuildContext context, {
  required bool selected,
  required Widget icon,
  required String label,
}) {
  return Row(
    children: [
      SizedBox(
        width: 16,
        child: selected
            ? Icon(
                Icons.check,
                size: 16,
                color: Theme.of(context).colorScheme.primary,
              )
            : null,
      ),
      const SizedBox(width: 8),
      icon,
      const SizedBox(width: 8),
      Text(label),
    ],
  );
}

class MediaToolbar extends StatelessWidget {
  final List<String> sortOptions;
  final String currentSort;
  final bool isAscending;
  final ValueChanged<String> onSortChanged;

  /// Flips the direction between ascending and descending.
  ///
  /// Separate from [onSortChanged], which commits a sort *field*: re-picking
  /// the field already active flips too (that rule lives in the provider — see
  /// `_SortNotifier.set`), but there the flip is the rule's outcome, not a
  /// direction contract. The arrow states the direction it wants, and being
  /// required keeps a caller from wiring an arrow that does nothing.
  final VoidCallback onSortDirectionChanged;

  final List<String>? extensions;
  final String? currentFilter;
  final ValueChanged<String>? onFilterChanged;

  final ValueChanged<int>? onColumnsChanged;
  final int? currentColumns;
  final int minColumns;
  final int maxColumns;

  /// Optional grid/list view toggle (rendered inline in the toolbar row).
  final bool? isGrid;
  final VoidCallback? onLayoutToggle;

  /// Optional grouping selector: what the list is ORGANIZED into — the video
  /// tab's flat / by-folder / by-format choice. Null hides it, like
  /// [onLayoutToggle], because the toolbar is shared with screens that have
  /// nothing to group by.
  ///
  /// A menu rather than a cycling button: three arrangements are not a sequence
  /// a user can predict from an icon, so the items say what they are.
  final String? currentGrouping;
  final ValueChanged<String>? onGroupingChanged;

  const MediaToolbar({
    super.key,
    required this.sortOptions,
    required this.currentSort,
    required this.isAscending,
    required this.onSortChanged,
    required this.onSortDirectionChanged,
    this.extensions,
    this.currentFilter,
    this.onFilterChanged,
    this.onColumnsChanged,
    this.currentColumns,
    this.minColumns = 2,
    this.maxColumns = 6,
    this.isGrid,
    this.onLayoutToggle,
    this.currentGrouping,
    this.onGroupingChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          bottom: BorderSide(color: Theme.of(context).dividerColor),
        ),
      ),
      child: Row(
        children: [
          // Sort
          _sortChip(context),

          // Filter by extension
          if (extensions != null &&
              extensions!.isNotEmpty &&
              onFilterChanged != null) ...[
            const SizedBox(width: 8),
            _filterDropdown(context),
          ],

          const Spacer(),

          // Column count toggle (cycles within [minColumns, maxColumns]) — no slider
          if (onColumnsChanged != null && currentColumns != null)
            ColumnButton(
              current: currentColumns!,
              min: minColumns,
              max: maxColumns,
              onChanged: onColumnsChanged!,
            ),

          // Sort direction. The icon reports the direction in effect, so it
          // agrees with the chip's arrow; the tooltip names what the tap does
          // (like the layout toggle below) and doubles as the semantics text.
          IconButton(
            icon: Icon(
              isAscending ? Icons.arrow_upward : Icons.arrow_downward,
              size: 18,
            ),
            onPressed: onSortDirectionChanged,
            tooltip: isAscending ? 'Sort descending' : 'Sort ascending',
            visualDensity: VisualDensity.compact,
          ),

          // Grouping (optional): the button's icon reports the arrangement in
          // effect, so every item wears the SAME icon its own mode puts on the
          // button — otherwise the menu names three arrangements whose icons the
          // user can only see one of, and picking one looks like it changed the
          // icon to something the menu never offered. (The sort and filter menus
          // beside it carry no item icons, but their buttons do not change icon
          // with the selection either.)
          if (currentGrouping != null && onGroupingChanged != null)
            PopupMenuButton<String>(
              tooltip: 'Organize',
              icon: groupingIcon(currentGrouping!),
              onSelected: onGroupingChanged,
              itemBuilder: (context) => [
                // Written out rather than looped over a label map, and each icon
                // a literal `const Icon`: the release icon tree-shaker keeps a
                // glyph only when its `IconData` reaches it as a constant at a
                // USE SITE, so an icon chosen through a lookup ships as an EMPTY
                // GLYPH — which is how the button and "By format" shipped blank
                // while the hardcoded `Icons.folder` in the sort menu rendered.
                // These three literals are what keeps all three glyphs in the
                // font; the button below may then pick among them at runtime.
                PopupMenuItem<String>(
                  value: 'none',
                  child: _groupingRow(
                    context,
                    selected: currentGrouping == 'none',
                    icon: const Icon(Icons.apps, size: 16),
                    label: 'Ungrouped',
                  ),
                ),
                PopupMenuItem<String>(
                  value: 'folder',
                  child: _groupingRow(
                    context,
                    selected: currentGrouping == 'folder',
                    icon: const Icon(Icons.folder, size: 16),
                    label: 'By folder',
                  ),
                ),
                PopupMenuItem<String>(
                  value: 'format',
                  child: _groupingRow(
                    context,
                    selected: currentGrouping == 'format',
                    icon: const Icon(Icons.category, size: 16),
                    label: 'By format',
                  ),
                ),
              ],
            ),

          // Grid/List layout toggle (optional)
          if (isGrid != null && onLayoutToggle != null)
            IconButton(
              icon: Icon(isGrid! ? Icons.list : Icons.grid_view, size: 18),
              onPressed: onLayoutToggle,
              tooltip: isGrid! ? 'List view' : 'Grid view',
              visualDensity: VisualDensity.compact,
            ),
        ],
      ),
    );
  }

  Widget _sortChip(BuildContext context) {
    return PopupMenuButton<String>(
      // The chip's own chrome shows the field and the direction in effect, and
      // the menu's check marks the field that is active — neither says what
      // re-picking that field does. The tooltip is where the rule is stated;
      // PopupMenuButton feeds the same string to the control's semantics, so
      // it is announced and not merely hovered.
      tooltip:
          'Sort: ${_capitalize(currentSort)} ${isAscending ? '↑' : '↓'} — '
          'pick ${_capitalize(currentSort)} again to reverse',
      onSelected: onSortChanged,
      itemBuilder: (context) => sortOptions.map((opt) {
        return PopupMenuItem(
          value: opt,
          child: Row(
            children: [
              if (opt == currentSort)
                Icon(
                  Icons.check,
                  size: 16,
                  color: Theme.of(context).colorScheme.primary,
                ),
              const SizedBox(width: 8),
              Text(_capitalize(opt)),
            ],
          ),
        );
      }).toList(),
      child: Chip(
        avatar: const Icon(Icons.sort, size: 16),
        label: Text('${_capitalize(currentSort)} ${isAscending ? '↑' : '↓'}'),
        visualDensity: VisualDensity.compact,
      ),
    );
  }

  Widget _filterDropdown(BuildContext context) {
    return PopupMenuButton<String>(
      onSelected: (v) => onFilterChanged?.call(v),
      itemBuilder: (context) {
        final items = <PopupMenuItem<String>>[
          PopupMenuItem(
            value: '',
            child: Row(
              children: [
                if (currentFilter == null || currentFilter!.isEmpty)
                  Icon(
                    Icons.check,
                    size: 16,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                const SizedBox(width: 8),
                const Text('All formats'),
              ],
            ),
          ),
        ];
        for (final ext in extensions!) {
          items.add(
            PopupMenuItem(
              value: ext,
              child: Row(
                children: [
                  if (ext == currentFilter)
                    Icon(
                      Icons.check,
                      size: 16,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  const SizedBox(width: 8),
                  Text(ext.toUpperCase()),
                ],
              ),
            ),
          );
        }
        return items;
      },
      child: Chip(
        avatar: const Icon(Icons.filter_list, size: 16),
        label: Text(
          currentFilter != null && currentFilter!.isNotEmpty
              ? currentFilter!.toUpperCase()
              : 'All',
        ),
        visualDensity: VisualDensity.compact,
      ),
    );
  }

  String _capitalize(String s) {
    if (s.isEmpty) return s;
    return '${s[0].toUpperCase()}${s.substring(1)}';
  }
}
